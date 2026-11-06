//! Local CA issuance and database-backed certificate revocation.
//!
//! Callers authorize operations before invoking this manager. It performs no
//! authentication and creates no HTTP routes. It uses the crate's protobuf DTOs
//! and `tonic::Status` errors, but requires no gRPC request, connection or server.
//! Issuance returns metadata; material stays in the hosting database.
use std::sync::Arc;

use claviron::auth::permission::PermissionCatalog;
#[cfg(feature = "authorization")]
use claviron::auth::{
    AnyAuthenticated,
    authorization::{
        ManagementError, RecordKey, Resource, RolePermissionManager,
    },
};
use claviron::hosting::{
    CertificateKind, HostedCertificate, HostingError, HostingService,
    HostingStore, NewCertificate,
};
use claviron::runtime::AppState;
use claviron::ssl::parsers::take_first_cert_from_der;
use claviron::ssl::{CommonName, Host, Organization};
use claviron::tls::{CertAuthority, CertSigner, CertificateStore};
use time::OffsetDateTime;
use tonic::Status;

use crate::proto::mtls::{
    CertificateInfo, CreateCertificateRequest, CreateRootCaRequest,
    RenewCertificateRequest, RevokeCertificateRequest,
};

/// Root CA creation, local-CA signing and certificate revocation in hosting.
///
/// Application handlers must enforce their own enrollment/authorization policy.
/// The manager never derives permission from a request's chosen CN or issuer.
pub struct MtlsManager {
    store: HostingStore,
    server_id: Option<i32>,
    authority: Option<Arc<CertAuthority>>,
    certificate_store: Option<Arc<CertificateStore>>,
    prepared_signer: Option<Arc<ManagedSigner>>,
    permissions: Option<Arc<PermissionCatalog>>,
    #[cfg(feature = "authorization")]
    permission_manager: Option<Arc<dyn RolePermissionManager>>,
    #[cfg(feature = "authorization")]
    actor: Option<AnyAuthenticated>,
}

pub(crate) struct ManagedSigner {
    signer: Arc<CertSigner>,
    issuer: CertAuthority,
}

impl ManagedSigner {
    fn issuer_id(&self) -> i32 {
        self.issuer.issuer_id().expect("managed signer has a hosting issuer")
    }

    async fn validate(
        &self,
        store: &HostingStore,
    ) -> Result<(), Status> {
        self.issuer
            .validate_issuer(store)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))
    }
}

impl MtlsManager {
    #[cfg(feature = "authorization")]
    /// Use the application actor already admitted for this management request.
    pub fn with_actor(
        mut self,
        actor: Option<AnyAuthenticated>,
    ) -> Self {
        self.actor = actor;
        self
    }

    async fn permission_selection(
        &self,
        names: &[String],
    ) -> Result<Arc<PermissionCatalog>, Status> {
        #[cfg(feature = "authorization")]
        if let Some(manager) = &self.permission_manager {
            let actor = self.actor.as_ref().ok_or_else(|| {
                Status::failed_precondition("certificate permissions require an application actor from GrpcAccessPolicy")
            })?;
            let mut selection = PermissionCatalog::new();
            for name in names {
                selection.register_name(name).map_err(|error| {
                    Status::invalid_argument(error.to_string())
                })?;
                let key = RecordKey {
                    resource: Resource::Permission,
                    reference: name.clone(),
                };
                let record = manager
                    .get(actor.as_ref(), key.clone())
                    .await
                    .map_err(permission_status)?;
                if record.key != key {
                    return Err(Status::invalid_argument(
                        "selected permission identity does not match",
                    ));
                }
            }
            return Ok(Arc::new(selection));
        }
        self.permissions.clone().ok_or_else(|| {
            Status::failed_precondition(
                "certificate permission definitions are not configured",
            )
        })
    }
    /// Revoke a stored certificate and disable it, retaining its first timestamp.
    /// No issuer ownership or signing key is required for this local DB decision.
    /// Store notifications refresh TLS snapshots after the committed mutation.
    pub async fn revoke_certificate(
        &self,
        request: RevokeCertificateRequest,
    ) -> Result<CertificateInfo, Status> {
        let name = request
            .common_name
            .parse::<CommonName>()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let hosted = self
            .store
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .ok_or_else(|| Status::not_found("certificate not found"))?;
        self.store
            .revoke_certificate(
                hosted.certificate.id,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(storage_status)?;
        let saved = self
            .store
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .ok_or_else(|| {
                Status::not_found("certificate not found after revocation")
            })?;
        metadata(saved)
    }
    /// Renew the original identity using its persisted key and signer.
    pub async fn renew_certificate(
        &self,
        request: RenewCertificateRequest,
    ) -> Result<CertificateInfo, Status> {
        let name = request
            .common_name
            .parse::<CommonName>()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let hosted = self
            .store
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .ok_or_else(|| Status::not_found("certificate not found"))?;
        let original = hosted.certificate;
        if original.revoked_at.is_some() {
            return Err(Status::failed_precondition(
                "revoked certificates cannot be renewed",
            ));
        }
        if !original.enabled {
            return Err(Status::failed_precondition(
                "disabled certificates cannot be renewed",
            ));
        }
        if original.key_der.is_empty() {
            return Err(Status::failed_precondition(
                "this client certificate requires a new device-signed request",
            ));
        }
        let peer = claviron::ssl::peer::peer_identity(&original.certs_der)
            .map_err(|_| {
                Status::failed_precondition(
                    "stored certificate identity cannot be decoded",
                )
            })?;
        if let Some(scope) = claviron::ssl::permission::from_uris(
            peer.subject_uris.iter().map(|uri| &**uri),
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?
        {
            let names = scope
                .iter()
                .map(|name| name.as_str().to_owned())
                .collect::<Vec<_>>();
            let catalog = self.permission_selection(&names).await?;
            catalog.validate(scope.iter()).map_err(|error| {
                Status::failed_precondition(error.to_string())
            })?;
        }
        let issuer = if let Some(id) = original.issuer_id {
            let issuer = self
                .store
                .issuer_by_id(id)
                .await
                .map_err(storage_status)?
                .ok_or_else(|| {
                    Status::failed_precondition("original issuer not found")
                })?;
            if issuer.kind != claviron::hosting::IssuerKind::LocalCa {
                return Err(Status::failed_precondition(
                    "ACME certificates must use AcmeManager.RenewCertificate",
                ));
            }
            let id = issuer.ca_certificate_id.ok_or_else(|| {
                Status::failed_precondition("issuer has no CA certificate")
            })?;
            let ca = self
                .store
                .public_certificate_by_id(id)
                .await
                .map_err(storage_status)?
                .ok_or_else(|| {
                    Status::failed_precondition("issuer CA not found")
                })?;
            if !ca.enabled || ca.kind != CertificateKind::Ca {
                return Err(Status::failed_precondition(
                    "issuer must reference an enabled CA",
                ));
            }
            let default_file =
                self.authority.as_ref().is_some_and(|authority| {
                    authority.path().is_some()
                        && authority
                            .roots()
                            .iter()
                            .flat_map(|cert| cert.as_ref().iter().copied())
                            .eq(ca.certs_der.iter().copied())
                });
            if default_file {
                let managed = self.default_signer().await?;
                if managed.issuer_id() != issuer.id {
                    return Err(Status::failed_precondition(
                        "original issuer changed",
                    ));
                }
                Some(managed.signer.clone())
            } else {
                let signer = CertSigner::from_issuer(&self.store, &issuer.name)
                    .await
                    .map_err(|error| {
                        Status::failed_precondition(error.to_string())
                    })?;
                if signer.issuer_id() != Some(issuer.id) {
                    return Err(Status::failed_precondition(
                        "original issuer changed",
                    ));
                }
                Some(Arc::new(signer))
            }
        } else {
            None
        };
        let previous = original.clone();
        let chain = tokio::task::spawn_blocking(move || {
            let leaf = take_first_cert_from_der(&previous.certs_der)?;
            let leaf = &previous.certs_der[..leaf.as_ref().len()];
            match issuer {
                Some(signer) => signer.renew_certificate(
                    leaf,
                    &previous.key_der,
                    request.validity_days,
                ),
                None => Ok(claviron::ssl::renewal::renew_certificate(
                    leaf,
                    &previous.key_der,
                    None,
                    request.validity_days,
                )?),
            }
        })
        .await
        .map_err(|_| Status::internal("certificate renewal task failed"))?
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let leaf = take_first_cert_from_der(&chain)
            .map_err(|error| Status::internal(error.to_string()))?;
        let issued = OffsetDateTime::from_unix_timestamp(
            leaf.validity().not_before.timestamp(),
        )
        .map_err(|_| Status::internal("invalid renewal issue date"))?;
        let expires = OffsetDateTime::from_unix_timestamp(
            leaf.validity().not_after.timestamp(),
        )
        .map_err(|_| Status::internal("invalid renewal expiry date"))?;
        let saved = self
            .store
            .renew_certificate_material(&original, chain, issued, expires)
            .await
            .map_err(|error| match error {
                HostingError::Conflict(message) => Status::aborted(message),
                other => storage_status(other),
            })?;
        metadata(saved)
    }
    /// Use an explicit store. A server id is required only for server certificates.
    /// The authority is the default for issuance requests without an issuer name.
    pub fn new(
        store: HostingStore,
        server_id: Option<i32>,
        authority: Option<Arc<CertAuthority>>,
    ) -> Self {
        Self {
            store,
            server_id,
            authority,
            certificate_store: None,
            prepared_signer: None,
            permissions: None,
            #[cfg(feature = "authorization")]
            permission_manager: None,
            #[cfg(feature = "authorization")]
            actor: None,
        }
    }

    /// Explicit permission definitions for issuer-owned enrollment without a manager.
    pub fn with_permissions(
        mut self,
        catalog: Arc<PermissionCatalog>,
    ) -> Self {
        self.permissions = Some(catalog);
        self
    }

    /// Resolve the application's managed hosting store and configured authority.
    pub fn from_state(state: &AppState) -> Result<Self, Status> {
        let hosting = state
            .registry_ref()
            .resolve::<HostingService>()
            .ok_or_else(|| {
                Status::failed_precondition("HostingService is not registered")
            })?;
        let store = hosting.store().map_err(|_| {
            Status::failed_precondition("HostingService is not initialized")
        })?;
        let mut manager = Self::new(
            store,
            hosting.server_id(),
            state.registry_ref().resolve::<CertAuthority>(),
        );
        manager.certificate_store =
            state.registry_ref().resolve::<CertificateStore>();
        manager.prepared_signer =
            state.registry_ref().resolve::<ManagedSigner>();
        manager.permissions =
            state.registry_ref().resolve::<PermissionCatalog>();
        #[cfg(feature = "authorization")]
        {
            manager.permission_manager =
                state.registry_ref().resolve_dyn::<dyn RolePermissionManager>();
        }
        Ok(manager)
    }

    async fn default_signer(&self) -> Result<Arc<ManagedSigner>, Status> {
        if let Some(prepared) = &self.prepared_signer {
            prepared.validate(&self.store).await?;
            return Ok(prepared.clone());
        }
        let authority = self.authority.as_ref().ok_or_else(|| {
            Status::failed_precondition("CertStore authority is not configured")
        })?;
        let signer = match &self.certificate_store {
            Some(source) => source.signer(authority).await,
            None => CertSigner::from_authority(&self.store, authority).await,
        }
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let issuer = if authority.issuer_id().is_some() {
            authority.as_ref().clone()
        } else {
            register_file_issuer(&self.store, authority).await?
        };
        Ok(Arc::new(ManagedSigner { signer: Arc::new(signer), issuer }))
    }

    #[cfg(feature = "registration")]
    pub(crate) async fn prepare_registration_signer(
        state: &AppState
    ) -> Result<Arc<ManagedSigner>, Status> {
        let managed = Self::from_state(state)?.default_signer().await?;
        registration_root(managed.signer.authority())?;
        Ok(managed)
    }

    #[cfg(feature = "registration")]
    pub(crate) async fn register_client(
        &self,
        user: super::registration::GrpcUser,
        csr: Vec<u8>,
        validity_days: std::num::NonZeroU32,
    ) -> Result<super::registration::Issued, Status> {
        use claviron::auth::permission::PermissionDefinition;
        use claviron::ssl::formatters::certificate_chain_to_pem;

        let (actor, subject) = user.into_parts();
        let name =
            actor.auth_identifier().parse::<CommonName>().map_err(|_| {
                Status::failed_precondition("invalid registration identity")
            })?;
        let permissions = if subject.is_some() {
            let mut catalog = PermissionCatalog::new();
            catalog
                .register_name(crate::permission::GrpcAccess::NAME)
                .map_err(|_| {
                    Status::internal("invalid registration permission")
                })?;
            Some(
                catalog
                    .validate([crate::permission::GrpcAccess::NAME])
                    .map_err(|_| {
                        Status::internal("invalid registration permission")
                    })?,
            )
        } else {
            None
        };
        let managed = self.default_signer().await?;
        let issuer = managed.issuer_id();
        let signer = managed.signer.clone();
        let authority_certificate_pem =
            certificate_chain_to_pem(registration_root(signer.authority())?)
                .map_err(|_| {
                    Status::failed_precondition("registration root is invalid")
                })?;
        let signing_name = name.clone();
        let certs_der = tokio::task::spawn_blocking(move || {
            signer.issue_client_csr(
                &csr,
                &signing_name,
                subject.as_ref(),
                permissions.as_ref(),
                validity_days.get(),
            )
        })
        .await
        .map_err(|_| Status::internal("registration signing task failed"))?
        .map_err(|_| {
            Status::invalid_argument("certificate request could not be signed")
        })?;
        let chain = certificate_chain_to_pem(&certs_der).map_err(|_| {
            Status::internal("registration certificate chain is invalid")
        })?;
        let stored = persist(
            &self.store,
            CertificateKind::Client,
            name.clone(),
            Vec::new(),
            Some(issuer),
            None,
            claviron::tls::IssuedCertificate {
                certs_der: certs_der.clone(),
                key_der: Vec::new(),
            },
        )
        .await;
        let certificate_chain_pem = match stored {
            Ok(_) => chain,
            Err(error) if error.code() == tonic::Code::AlreadyExists => {
                let Some(saved) = self
                    .store
                    .certificate_by_cn(name.as_str())
                    .await
                    .map_err(storage_status)?
                else {
                    return Err(error);
                };
                let saved = saved.certificate;
                if saved.kind != CertificateKind::Client
                    || saved.issuer_id != Some(issuer)
                    || !saved.enabled
                    || saved.revoked_at.is_some()
                    || !saved.key_der.is_empty()
                    || saved.expires_at <= OffsetDateTime::now_utc()
                    || !same_registration_identity(&saved.certs_der, &certs_der)
                {
                    return Err(error);
                }
                certificate_chain_to_pem(&saved.certs_der).map_err(|_| {
                    Status::internal(
                        "stored registration certificate chain is invalid",
                    )
                })?
            }
            Err(error) => return Err(error),
        };
        Ok(super::registration::Issued {
            certificate_chain_pem,
            authority_certificate_pem,
        })
    }
    /// Generate and atomically store a self-signed CA and its issuer identity.
    pub async fn create_root_ca(
        &self,
        request: CreateRootCaRequest,
    ) -> Result<CertificateInfo, Status> {
        let name = identity(&request.common_name, CertificateKind::Ca)?;
        let hosting = &self.store;
        let signing_name = name.clone();
        let material = tokio::task::spawn_blocking(move || {
            use claviron::ssl::generators;
            let key = generators::generate_ca_key()?;
            let organization = Organization {
                name: request.organization.unwrap_or_default().into_boxed_str(),
                country: request.country.unwrap_or_default().into_boxed_str(),
                ..Default::default()
            };
            let certificate = generators::generate_ca_cert(
                &signing_name,
                &key,
                request.validity_days,
                &organization,
            )?;
            Ok::<_, claviron::ssl::SSLError>(
                claviron::tls::authority::IssuedCertificate {
                    certs_der: certificate.to_vec(),
                    key_der: key.serialize_der(),
                },
            )
        })
        .await
        .map_err(|_| Status::internal("root CA generation task failed"))?
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let info = persist(
            hosting,
            CertificateKind::Ca,
            name.clone(),
            vec![name.into()],
            None,
            None,
            material,
        )
        .await?;
        Ok(info)
    }

    /// Sign a server, client or intermediate CA and persist it before returning metadata.
    pub async fn create_certificate(
        &self,
        request: CreateCertificateRequest,
    ) -> Result<CertificateInfo, Status> {
        let issuer_name = request.issuer.clone();
        let IssuanceRequest {
            name,
            aliases,
            validity_days,
            kind,
            path_len,
            subject_uri,
            permissions,
        } = input(request)?;
        // Revalidate selected definitions before issuer lookup or signing.
        let catalog = if let Some(names) = &permissions {
            let catalog = self.permission_selection(names).await?;
            catalog
                .validate(names)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            Some(catalog)
        } else {
            None
        };
        let hosting = &self.store;
        let server_id = if kind == CertificateKind::Server {
            Some(self.server_id.ok_or_else(|| {
                Status::failed_precondition(
                    "server identity is not initialized",
                )
            })?)
        } else {
            None
        };
        let (authority, issuer_id) = if let Some(name) = issuer_name {
            let signer =
                CertSigner::from_issuer(hosting, &name).await.map_err(
                    |error| Status::failed_precondition(error.to_string()),
                )?;
            let issuer = signer.issuer_id().ok_or_else(|| {
                Status::failed_precondition(
                    "selected signer has no hosting issuer",
                )
            })?;
            (Arc::new(signer), issuer)
        } else {
            let managed = self.default_signer().await?;
            (managed.signer.clone(), managed.issuer_id())
        };
        if hosting
            .certificate_by_cn(name.as_str())
            .await
            .map_err(storage_status)?
            .is_some()
        {
            return Err(Status::already_exists(
                "a certificate with this common name already exists",
            ));
        }
        let signing_name = name.clone();
        let signing_aliases = aliases.clone();
        let material = tokio::task::spawn_blocking(move || {
            if kind == CertificateKind::Client {
                if let (Some(catalog), Some(names)) = (&catalog, &permissions) {
                    authority.issue_client_certificate_with_permissions(
                        &signing_name,
                        &signing_aliases,
                        subject_uri.as_ref(),
                        validity_days,
                        catalog,
                        names,
                    )
                } else {
                    authority.issue_client_certificate(
                        &signing_name,
                        &signing_aliases,
                        subject_uri.as_ref(),
                        validity_days,
                    )
                }
            } else {
                authority.issue_certificate(
                    kind,
                    &signing_name,
                    &signing_aliases,
                    validity_days,
                    path_len,
                )
            }
        })
        .await
        .map_err(|_| Status::internal("certificate signing task failed"))?
        .map_err(|error| {
            Status::failed_precondition(format!(
                "certificate issuance failed: {error}"
            ))
        })?;
        let info = persist(
            hosting,
            kind,
            name,
            aliases,
            Some(issuer_id),
            server_id,
            material,
        )
        .await?;
        Ok(info)
    }
}

#[cfg(feature = "registration")]
fn registration_root(authority: &CertAuthority) -> Result<&[u8], Status> {
    let root = authority
        .roots()
        .last()
        .ok_or_else(|| {
            Status::failed_precondition("registration CA has no root")
        })?
        .as_ref();
    let parsed = take_first_cert_from_der(root).map_err(|_| {
        Status::failed_precondition("registration root is invalid")
    })?;
    if !parsed.is_ca()
        || parsed.subject() != parsed.issuer()
        || parsed.verify_signature(None).is_err()
    {
        return Err(Status::failed_precondition("registration CA has no root"));
    }
    Ok(root)
}

/// Retain the public issuer hierarchy so file-issued leaves use the normal
/// hosting identity and revocation paths. Private keys stay in CertStore.
async fn register_file_issuer(
    store: &HostingStore,
    authority: &CertAuthority,
) -> Result<CertAuthority, Status> {
    let roots = authority.roots();
    let mut parent = None;
    for (index, der) in roots.iter().enumerate().rev() {
        let certificate =
            take_first_cert_from_der(der.as_ref()).map_err(|_| {
                Status::failed_precondition("invalid CA certificate")
            })?;
        if parent.is_none()
            && (certificate.subject() != certificate.issuer()
                || certificate.verify_signature(None).is_err())
        {
            return Err(Status::failed_precondition(
                "file authority must include its root CA",
            ));
        }
        let name = CommonName::read(certificate.subject())
            .map_err(|_| {
                Status::failed_precondition("invalid authority common name")
            })?
            .ok_or_else(|| {
                Status::failed_precondition("authority has no common name")
            })?;
        if store.issuer_by_name(name).await.map_err(storage_status)?.is_none() {
            let material = claviron::tls::IssuedCertificate {
                certs_der: roots[index..]
                    .iter()
                    .flat_map(|cert| cert.as_ref().iter().copied())
                    .collect(),
                key_der: Vec::new(),
            };
            match persist(
                store,
                CertificateKind::Ca,
                name.parse().map_err(|_| {
                    Status::failed_precondition("invalid authority common name")
                })?,
                Vec::new(),
                parent,
                None,
                material,
            )
            .await
            {
                Ok(_) => (),
                Err(error) if error.code() == tonic::Code::AlreadyExists => (),
                Err(error) => return Err(error),
            }
        }
        let issuer = CertAuthority::from_issuer(store, name)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        if issuer.roots() != &roots[index..] {
            return Err(Status::failed_precondition(
                "hosting issuer does not match the selected file CA chain",
            ));
        }
        parent = issuer.issuer_id();
        if index == 0 {
            return Ok(issuer);
        }
    }
    Err(Status::failed_precondition("file signing authority is empty"))
}

#[cfg(feature = "registration")]
fn same_registration_identity(
    saved: &[u8],
    candidate: &[u8],
) -> bool {
    use claviron::ssl::peer::peer_identity;
    match (take_first_cert_from_der(saved), take_first_cert_from_der(candidate))
    {
        (Ok(saved), Ok(candidate))
            if saved.public_key().raw == candidate.public_key().raw => {}
        _ => return false,
    }
    matches!((peer_identity(saved), peer_identity(candidate)), (Ok(saved), Ok(candidate))
        if saved.common_names == candidate.common_names && saved.subject_uris == candidate.subject_uris)
}

fn identity(
    raw: &str,
    kind: CertificateKind,
) -> Result<CommonName, Status> {
    let host = raw.parse::<Host>().map_err(|_| Status::invalid_argument("certificate names and aliases must be valid DNS names, IP addresses or bare names"))?;
    let name = CommonName::from(&host);
    if kind != CertificateKind::Server && name.as_str().starts_with("*.") {
        return Err(Status::invalid_argument(
            "client and CA identities must not be wildcards",
        ));
    }
    Ok(name)
}

struct IssuanceRequest {
    name: CommonName,
    aliases: Vec<String>,
    validity_days: u32,
    kind: CertificateKind,
    path_len: Option<u8>,
    subject_uri: Option<claviron::ssl::SubjectUri>,
    permissions: Option<Vec<String>>,
}

fn input(request: CreateCertificateRequest) -> Result<IssuanceRequest, Status> {
    if request.validity_days == 0
        || OffsetDateTime::now_utc()
            .checked_add(time::Duration::days(i64::from(request.validity_days)))
            .is_none()
    {
        return Err(Status::invalid_argument(
            "validity_days must be positive and within the supported date range",
        ));
    }
    let kind = match crate::proto::mtls::CertificateKind::try_from(request.kind)
    {
        Ok(crate::proto::mtls::CertificateKind::Server) => {
            CertificateKind::Server
        }
        Ok(crate::proto::mtls::CertificateKind::Client) => {
            CertificateKind::Client
        }
        Ok(crate::proto::mtls::CertificateKind::Ca) => CertificateKind::Ca,
        _ => {
            return Err(Status::invalid_argument(
                "kind must be server, client or ca",
            ));
        }
    };
    let path_len = match (kind, request.ca_path_len) {
        (CertificateKind::Ca, Some(value)) => {
            Some(u8::try_from(value).map_err(|_| {
                Status::invalid_argument("ca_path_len is out of range")
            })?)
        }
        (CertificateKind::Ca, None) => {
            return Err(Status::invalid_argument(
                "ca_path_len is required for CA issuance",
            ));
        }
        (_, Some(_)) => {
            return Err(Status::invalid_argument(
                "ca_path_len only applies to CA issuance",
            ));
        }
        (_, None) => None,
    };
    if kind == CertificateKind::Ca && !request.aliases.is_empty() {
        return Err(Status::invalid_argument(
            "CA issuance takes its common name, not leaf SAN aliases",
        ));
    }
    if request.permissions.is_some() && kind != CertificateKind::Client {
        return Err(Status::invalid_argument(
            "permissions only apply to client certificates",
        ));
    }
    let subject_uri = request
        .subject_uri
        .map(|value| {
            if kind != CertificateKind::Client {
                return Err(Status::invalid_argument(
                    "subject_uri only applies to client certificates",
                ));
            }
            if claviron::ssl::permission::is_permission_uri(&value) {
                return Err(Status::invalid_argument(
                    "permission declarations must use the permissions field",
                ));
            }
            value.parse::<claviron::ssl::SubjectUri>().map_err(|_| {
                Status::invalid_argument(
                    "subject_uri must be an absolute ASCII URI",
                )
            })
        })
        .transpose()?;
    let name = identity(&request.common_name, kind)?;
    let mut aliases = vec![String::from(&name)];
    for alias in request.aliases {
        let alias = identity(&alias, kind)?;
        if !aliases.iter().any(|existing| existing == alias.as_str()) {
            aliases.push(alias.into());
        }
    }
    Ok(IssuanceRequest {
        name,
        aliases,
        validity_days: request.validity_days,
        kind,
        path_len,
        subject_uri,
        permissions: request.permissions.map(|scope| scope.names),
    })
}

#[cfg(feature = "authorization")]
fn permission_status(error: ManagementError) -> Status {
    let message = error.to_string();
    match error {
        ManagementError::NotFound => {
            Status::invalid_argument("selected permission no longer exists")
        }
        ManagementError::Forbidden => Status::permission_denied(message),
        ManagementError::Unsupported => Status::unimplemented(message),
        ManagementError::Unavailable => Status::unavailable(message),
        ManagementError::Conflict => Status::aborted(message),
        ManagementError::SchemaChanged => Status::failed_precondition(message),
        ManagementError::Validation(_) => Status::invalid_argument(message),
    }
}

fn storage_status(error: HostingError) -> Status {
    match error {
        HostingError::Conflict(_) => Status::already_exists(
            "a certificate with this common name already exists",
        ),
        HostingError::InvalidInput(message) => {
            Status::invalid_argument(message)
        }
        other => {
            tracing::error!(error = %other, "mTLS certificate persistence failed");
            Status::internal("mTLS certificate persistence failed")
        }
    }
}

async fn persist(
    hosting: &HostingStore,
    kind: CertificateKind,
    common_name: CommonName,
    aliases: Vec<String>,
    issuer_id: Option<i32>,
    server_id: Option<i32>,
    material: claviron::tls::authority::IssuedCertificate,
) -> Result<CertificateInfo, Status> {
    let leaf = take_first_cert_from_der(&material.certs_der).map_err(|_| {
        Status::internal("issued certificate could not be parsed")
    })?;
    let issued_at = OffsetDateTime::from_unix_timestamp(
        leaf.validity().not_before.timestamp(),
    )
    .map_err(|_| Status::internal("invalid certificate issue date"))?;
    let expires_at = OffsetDateTime::from_unix_timestamp(
        leaf.validity().not_after.timestamp(),
    )
    .map_err(|_| Status::internal("invalid certificate expiry date"))?;
    let new = NewCertificate {
        kind,
        issuer_id,
        cn: common_name.into(),
        certs_der: material.certs_der,
        key_der: material.key_der,
        issued_at,
        expires_at,
        enabled: true,
    };
    let saved = match server_id {
        Some(id) => hosting.insert_certificate(new, &aliases, id).await,
        None => hosting.insert_unassigned_certificate(new, &aliases).await,
    }
    .map_err(storage_status)?;
    metadata(saved)
}

fn metadata(saved: HostedCertificate) -> Result<CertificateInfo, Status> {
    let cert = saved.certificate;
    let peer =
        claviron::ssl::peer::peer_identity(&cert.certs_der).map_err(|_| {
            Status::failed_precondition(
                "stored certificate identity cannot be decoded",
            )
        })?;
    let permissions = claviron::ssl::permission::from_uris(
        peer.subject_uris.iter().map(|uri| &**uri),
    )
    .map_err(|error| Status::failed_precondition(error.to_string()))?
    .map(|scope| crate::proto::mtls::CertificatePermissions {
        names: scope.iter().map(ToString::to_string).collect(),
    });
    Ok(CertificateInfo {
        permissions,
        subject_uris: peer
            .subject_uris
            .into_vec()
            .into_iter()
            .map(String::from)
            .collect(),
        id: cert.id,
        issuer_id: cert.issuer_id,
        kind: match cert.kind {
            CertificateKind::Server => {
                crate::proto::mtls::CertificateKind::Server as i32
            }
            CertificateKind::Client => {
                crate::proto::mtls::CertificateKind::Client as i32
            }
            CertificateKind::Ca => {
                crate::proto::mtls::CertificateKind::Ca as i32
            }
        },
        common_name: cert.cn,
        aliases: saved
            .aliases
            .into_iter()
            .map(|alias| alias.hostname)
            .collect(),
        issued_at: Some(prost_types::Timestamp {
            seconds: cert.issued_at.unix_timestamp(),
            nanos: 0,
        }),
        expires_at: Some(prost_types::Timestamp {
            seconds: cert.expires_at.unix_timestamp(),
            nanos: 0,
        }),
        enabled: cert.enabled,
        revoked_at: cert.revoked_at.map(|date| prost_types::Timestamp {
            seconds: date.unix_timestamp(),
            nanos: 0,
        }),
    })
}

#[cfg(test)]
#[path = "../../../tests/mtls_manager.rs"]
mod tests;
