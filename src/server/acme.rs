//! SSL/TLS Certificate Management gRPC Service

use std::str::FromStr;
use std::sync::Arc;

use claviron::db::DbService;
use claviron::hosting::{HostedCertificate, HostingService, HostingStore};
use claviron::runtime::AppState;
use claviron::runtime::registry::Reloadable;
use claviron::ssl::Sni;
use claviron::ssl::formatters::certificate_chain_to_pem;
use claviron::tls::{CertResolver, CertificateManager};
use claviron_acme::actions::database::{add_cert_to_db, renew_cert_to_db};
use claviron_acme::{AcmeError, AcmeProvider as AcmeConfigService, AcmeStore};
use tonic::{Request, Response, Status};

pub mod acme_proto {
    include!(concat!(env!("OUT_DIR"), "/claviron.acme.rs"));
}

use acme_proto::acme_manager_server::AcmeManager;
use acme_proto::{
    AddCertificateRequest, AddCertificateResponse,
    AddCertificateToServersRequest, CertificateInventoryInfo,
    CertificateResponse, GetCertificateRequest,
    ListCertificateInventoryResponse, ListCertificatesByServerRequest,
    ListCertificatesRequest, ListCertificatesResponse,
    ListServersByCertificateRequest, ListServersResponse, OperationResponse,
    ReloadRequest, RemoveCertificateFromServersRequest,
    RenewCertificateRequest, RenewCertificateResponse, ServerInfo,
    UpdateCertificateRequest,
};

#[derive(Clone)]
pub struct AcmeService {
    state: AppState,
    hosting: HostingStore,
    acme_store: AcmeStore,
    server_id: i32,
    acme: Arc<AcmeConfigService>,
}

impl AcmeService {
    pub fn new(state: AppState) -> Result<Self, Status> {
        let db =
            state.registry_ref().resolve::<DbService>().ok_or_else(|| {
                Status::failed_precondition(
                    "AcmeService: DbService not registered",
                )
            })?;
        // Through HostingService: the store it opens announces its writes
        // where the database does not (SQLite).
        let hosting = state
            .registry_ref()
            .resolve::<HostingService>()
            .ok_or_else(|| {
                Status::failed_precondition(
                    "AcmeService: HostingService not registered",
                )
            })?
            .store()
            .map_err(|error| {
                Status::failed_precondition(format!("AcmeService: {error}"))
            })?;
        let acme_store = AcmeStore::open(&db).map_err(|error| {
            Status::failed_precondition(format!("AcmeService: {error}"))
        })?;
        let server_id = state
            .registry_ref()
            .resolve::<HostingService>()
            .ok_or_else(|| {
                Status::failed_precondition("HostingService is not registered")
            })?
            .server_id()
            .ok_or_else(|| {
                Status::failed_precondition("HostingService is not initialized")
            })?;
        let acme = state
            .registry_ref()
            .resolve::<AcmeConfigService>()
            .ok_or_else(|| {
                Status::failed_precondition(
                    "AcmeService: AcmeConfigService not registered",
                )
            })?;
        Ok(Self { state, hosting, acme_store, server_id, acme })
    }

    fn acme_config(&self) -> Result<Arc<claviron_acme::AcmeConfig>, Status> {
        self.acme.snapshot().ok_or_else(|| {
            Status::failed_precondition(
                "AcmeService: acme.yaml snapshot is empty",
            )
        })
    }

    fn resolver(&self) -> Result<Arc<CertResolver>, Status> {
        self.state.registry_ref().resolve::<CertResolver>().ok_or_else(|| {
            Status::failed_precondition("Certificate resolver not registered")
        })
    }
}

#[tonic::async_trait]
impl AcmeManager for AcmeService {
    async fn add_certificate(
        &self,
        request: Request<AddCertificateRequest>,
    ) -> Result<Response<AddCertificateResponse>, Status> {
        let aliases = request
            .into_inner()
            .aliases
            .into_iter()
            .map(|raw| {
                Sni::from_str(&raw).map_err(|error| {
                    Status::invalid_argument(format!(
                        "Invalid alias '{raw}': {error}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cn = aliases.first().cloned().ok_or_else(|| {
            Status::invalid_argument("At least one alias is required")
        })?;
        let config = self.acme_config()?;
        let result = add_cert_to_db(
            &self.acme_store,
            &self.hosting,
            self.server_id,
            &cn,
            &aliases,
            &config,
        )
        .await
        .map_err(acme_status)?;
        Ok(Response::new(AddCertificateResponse {
            id: result.certificate.id,
            content: result.content,
            attached_existing: result.attached_existing,
        }))
    }

    async fn get_certificate(
        &self,
        request: Request<GetCertificateRequest>,
    ) -> Result<Response<CertificateResponse>, Status> {
        let hostname = request.into_inner().hostname;
        let hostname = hostname.trim();
        if hostname.is_empty() {
            return Err(Status::invalid_argument("hostname must not be empty"));
        }
        let hosted = self
            .hosting
            .certificate_by_hostname(hostname)
            .await
            .map_err(hosting_status)?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "No certificate found for hostname '{hostname}'"
                ))
            })?;
        let fullchain_pem = certificate_chain_to_pem(
            &hosted.certificate.certs_der,
        )
        .map_err(|error| {
            Status::internal(format!("Failed to encode certificate: {error}"))
        })?;
        let mut response = certificate_response(hosted, true);
        response.fullchain_pem = fullchain_pem;
        Ok(Response::new(response))
    }

    async fn renew_certificate(
        &self,
        request: Request<RenewCertificateRequest>,
    ) -> Result<Response<RenewCertificateResponse>, Status> {
        let req = request.into_inner();
        let cn = Sni::from_str(&req.cn).map_err(|error| {
            Status::invalid_argument(format!("Invalid SNI: {error}"))
        })?;
        let renew_before = req
            .renew_before
            .map(|value| {
                u32::try_from(value).map_err(|_| {
                    Status::invalid_argument("renew_before is out of range")
                })
            })
            .transpose()?;
        let config = self.acme_config()?;
        let (certificate, content) = renew_cert_to_db(
            &self.acme_store,
            &self.hosting,
            &config,
            &cn,
            renew_before,
            false,
        )
        .await
        .map_err(acme_status)?;
        Ok(Response::new(RenewCertificateResponse {
            content,
            expires_at: Some(to_proto_ts(certificate.expires_at)),
        }))
    }

    async fn list_certificates(
        &self,
        request: Request<ListCertificatesRequest>,
    ) -> Result<Response<ListCertificatesResponse>, Status> {
        let (active_only, expires_before) =
            certificate_filters(request.into_inner())?;
        let certificates = self
            .hosting
            .certificates(active_only, expires_before)
            .await
            .map_err(hosting_status)?
            .into_iter()
            .map(|hosted| certificate_response(hosted, false))
            .collect();
        Ok(Response::new(ListCertificatesResponse { certificates }))
    }

    async fn list_certificate_inventory(
        &self,
        request: Request<ListCertificatesRequest>,
    ) -> Result<Response<ListCertificateInventoryResponse>, Status> {
        let (active_only, expires_before) =
            certificate_filters(request.into_inner())?;
        let hosted_certificates = self
            .hosting
            .certificates(active_only, expires_before)
            .await
            .map_err(hosting_status)?;
        let mut certificates = Vec::with_capacity(hosted_certificates.len());
        for hosted in hosted_certificates {
            let servers = self
                .hosting
                .servers_for_certificate(&hosted.certificate.cn)
                .await
                .map_err(hosting_status)?;
            certificates.push(certificate_inventory_info(hosted, servers));
        }
        Ok(Response::new(ListCertificateInventoryResponse { certificates }))
    }

    async fn remove_certificate(
        &self,
        request: Request<UpdateCertificateRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let cn = request.into_inner().cn;
        if !self
            .hosting
            .delete_certificate(&cn)
            .await
            .map_err(hosting_status)?
        {
            return Err(Status::not_found(format!(
                "Certificate '{cn}' not found"
            )));
        }
        self.resolver()?.remove_host(&cn);
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!("Certificate '{cn}' permanently deleted")),
        }))
    }

    async fn disable_certificate(
        &self,
        request: Request<UpdateCertificateRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let cn = request.into_inner().cn;
        self.hosting
            .set_certificate_enabled(&cn, false)
            .await
            .map_err(hosting_status)?;
        self.resolver()?.remove_host(&cn);
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!(
                "Certificate '{cn}' disabled and removed from resolver"
            )),
        }))
    }

    async fn activate_certificate(
        &self,
        request: Request<UpdateCertificateRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let cn = request.into_inner().cn;
        let hosted = self
            .hosting
            .set_certificate_enabled(&cn, true)
            .await
            .map_err(hosting_status)?;
        if self.state.is_standalone() {
            let resolver = self.resolver()?;
            CertificateManager::new(&self.hosting, &resolver)
                .upsert(hosted)
                .map_err(|error| Status::internal(error.to_string()))?;
        }
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!("Certificate '{cn}' activated")),
        }))
    }

    async fn reload_resolver(
        &self,
        _request: Request<ReloadRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        self.resolver()?.reload(&self.state).await.map_err(|error| {
            Status::internal(format!("Failed to reload resolver: {error}"))
        })?;
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(
                "Certificate resolver reloaded successfully".to_owned(),
            ),
        }))
    }

    async fn add_certificate_to_servers(
        &self,
        request: Request<AddCertificateToServersRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let req = request.into_inner();
        let added = self
            .hosting
            .add_certificate_to_servers(&req.cn, &req.server_names)
            .await
            .map_err(hosting_status)?;
        if self.state.is_standalone() {
            let hosted = self
                .hosting
                .certificate_by_cn(&req.cn)
                .await
                .map_err(hosting_status)?
                .ok_or_else(|| {
                    Status::not_found(format!(
                        "Certificate '{}' not found",
                        req.cn
                    ))
                })?;
            if hosted.certificate.enabled {
                let resolver = self.resolver()?;
                CertificateManager::new(&self.hosting, &resolver)
                    .upsert(hosted)
                    .map_err(|error| Status::internal(error.to_string()))?;
            }
        }
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!(
                "Added certificate '{}' to {} server(s)",
                req.cn, added
            )),
        }))
    }

    async fn remove_certificate_from_servers(
        &self,
        request: Request<RemoveCertificateFromServersRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let req = request.into_inner();
        let removed = self
            .hosting
            .remove_certificate_from_servers(&req.cn, &req.server_names)
            .await
            .map_err(hosting_status)?;
        if self.state.is_standalone() {
            self.resolver()?.remove_host(&req.cn);
        }
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!(
                "Removed certificate '{}' from {} server(s)",
                req.cn, removed
            )),
        }))
    }

    async fn list_certificates_by_server(
        &self,
        request: Request<ListCertificatesByServerRequest>,
    ) -> Result<Response<ListCertificatesResponse>, Status> {
        let server_name = request.into_inner().server_name;
        let server = self
            .hosting
            .server_by_name(&server_name)
            .await
            .map_err(hosting_status)?
            .ok_or_else(|| {
                Status::not_found(format!("Server '{server_name}' not found"))
            })?;
        let certificates = self
            .hosting
            .all_certificates_for_server(server.id)
            .await
            .map_err(hosting_status)?
            .into_iter()
            .map(|hosted| certificate_response(hosted, false))
            .collect();
        Ok(Response::new(ListCertificatesResponse { certificates }))
    }

    async fn list_servers_by_certificate(
        &self,
        request: Request<ListServersByCertificateRequest>,
    ) -> Result<Response<ListServersResponse>, Status> {
        let cn = request.into_inner().cn;
        let servers = self
            .hosting
            .servers_for_certificate(&cn)
            .await
            .map_err(hosting_status)?
            .into_iter()
            .map(|server| ServerInfo {
                id: server.id,
                name: server.name,
                enabled: server.enabled,
            })
            .collect();
        Ok(Response::new(ListServersResponse { servers }))
    }
}

pub fn create_acme_service(
    state: AppState
) -> Result<
    acme_proto::acme_manager_server::AcmeManagerServer<AcmeService>,
    Status,
> {
    Ok(acme_proto::acme_manager_server::AcmeManagerServer::new(
        AcmeService::new(state)?,
    ))
}

fn certificate_response(
    hosted: HostedCertificate,
    omit_cn_alias: bool,
) -> CertificateResponse {
    let certificate = hosted.certificate;
    let aliases = hosted
        .aliases
        .into_iter()
        .map(|alias| alias.hostname)
        .filter(|alias| !omit_cn_alias || alias != &certificate.cn)
        .collect();
    CertificateResponse {
        id: certificate.id,
        cname: certificate.cn,
        aliases,
        issued_at: Some(to_proto_ts(certificate.issued_at)),
        expires_at: Some(to_proto_ts(certificate.expires_at)),
        enabled: certificate.enabled,
        updated_at: certificate.updated_at.map(to_proto_ts),
        revoked_at: certificate.revoked_at.map(to_proto_ts),
        fullchain_pem: String::new(),
        kind: match certificate.kind {
            claviron::hosting::CertificateKind::Server => {
                acme_proto::CertificateKind::Server as i32
            }
            claviron::hosting::CertificateKind::Client => {
                acme_proto::CertificateKind::Client as i32
            }
            claviron::hosting::CertificateKind::Ca => {
                acme_proto::CertificateKind::Ca as i32
            }
        },
    }
}

fn certificate_inventory_info(
    hosted: HostedCertificate,
    servers: Vec<claviron::hosting::Server>,
) -> CertificateInventoryInfo {
    CertificateInventoryInfo {
        certificate: Some(certificate_response(hosted, false)),
        servers: servers
            .into_iter()
            .map(|server| ServerInfo {
                id: server.id,
                name: server.name,
                enabled: server.enabled,
            })
            .collect(),
    }
}

fn certificate_filters(
    request: ListCertificatesRequest
) -> Result<(bool, Option<time::OffsetDateTime>), Status> {
    let expires_before = request
        .expiring_days
        .map(|days| {
            if days < 0 {
                return Err(Status::invalid_argument(
                    "expiring_days must not be negative",
                ));
            }
            time::OffsetDateTime::now_utc()
                .checked_add(time::Duration::days(i64::from(days)))
                .ok_or_else(|| {
                    Status::invalid_argument("expiring_days is out of range")
                })
        })
        .transpose()?;
    Ok((request.active_only.unwrap_or(false), expires_before))
}

fn hosting_status(error: claviron::hosting::HostingError) -> Status {
    match error {
        claviron::hosting::HostingError::NotFound(message) => {
            Status::not_found(message)
        }
        claviron::hosting::HostingError::InvalidInput(message) => {
            Status::invalid_argument(message)
        }
        error => Status::internal(error.to_string()),
    }
}

fn acme_status(error: AcmeError) -> Status {
    match error {
        AcmeError::RenewalNotDue { .. } | AcmeError::RecentlyDone(_) => {
            Status::failed_precondition(error.to_string())
        }
        AcmeError::TooMany(_) => Status::resource_exhausted(error.to_string()),
        error => Status::internal(error.to_string()),
    }
}

fn to_proto_ts(dt: time::OffsetDateTime) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.unix_timestamp(),
        nanos: dt.nanosecond() as i32,
    }
}

#[cfg(test)]
mod tests {
    use claviron::hosting::{
        Certificate, CertificateAlias, HostedCertificate, Server,
    };
    use time::OffsetDateTime;

    use super::{certificate_filters, certificate_inventory_info};
    use crate::server::acme::acme_proto::ListCertificatesRequest;

    #[test]
    fn certificate_inventory_preserves_dates_aliases_state_and_servers() {
        let issued_at = OffsetDateTime::UNIX_EPOCH;
        let updated_at = issued_at + time::Duration::hours(1);
        let expires_at = issued_at + time::Duration::days(90);
        let info = certificate_inventory_info(
            HostedCertificate {
                certificate: Certificate {
                    id: 7,
                    kind: claviron::hosting::CertificateKind::Server,
                    issuer_id: Some(2),
                    cn: "example.test".to_owned(),
                    certs_der: Vec::new(),
                    key_der: Vec::new(),
                    expires_at,
                    issued_at,
                    updated_at: Some(updated_at),
                    revoked_at: Some(updated_at),
                    enabled: false,
                },
                aliases: vec![CertificateAlias {
                    id: 8,
                    certificate_id: 7,
                    hostname: "www.example.test".to_owned(),
                    created_at: issued_at,
                }],
            },
            vec![Server {
                id: 9,
                name: "edge".to_owned(),
                created_at: issued_at,
                enabled: true,
            }],
        );

        let certificate =
            info.certificate.expect("certificate should be present");
        assert_eq!(certificate.cname, "example.test");
        assert_eq!(
            certificate.kind,
            super::acme_proto::CertificateKind::Server as i32
        );
        assert_eq!(certificate.aliases, ["www.example.test"]);
        assert!(!certificate.enabled);
        assert_eq!(
            certificate.revoked_at.map(|value| value.seconds),
            Some(3_600)
        );
        assert_eq!(certificate.issued_at.map(|value| value.seconds), Some(0));
        assert_eq!(
            certificate.updated_at.map(|value| value.seconds),
            Some(3_600)
        );
        assert_eq!(
            certificate.expires_at.map(|value| value.seconds),
            Some(7_776_000)
        );
        assert_eq!(info.servers.len(), 1);
        assert_eq!(info.servers[0].name, "edge");
        assert!(info.servers[0].enabled);
    }

    #[test]
    fn certificate_filter_rejects_negative_expiry_window() {
        let error = certificate_filters(ListCertificatesRequest {
            active_only: None,
            expiring_days: Some(-1),
        })
        .expect_err("negative windows must be rejected");

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
