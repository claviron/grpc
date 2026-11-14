//! Application-authenticated enrollment for device-owned mTLS keys.

use std::num::NonZeroU32;
use std::sync::Arc;

use crate::server::head_within;
use async_trait::async_trait;
use base64ct::{Base64, Encoding};
#[cfg(feature = "authorization")]
use claviron::auth::permission::{Permission, PermissionCatalog, Permissions};
use claviron::edge::{
    Host, Inherit, SessionPlan, SessionProfile, SessionProfiles, VhostResolver,
};
use claviron::http::ext::ConnCtx;
use claviron::http::{
    RouteBody, RouteResponse, ServiceResult, bytes_body, empty_body,
};
use claviron::pipeline::plan::HostExecution;
use claviron::pipeline::{HostHandler, HostHandlerFuture, HostRequest};
use claviron::runtime::registry::{Bootable, Component, priority};
use claviron::runtime::{AppState, registry};
use claviron::ssl::SubjectUri;
use claviron::tls::{CertResolver, CertificateProvider, SessionWire};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tonic::Code;

use super::mtls::{ManagedSigner, MtlsManager};
use crate::access::AccessError;
use crate::server::provider::GrpcServiceProvider;

/// The ALPN protocol id of mTLS enrollment. A host offers it by listing it in
/// `tls.alpn`; a connection that negotiates it reaches only enrollment.
pub const PROTOCOL: &[u8] = b"claviron-mtls-enroll/1";

/// The one path an enrollment session answers.
pub const PATH: &str = "/.well-known/claviron/mtls-enroll";

// Bounds the v1 JSON envelope, including the base64-encoded PKCS#10 request.
const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// What a guard grants: the certificate it issues. The client chooses none
/// of it.
///
/// The common name names this one credential, unique in the hosting store
/// and the handle every consumer uses for it: admission, a VPN address,
/// revocation. The subject URI names the account, the same across its
/// certificates. A certificate carries identity only; what the account may do
/// stays with the application.
pub struct GrpcUser {
    common_name: Box<str>,
    subject: Option<SubjectUri>,
    #[cfg(feature = "authorization")]
    permissions: Permissions,
}

impl GrpcUser {
    /// Issue the certificate named `common_name`, such as `ada.bison-cli`
    /// for one device of the account `ada`.
    pub fn new(common_name: impl Into<Box<str>>) -> Self {
        Self {
            common_name: common_name.into(),
            subject: None,
            #[cfg(feature = "authorization")]
            permissions: Permissions::default(),
        }
    }

    /// Grant these beside the account's own, for connections that present
    /// this certificate only. They are the application's to record when
    /// [`EnrollGuard::enrolled`] reports the certificate issued, and to apply
    /// when such a connection is admitted; none is signed into it.
    #[cfg(feature = "authorization")]
    pub fn with_permissions(
        mut self,
        permissions: Permissions,
    ) -> Self {
        self.permissions = permissions;
        self
    }

    fn enrolled(&self) -> Enrolled<'_> {
        Enrolled {
            common_name: &self.common_name,
            subject: self.subject.as_ref(),
            #[cfg(feature = "authorization")]
            permissions: &self.permissions,
        }
    }

    /// Name the account with a stable subject URI, the same in every
    /// certificate of the account.
    pub fn with_subject(
        mut self,
        subject: SubjectUri,
    ) -> Self {
        self.subject = Some(subject);
        self
    }

    pub(crate) fn common_name(&self) -> &str {
        &self.common_name
    }

    pub(crate) fn subject(&self) -> Option<&SubjectUri> {
        self.subject.as_ref()
    }
}

/// One enrollment, as the client asks for it.
#[non_exhaustive]
pub struct EnrollRequest<'a> {
    /// What the client presents.
    pub credential: &'a Credential,
    /// The client's label for the device it enrolls, a DNS label such as
    /// `bison-cli`. A guard names the certificate after it; it proves
    /// nothing.
    pub device: &'a str,
    /// Permissions the client asks for this certificate beside the account's
    /// own, each defined in the server's catalog. Asking grants nothing.
    #[cfg(feature = "authorization")]
    pub permissions: &'a Permissions,
}

impl<'a> EnrollRequest<'a> {
    /// A request asking for no permissions, as a guard's own tests build one.
    pub fn new(
        credential: &'a Credential,
        device: &'a str,
    ) -> Self {
        Self {
            credential,
            device,
            #[cfg(feature = "authorization")]
            permissions: no_permissions(),
        }
    }
}

#[cfg(feature = "authorization")]
fn no_permissions() -> &'static Permissions {
    static NONE: std::sync::LazyLock<Permissions> =
        std::sync::LazyLock::new(Permissions::default);
    &NONE
}

/// A certificate enrollment issued, as its guard granted it.
#[non_exhaustive]
pub struct Enrolled<'a> {
    pub common_name: &'a str,
    pub subject: Option<&'a SubjectUri>,
    /// What connections presenting this certificate are granted beside the
    /// account's own.
    #[cfg(feature = "authorization")]
    pub permissions: &'a Permissions,
}

/// What a client presents to enroll, chosen by the client. Which kinds a
/// server accepts is its guard's to say; a kind it does not take is refused
/// like a credential that does not verify.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Credential {
    /// An account name and its password.
    Password { username: String, password: String },
    /// A token the application issued, such as an invitation.
    Token(String),
}

impl Credential {
    /// Who presented it, for the operator's log; never the secret.
    fn presenter(&self) -> Presenter<'_> {
        Presenter(self)
    }
}

struct Presenter<'a>(&'a Credential);

impl std::fmt::Display for Presenter<'_> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self.0 {
            Credential::Password { username, .. } => write!(f, "{username:?}"),
            Credential::Token(_) => f.write_str("a token"),
        }
    }
}

/// Verify a credential and name the certificate before returning a GrpcUser.
/// Applications own credential verification, access policy, account status
/// and how their certificates are named.
#[async_trait]
pub trait EnrollGuard: Send + Sync + 'static {
    async fn authorize(
        &self,
        request: &EnrollRequest<'_>,
    ) -> Result<GrpcUser, AccessError>;

    /// The certificate was issued, or an issued one returned again for the
    /// same key. An application that keeps per-certificate state, such as its
    /// grants, records it here; a failure answers 503 and the client retries.
    async fn enrolled(
        &self,
        _enrolled: &Enrolled<'_>,
    ) -> Result<(), AccessError> {
        Ok(())
    }
}

pub fn register_guard<G: EnrollGuard>(
    state: &AppState,
    guard: Arc<G>,
) -> registry::Result<()> {
    let registry = state.registry_ref();
    registry.insert(guard)?;
    registry.bind_dyn::<dyn EnrollGuard, G>(|guard| guard)?;
    Ok(())
}

/// Offer mTLS enrollment as a session profile, for the hosts that list it.
pub(crate) fn register_profile(
    state: &AppState,
    grpc: Arc<GrpcServiceProvider>,
) -> registry::Result<()> {
    let registry = state.registry_ref();
    let profile = Arc::new(EnrollProfile { grpc });
    registry.register(profile.clone())?;
    if let Some(profiles) = registry.resolve::<SessionProfiles>() {
        profiles
            .register(profile)
            .map_err(|conflict| registry::Error::msg(conflict.to_string()))?;
    }
    Ok(())
}

struct EnrollProfile {
    grpc: Arc<GrpcServiceProvider>,
}

/// Whether any host this process serves offers enrollment.
fn offered(vhosts: &VhostResolver) -> bool {
    vhosts.snapshot().canonical_entries().any(|(_, record)| {
        record.config.tls.alpn.keys().any(|id| id.as_bytes() == PROTOCOL)
    })
}

impl Component<AppState> for EnrollProfile {
    // The host table is published before this boots, so it can tell whether
    // enrollment is offered at all.
    type Deps = (Arc<CertificateProvider>, Arc<VhostResolver>);

    fn name(&self) -> &'static str {
        "GrpcMtlsEnroll"
    }

    fn boot_priority(&self) -> Option<u8> {
        Some(priority::NORMAL)
    }

    fn as_bootable(&self) -> Option<&dyn Bootable<AppState, Self::Deps>> {
        Some(self)
    }
}

#[async_trait]
impl Bootable<AppState, (Arc<CertificateProvider>, Arc<VhostResolver>)>
    for EnrollProfile
{
    async fn boot(
        &self,
        (_, vhosts): (Arc<CertificateProvider>, Arc<VhostResolver>),
        state: &AppState,
    ) -> registry::Result<()> {
        // A server that offers no enrollment needs no signer, so a missing
        // CA key does not stop it.
        if state.is_master() || !offered(&vhosts) {
            return Ok(());
        }
        let signer = MtlsManager::prepare_enroll_signer(state).await.map_err(
            |error| registry::Error::msg(error.message().to_owned()),
        )?;
        state.registry_ref().insert(signer)?;
        Ok(())
    }
}

/// This host's parameters for enrollment, under its id in `tls.alpn`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollParams {
    /// Days an issued certificate is valid.
    validity_days: NonZeroU32,
    /// What a certificate enrolled on this host may be granted beside its
    /// account's own: the bound a client's request meets. Unwritten, nothing.
    #[cfg(feature = "authorization")]
    #[serde(default)]
    permissions: Vec<Permission>,
}

impl SessionProfile for EnrollProfile {
    fn protocol(&self) -> &'static [u8] {
        PROTOCOL
    }

    /// A tool that enrolls and exits sends one request over HTTP/1.1; an
    /// application that keeps the connection speaks HTTP/2.
    fn wire(&self) -> SessionWire {
        SessionWire::Either
    }

    /// Enrollment takes credentials, so it keeps everything the host declares
    /// to admit and bound them: the real client behind a trusted proxy, the
    /// deny list and ACL, quotas, the access log and metrics.
    fn inherits(&self) -> Inherit {
        Inherit::PROXY
            | Inherit::DENY
            | Inherit::ACL
            | Inherit::QUOTA
            | Inherit::ACCESS_LOG
            | Inherit::METRICS
    }

    fn execution(
        &self,
        plan: SessionPlan<'_>,
    ) -> registry::Result<HostExecution> {
        let state = plan.state();
        if !state.is_master()
            && state.registry_ref().resolve::<ManagedSigner>().is_none()
        {
            return Err(registry::Error::msg(
                "mTLS enrollment has no signer: a host that starts offering it takes a restart",
            ));
        }
        let guard = state
            .registry_ref()
            .resolve_dyn::<dyn EnrollGuard>()
            .ok_or_else(|| {
                registry::Error::msg("mTLS enrollment requires an EnrollGuard")
            })?;
        let params: EnrollParams = plan.params()?;
        #[cfg(feature = "authorization")]
        let grantable = if params.permissions.is_empty() {
            Permissions::default()
        } else {
            state
                .registry_ref()
                .resolve::<PermissionCatalog>()
                .ok_or_else(|| {
                    registry::Error::msg(
                        "mTLS enrollment permissions need a permission catalog",
                    )
                })?
                .validate(&params.permissions)
                .map_err(|error| {
                    registry::Error::msg(format!(
                        "mTLS enrollment permissions: {error}"
                    ))
                })?
        };
        let handler = EnrollHandler {
            state: state.clone(),
            guard,
            management_hosts: self.grpc.config().vhosts().to_vec().into(),
            validity_days: params.validity_days,
            #[cfg(feature = "authorization")]
            grantable: Arc::new(grantable),
            timeout: plan.policy().responses.idle_timeout,
        };
        plan.backend(handler)
    }
}

struct EnrollHandler {
    state: AppState,
    guard: Arc<dyn EnrollGuard>,
    management_hosts: Arc<[Host]>,
    validity_days: NonZeroU32,
    /// The bound of what a certificate enrolled here may be granted.
    #[cfg(feature = "authorization")]
    grantable: Arc<Permissions>,
    /// The host's response idle timeout, fixed when the session is prepared.
    timeout: Option<std::time::Duration>,
}

impl HostHandler for EnrollHandler {
    fn call(
        &self,
        request: HostRequest,
    ) -> HostHandlerFuture {
        // Any other path is not the session's; the plan answers it as unknown.
        if request.head().uri.path() != PATH {
            return Box::pin(std::future::ready(ServiceResult::Unhandled(
                request,
            )));
        }
        let state = self.state.clone();
        let guard = self.guard.clone();
        let management_hosts = self.management_hosts.clone();
        let validity_days = self.validity_days;
        #[cfg(feature = "authorization")]
        let grantable = self.grantable.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let response = head_within(
                timeout,
                enroll(
                    request.into_request(),
                    &state,
                    guard.as_ref(),
                    validity_days,
                    &management_hosts,
                    #[cfg(feature = "authorization")]
                    &grantable,
                ),
            )
            .await
            .unwrap_or_else(|| {
                reply(StatusCode::GATEWAY_TIMEOUT, empty_body())
            });
            ServiceResult::Handled(response)
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    credential: Credential,
    device: String,
    /// Without `authorization` a request naming permissions is refused as
    /// malformed: this server cannot grant them.
    #[cfg(feature = "authorization")]
    #[serde(default)]
    permissions: Vec<Permission>,
    csr_der: String,
}

/// A device label as DNS names a label: 1 to 63 lowercase letters, digits
/// and hyphens, starting and ending with a letter or digit.
fn is_device_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'
        })
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Issued {
    pub(crate) certificate_chain_pem: String,
    pub(crate) authority_certificate_pem: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    management_address: Box<str>,
    #[serde(flatten)]
    issued: Issued,
}

fn management_address(
    state: &AppState,
    management_hosts: &[Host],
) -> Option<Box<str>> {
    let registry = state.registry_ref();
    let resolver = registry.resolve::<VhostResolver>()?;
    let hosts = resolver.snapshot();
    let certificates = registry.resolve::<CertResolver>()?;

    for key in management_hosts {
        let Some(host) = hosts.canonical_config(key) else {
            continue;
        };
        let mut aliases: Vec<_> = hosts
            .alias_entries()
            .filter_map(|(alias, canonical)| {
                (canonical == key).then_some(alias)
            })
            .collect();
        aliases.sort_unstable_by_key(|alias| alias.as_str_if_textual());

        let candidates =
            std::iter::once(key).chain(host.aliases().iter()).chain(aliases);
        for candidate in candidates {
            let Some(name) = candidate.as_sni().map(|sni| sni.as_str()) else {
                continue;
            };
            if name.starts_with("*.")
                || !hosts
                    .resolve_exact(candidate)
                    .is_some_and(|(owner, _)| owner == *key)
                || !certificates.contains(name)
            {
                continue;
            }
            if let Some(port) = resolver.serving_mtls_h2_port(candidate, key) {
                return Some(if port == 443 {
                    format!("https://{name}").into_boxed_str()
                } else {
                    format!("https://{name}:{port}").into_boxed_str()
                });
            }
        }
    }
    None
}

async fn enroll(
    request: Request<RouteBody>,
    state: &AppState,
    guard: &dyn EnrollGuard,
    validity_days: NonZeroU32,
    management_hosts: &[Host],
    #[cfg(feature = "authorization")] grantable: &Permissions,
) -> RouteResponse {
    if request.method() == Method::HEAD {
        let status = if management_address(state, management_hosts).is_some() {
            StatusCode::NO_CONTENT
        } else {
            tracing::warn!(
                "mTLS enrollment probe could not find a serving management TLS/H2 address"
            );
            StatusCode::SERVICE_UNAVAILABLE
        };
        let mut response = reply(status, empty_body());
        // Identifies the enrollment probe protocol to clients.
        response.headers_mut().insert(
            "claviron-mtls-enroll",
            http::HeaderValue::from_static("1"),
        );
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        return response;
    }
    if request.method() != Method::POST {
        let mut response = reply(StatusCode::METHOD_NOT_ALLOWED, empty_body());
        response.headers_mut().insert(
            header::ALLOW,
            http::HeaderValue::from_static("HEAD, POST"),
        );
        return response;
    }
    let client = request
        .extensions()
        .get::<Arc<ConnCtx>>()
        .map(|connection| connection.real_ip.unwrap_or(connection.remote.ip()))
        .map_or_else(|| "an unknown client".to_owned(), |ip| ip.to_string());
    if request.headers().contains_key(header::ORIGIN) {
        tracing::warn!(
            "mTLS enrollment refused a browser request from {client}"
        );
        return reply(StatusCode::FORBIDDEN, empty_body());
    }
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| {
            !value.trim().eq_ignore_ascii_case("application/json")
        })
    {
        return reply(StatusCode::UNSUPPORTED_MEDIA_TYPE, empty_body());
    }

    let mut incoming = request.into_body();
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        let Ok(frame) = frame else {
            return reply(StatusCode::BAD_REQUEST, empty_body());
        };
        if let Ok(data) = frame.into_data() {
            if data.len() > MAX_REQUEST_BYTES - body.len() {
                return reply(StatusCode::PAYLOAD_TOO_LARGE, empty_body());
            }
            body.extend_from_slice(&data);
        }
    }
    let Ok(input) = serde_json::from_slice::<Enrollment>(&body) else {
        return reply(StatusCode::BAD_REQUEST, empty_body());
    };
    let Ok(csr) = Base64::decode_vec(&input.csr_der) else {
        return reply(StatusCode::BAD_REQUEST, empty_body());
    };
    if !is_device_label(&input.device) {
        return reply(StatusCode::BAD_REQUEST, empty_body());
    }
    #[cfg(feature = "authorization")]
    let permissions = match requested_permissions(state, &input.permissions) {
        Some(permissions) => permissions,
        None => return reply(StatusCode::BAD_REQUEST, empty_body()),
    };
    // What a client asks must be within what this host grants.
    #[cfg(feature = "authorization")]
    if !within(&permissions, grantable) {
        tracing::warn!(
            "mTLS enrollment refused permissions this host does not grant, asked by {} from {client}",
            input.credential.presenter()
        );
        return reply(StatusCode::FORBIDDEN, empty_body());
    }
    let request = EnrollRequest {
        credential: &input.credential,
        device: &input.device,
        #[cfg(feature = "authorization")]
        permissions: &permissions,
    };
    let user = match guard.authorize(&request).await {
        Ok(user) => user,
        Err(AccessError::Unauthenticated) => {
            tracing::warn!(
                "mTLS enrollment did not accept the credential of {} from {client}",
                input.credential.presenter()
            );
            return reply(StatusCode::UNAUTHORIZED, empty_body());
        }
        Err(AccessError::Forbidden) => {
            tracing::warn!(
                "mTLS enrollment is forbidden for {} from {client}",
                input.credential.presenter()
            );
            return reply(StatusCode::FORBIDDEN, empty_body());
        }
        Err(AccessError::Unavailable) => {
            tracing::warn!(
                "mTLS enrollment could not reach its access policy for {} from {client}",
                input.credential.presenter()
            );
            return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
        }
    };
    // A guard grants within the same bound.
    #[cfg(feature = "authorization")]
    if !within(&user.permissions, grantable) {
        tracing::error!(
            "mTLS enrollment guard granted permissions this host does not grant"
        );
        return reply(StatusCode::INTERNAL_SERVER_ERROR, empty_body());
    }
    let Some(management_address) = management_address(state, management_hosts)
    else {
        tracing::warn!(
            "mTLS enrollment could not find a serving management TLS/H2 address"
        );
        return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
    };
    let result = match MtlsManager::from_state(state) {
        Ok(manager) => manager.register_client(&user, csr, validity_days).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(issued) => {
            if guard.enrolled(&user.enrolled()).await.is_err() {
                tracing::warn!(
                    "mTLS enrollment could not record the certificate of {} from {client}",
                    input.credential.presenter()
                );
                return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
            }
            tracing::info!(
                "mTLS enrollment issued a client certificate to {} at {client}",
                input.credential.presenter()
            );
            let Ok(body) = serde_json::to_vec(&EnrollResponse {
                management_address,
                issued,
            }) else {
                return reply(StatusCode::INTERNAL_SERVER_ERROR, empty_body());
            };
            let mut response =
                reply(StatusCode::CREATED, bytes_body(body.into()));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                "application/json".parse().unwrap(),
            );
            response
        }
        Err(error) => {
            let status = match error.code() {
                Code::AlreadyExists => {
                    tracing::warn!(
                        "mTLS enrollment found an existing certificate for {} from {client}",
                        input.credential.presenter()
                    );
                    StatusCode::CONFLICT
                }
                Code::InvalidArgument => StatusCode::BAD_REQUEST,
                Code::FailedPrecondition => {
                    tracing::warn!(
                        reason = error.message(),
                        "mTLS enrollment is unavailable"
                    );
                    StatusCode::SERVICE_UNAVAILABLE
                }
                _ => {
                    tracing::error!(code = ?error.code(), "mTLS enrollment failed");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            };
            reply(status, empty_body())
        }
    }
}

/// Whether every one of `permissions` is in `bound`.
#[cfg(feature = "authorization")]
fn within(
    permissions: &Permissions,
    bound: &Permissions,
) -> bool {
    permissions.iter().all(|permission| bound.contains_name(permission))
}

/// What a request asks, each name defined in the server's catalog; `None`
/// when a name is not, or permissions are asked of a server defining none.
#[cfg(feature = "authorization")]
fn requested_permissions(
    state: &AppState,
    requested: &[Permission],
) -> Option<Permissions> {
    if requested.is_empty() {
        return Some(Permissions::default());
    }
    state
        .registry_ref()
        .resolve::<PermissionCatalog>()?
        .validate(requested)
        .ok()
}

fn reply(
    status: StatusCode,
    body: RouteBody,
) -> RouteResponse {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[cfg(test)]
#[path = "../../../tests/enroll.rs"]
mod tests;
