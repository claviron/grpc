//! Application-authenticated enrollment for device-owned mTLS keys.

use std::num::NonZeroU32;
use std::sync::Arc;

use crate::server::head_within;
use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use claviron::auth::AnyAuthenticated;
use claviron::edge::{
    Host, HostConfig, SessionProfile, SessionProfiles, VhostResolver,
};
use claviron::http::config::HttpPolicy;
use claviron::http::ext::ConnCtx;
use claviron::http::{
    OtherHandler, OtherService, RouteBody, RouteFuture, RouteResponse,
    RustRouter, bytes_body, empty_body,
};
use claviron::pipeline::plan::HostExecution;
use claviron::runtime::registry::{Bootable, Component, priority};
use claviron::runtime::{AppState, registry};
use claviron::ssl::SubjectUri;
use claviron::tls::Proto;
use claviron::tls::{CertResolver, CertificateProvider};
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

/// The authorized application identity. The client cannot choose its claims.
pub struct GrpcUser {
    actor: AnyAuthenticated,
    subject: Option<SubjectUri>,
}

impl GrpcUser {
    /// Use the authenticated actor's identifier as the client certificate CN.
    pub fn new(actor: AnyAuthenticated) -> Self {
        Self { actor, subject: None }
    }

    /// Add a server-selected stable subject URI and the grpc.access grant.
    pub fn with_subject(
        mut self,
        subject: SubjectUri,
    ) -> Self {
        self.subject = Some(subject);
        self
    }

    pub(crate) fn into_parts(self) -> (AnyAuthenticated, Option<SubjectUri>) {
        (self.actor, self.subject)
    }
}

/// Verify credentials and authorize grpc.access before returning a GrpcUser.
/// Applications own password verification, access policy and account status.
#[async_trait]
pub trait EnrollGuard: Send + Sync + 'static {
    async fn authorize(
        &self,
        username: &str,
        password: &str,
    ) -> Result<GrpcUser, AccessError>;
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
        record.config.tls.alpn.iter().any(|id| id.as_bytes() == PROTOCOL)
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

impl SessionProfile for EnrollProfile {
    fn protocol(&self) -> &'static [u8] {
        PROTOCOL
    }

    fn wire(&self) -> Proto {
        Proto::H2
    }

    fn execution(
        &self,
        state: &AppState,
        _host: &Host,
        _config: &Arc<HostConfig>,
        policy: &HttpPolicy,
    ) -> registry::Result<HostExecution> {
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
        let config = self.grpc.config();
        let validity_days = config.enroll_validity_days.ok_or_else(|| {
            registry::Error::msg(
                "enroll_validity_days is required where a host offers mTLS enrollment",
            )
        })?;
        let handler = EnrollHandler {
            state: state.clone(),
            guard,
            management_hosts: config.vhosts().to_vec().into(),
            validity_days,
            timeout: policy.responses.idle_timeout,
        };
        Ok(HostExecution::router(
            RustRouter::Other(OtherService::new(handler)),
            policy.clone(),
        ))
    }
}

struct EnrollHandler {
    state: AppState,
    guard: Arc<dyn EnrollGuard>,
    management_hosts: Arc<[Host]>,
    validity_days: NonZeroU32,
    /// The host's response idle timeout, fixed when the session is prepared.
    timeout: Option<std::time::Duration>,
}

impl OtherHandler for EnrollHandler {
    fn name(&self) -> &'static str {
        "mtls_enroll"
    }

    fn call(
        &self,
        request: Request<RouteBody>,
    ) -> RouteFuture {
        // The session reaches nothing else, so any other path is not found.
        if request.uri().path() != PATH {
            return Box::pin(std::future::ready(Ok(reply(
                StatusCode::NOT_FOUND,
                empty_body(),
            ))));
        }
        let state = self.state.clone();
        let guard = self.guard.clone();
        let management_hosts = self.management_hosts.clone();
        let validity_days = self.validity_days;
        let timeout = self.timeout;
        Box::pin(async move {
            Ok(head_within(
                timeout,
                enroll(
                    request,
                    &state,
                    guard.as_ref(),
                    validity_days,
                    &management_hosts,
                ),
            )
            .await
            .unwrap_or_else(|| {
                reply(StatusCode::GATEWAY_TIMEOUT, empty_body())
            }))
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    username: String,
    password: String,
    csr_der: String,
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
    let user = match guard.authorize(&input.username, &input.password).await {
        Ok(user) => user,
        Err(AccessError::Unauthenticated) => {
            tracing::warn!(
                "mTLS enrollment did not accept the credentials of {:?} from {client}",
                input.username
            );
            return reply(StatusCode::UNAUTHORIZED, empty_body());
        }
        Err(AccessError::Forbidden) => {
            tracing::warn!(
                "mTLS enrollment is forbidden for {:?} from {client}",
                input.username
            );
            return reply(StatusCode::FORBIDDEN, empty_body());
        }
        Err(AccessError::Unavailable) => {
            tracing::warn!(
                "mTLS enrollment could not reach its access policy for {:?} from {client}",
                input.username
            );
            return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
        }
    };
    let Some(management_address) = management_address(state, management_hosts)
    else {
        tracing::warn!(
            "mTLS enrollment could not find a serving management TLS/H2 address"
        );
        return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
    };
    let result = match MtlsManager::from_state(state) {
        Ok(manager) => manager.register_client(user, csr, validity_days).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(issued) => {
            tracing::info!(
                "mTLS enrollment issued a client certificate to {:?} at {client}",
                input.username
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
                        "mTLS enrollment found an existing certificate for {:?} from {client}",
                        input.username
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
