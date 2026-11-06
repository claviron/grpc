//! Application-authenticated enrollment for device-owned mTLS keys.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use claviron::auth::AnyAuthenticated;
use claviron::edge::pipeline::{HostHandler, HostHandlerFuture, HostRequest};
use claviron::edge::{
    Host, HostConfig, Routable, RouteProtocol, VhostResolver,
};
use claviron::http::deadline::head_within;
use claviron::http::policy::HttpPolicy;
use claviron::http::{
    RouteBody, RouteResponse, ServiceResult, bytes_body, empty_body,
};
use claviron::runtime::registry::{Bootable, Component, priority};
use claviron::runtime::{AppState, registry};
use claviron::ssl::SubjectUri;
use claviron::tls::{CertResolver, CertificateProvider};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tonic::Code;

use super::mtls::{ManagedSigner, MtlsManager};
use crate::access::AccessError;
use crate::server::config::GrpcConfig;
use crate::server::provider::GrpcServiceProvider;

pub const PATH: &str = "/.well-known/claviron/grpc-registration";

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
pub trait RegistrationGuard: Send + Sync + 'static {
    async fn authorize(
        &self,
        username: &str,
        password: &str,
    ) -> Result<GrpcUser, AccessError>;
}

pub fn register_guard<G: RegistrationGuard>(
    state: &AppState,
    guard: Arc<G>,
) -> registry::Result<()> {
    let registry = state.registry_ref();
    registry.insert(guard)?;
    registry.bind_dyn::<dyn RegistrationGuard, G>(|guard| guard)?;
    Ok(())
}

pub(crate) fn register_routes(
    state: &AppState,
    grpc: Arc<GrpcServiceProvider>,
) -> registry::Result<()> {
    claviron::edge::register_routable(
        state,
        Arc::new(RegistrationRoutes { grpc }),
    )
}

struct RegistrationRoutes {
    grpc: Arc<GrpcServiceProvider>,
}

impl Component<AppState> for RegistrationRoutes {
    type Deps = (Arc<CertificateProvider>,);

    fn name(&self) -> &'static str {
        "GrpcRegistration"
    }

    fn boot_priority(&self) -> Option<u8> {
        Some(priority::NORMAL)
    }

    fn as_bootable(&self) -> Option<&dyn Bootable<AppState, Self::Deps>> {
        Some(self)
    }
}

#[async_trait]
impl Bootable<AppState, (Arc<CertificateProvider>,)> for RegistrationRoutes {
    async fn boot(
        &self,
        _deps: (Arc<CertificateProvider>,),
        state: &AppState,
    ) -> registry::Result<()> {
        if state.is_master() || self.grpc.config().registration.is_empty() {
            return Ok(());
        }
        let signer =
            MtlsManager::prepare_registration_signer(state).await.map_err(
                |error| registry::Error::msg(error.message().to_owned()),
            )?;
        state.registry_ref().insert(signer)?;
        Ok(())
    }
}

impl Routable for RegistrationRoutes {
    fn match_protocol(
        &self,
        protocol: RouteProtocol,
    ) -> bool {
        protocol == RouteProtocol::Https
    }

    fn match_host(
        &self,
        key: &Host,
        _host: &HostConfig,
    ) -> bool {
        self.grpc.config().registration.contains(key)
    }

    fn application(
        self: Arc<Self>,
        state: &AppState,
        _key: &Host,
        host: Arc<HostConfig>,
    ) -> registry::Result<Option<Arc<dyn HostHandler>>> {
        if host.tls_policy().client_auth.is_required() {
            return Err(registry::Error::msg(
                "gRPC registration requires TLS without mandatory client authentication",
            ));
        }
        if !state.is_master()
            && state.registry_ref().resolve::<ManagedSigner>().is_none()
        {
            return Err(registry::Error::msg(
                "gRPC registration signer must be prepared at boot",
            ));
        }
        let guard = state
            .registry_ref()
            .resolve_dyn::<dyn RegistrationGuard>()
            .ok_or_else(|| {
                registry::Error::msg(
                    "gRPC registration requires a RegistrationGuard",
                )
            })?;
        let config = self.grpc.config();
        let validity_days =
            config.registration_validity_days.ok_or_else(|| {
                registry::Error::msg(
                    "registration_validity_days is required for registration",
                )
            })?;
        Ok(Some(Arc::new(RegistrationHandler {
            state: state.clone(),
            guard,
            config,
            validity_days,
        })))
    }
}

struct RegistrationHandler {
    state: AppState,
    guard: Arc<dyn RegistrationGuard>,
    config: Arc<GrpcConfig>,
    validity_days: NonZeroU32,
}

impl HostHandler for RegistrationHandler {
    fn call(
        &self,
        request: HostRequest,
    ) -> HostHandlerFuture {
        if request.head().uri.path() != PATH {
            return Box::pin(std::future::ready(ServiceResult::Unhandled(
                request,
            )));
        }
        let state = self.state.clone();
        let guard = self.guard.clone();
        let config = self.config.clone();
        let validity_days = self.validity_days;
        let timeout = request
            .head()
            .extensions
            .get::<HttpPolicy>()
            .and_then(|policy| policy.requests.head_timeout);
        Box::pin(async move {
            let response = head_within(
                timeout,
                enroll(
                    request.into_request(),
                    &state,
                    guard.as_ref(),
                    validity_days,
                    config.vhosts(),
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
struct RegistrationResponse {
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
    guard: &dyn RegistrationGuard,
    validity_days: NonZeroU32,
    management_hosts: &[Host],
) -> RouteResponse {
    if request.method() == Method::HEAD {
        let status = if management_address(state, management_hosts).is_some() {
            StatusCode::NO_CONTENT
        } else {
            tracing::warn!(
                "gRPC registration probe could not find a serving management TLS/H2 address"
            );
            StatusCode::SERVICE_UNAVAILABLE
        };
        let mut response = reply(status, empty_body());
        // Identifies the enrollment probe protocol to clients.
        response.headers_mut().insert(
            "claviron-registration",
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
    if request.headers().contains_key(header::ORIGIN) {
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
            return reply(StatusCode::UNAUTHORIZED, empty_body());
        }
        Err(AccessError::Forbidden) => {
            return reply(StatusCode::FORBIDDEN, empty_body());
        }
        Err(AccessError::Unavailable) => {
            return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
        }
    };
    let Some(management_address) = management_address(state, management_hosts)
    else {
        tracing::warn!(
            "gRPC registration could not find a serving management TLS/H2 address"
        );
        return reply(StatusCode::SERVICE_UNAVAILABLE, empty_body());
    };
    let result = match MtlsManager::from_state(state) {
        Ok(manager) => manager.register_client(user, csr, validity_days).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(issued) => {
            let Ok(body) = serde_json::to_vec(&RegistrationResponse {
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
                Code::AlreadyExists => StatusCode::CONFLICT,
                Code::InvalidArgument => StatusCode::BAD_REQUEST,
                Code::FailedPrecondition => {
                    tracing::warn!(
                        reason = error.message(),
                        "gRPC registration is unavailable"
                    );
                    StatusCode::SERVICE_UNAVAILABLE
                }
                _ => {
                    tracing::error!(code = ?error.code(), "gRPC registration failed");
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
