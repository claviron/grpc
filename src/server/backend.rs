use std::sync::Arc;

use crate::server::head_within;
use claviron::http::ext::{ClientAuthStatus, ConnCtx, ConnStateBuilder};
use claviron::http::policy::HttpPolicy;
use claviron::http::{RouteBody, RouteResponse, ServiceResult, boxed_body};
use claviron::pipeline::extension::{PreparedScope, RouteLayer};
use claviron::pipeline::layers::HostLayer;
use claviron::pipeline::plan::{Backend, HostLayerBuilder};
use claviron::pipeline::{
    BackendContract, BackendHandler, BackendIdentity, BackendReply,
    DispatchCall, DispatchStep, HostContext,
};
use claviron::runtime::AppState;
use http::{Request, Response};
use http_body_util::BodyExt;
use tonic::Status;
use tower::ServiceExt;

use super::service::ConnInfo;
use super::services::ManagementTransport;

#[derive(Clone)]
pub(crate) struct ManagementGrpcHandler {
    routes: tonic::service::Routes,
    auth_guard: AuthGuard,
}

impl ManagementGrpcHandler {
    pub(crate) fn with_routes(
        routes: tonic::service::Routes,
        host: String,
    ) -> Self {
        Self { routes, auth_guard: AuthGuard { host } }
    }
}

impl BackendHandler for ManagementGrpcHandler {
    fn contract(&self) -> BackendContract {
        BackendContract {
            identity: BackendIdentity::None,
            reply: BackendReply::Owner,
        }
    }
}

impl DispatchStep for ManagementGrpcHandler {
    fn call(
        &self,
        mut req: Request<RouteBody>,
        context: Option<HostContext<'_>>,
    ) -> DispatchCall {
        let version = req.version();
        // Framing and TLS belong to the accepting Edge transport. Tonic's
        // service consumes the same request body/trailer contract on H2/H3.
        if !matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3) {
            return DispatchCall::ready(ServiceResult::Handled(
                status_response(
                    Status::failed_precondition(
                        "management gRPC requires HTTP/2 or HTTP/3",
                    ),
                    version,
                ),
            ));
        }

        let conn_ctx = context.map(|context| context.connection);
        let client_cert_present =
            conn_ctx.is_some_and(|ctx| verified_peer(ctx).is_some());
        if let Some(status) =
            self.auth_guard.connection_status(client_cert_present)
        {
            return DispatchCall::ready(ServiceResult::Handled(
                status_response(status, version),
            ));
        }

        let conn_ctx = conn_ctx
            .expect("verified client certificate requires connection context");
        // Prepared once, when the connection was accepted; every request of
        // the connection shares its decision.
        let Some(session) = context
            .and_then(|context| {
                context.conn_state().get::<Arc<super::access::Session>>()
            })
            .cloned()
        else {
            return DispatchCall::ready(ServiceResult::Handled(
                status_response(
                    Status::internal(
                        "no management session was prepared when this connection was accepted",
                    ),
                    version,
                ),
            ));
        };
        let transport = ManagementTransport(conn_ctx.listener.clone());
        req.extensions_mut().insert(Arc::new(conn_info_from_ctx(conn_ctx)));
        req.extensions_mut().insert(transport);

        let routes = self.routes.clone();
        let operation = req.uri().path().to_owned();
        let idle_timeout = context
            .and_then(|context| context.policy())
            .and_then(|policy| policy.responses.idle_timeout);
        let mut req = req.map(|body| {
            let body = body.map_err(|err| Status::internal(err.to_string()));
            tonic::body::Body::new(body)
        });

        DispatchCall::response(Box::pin(async move {
            let serve = async {
                let admitted = session.admit(operation).await?;
                req.extensions_mut().insert(admitted);
                let response = routes
                    .oneshot(req)
                    .await
                    .unwrap_or_else(|err| match err {});
                Ok::<_, Status>(response)
            };
            match head_within(idle_timeout, serve).await {
                Some(Ok(resp)) => Ok(route_response(resp, version)),
                Some(Err(status)) => Ok(status_response(status, version)),
                None => Ok(status_response(
                    Status::deadline_exceeded("gRPC response head timed out"),
                    version,
                )),
            }
        }))
    }
}

impl RouteLayer for ManagementGrpcHandler {
    fn prepare(
        &self,
        layer: &mut HostLayerBuilder,
    ) -> claviron::pipeline::Result<()> {
        Backend::new(self.clone(), HttpPolicy::unlimited()).prepare(layer)
    }

    fn prepare_scoped(
        &self,
        layer: &mut HostLayerBuilder,
        scope: &PreparedScope<'_>,
    ) -> claviron::pipeline::Result<()> {
        Backend::new(self.clone(), scope.policy).prepare(layer)
    }
}

/// The peer whose client certificate the handshake verified.
fn verified_peer(
    connection: &ConnCtx
) -> Option<&Arc<claviron::ssl::peer::PeerIdentity>> {
    let tls = connection.tls.as_ref()?;
    matches!(tls.client_auth, ClientAuthStatus::Verified)
        .then_some(tls.client_cert.as_ref())
        .flatten()
}

/// What a management connection keeps for its requests: the access session
/// of the peer its handshake verified. Runs once, when the connection is
/// accepted; the session resolves its decision on first use and every
/// request of the connection shares it.
pub(crate) fn prepare_connection(
    state: &AppState,
    connection: &ConnCtx,
    conn: &mut ConnStateBuilder,
) {
    if let Some(peer) = verified_peer(connection) {
        conn.insert(Arc::new(super::access::Session::new(
            state.clone(),
            Some(peer.clone()),
        )));
    }
}

#[derive(Clone)]
struct AuthGuard {
    host: String,
}

impl AuthGuard {
    fn connection_status(
        &self,
        client_cert_present: bool,
    ) -> Option<Status> {
        if !client_cert_present {
            return Some(Status::unauthenticated(format!(
                "management gRPC host '{}' requires a TLS client certificate",
                self.host
            )));
        }
        None
    }
}

fn route_response(
    resp: Response<tonic::body::Body>,
    version: http::Version,
) -> RouteResponse {
    let mut response = resp.map(boxed_body);
    // Tonic creates HTTP/2 responses. Keep the accepted transport's version
    // without changing gRPC status, metadata, data frames or trailers.
    *response.version_mut() = version;
    response
}

fn status_response(
    status: Status,
    version: http::Version,
) -> RouteResponse {
    route_response(status.into_http::<tonic::body::Body>(), version)
}

fn conn_info_from_ctx(ctx: &ConnCtx) -> ConnInfo {
    let client_cn =
        ctx.tls.as_ref().and_then(|tls| tls.client_cert.as_ref()).and_then(
            |identity| match &*identity.common_names {
                [name] => Some(name.to_string()),
                _ => None,
            },
        );

    ConnInfo { addr: ctx.remote, client_cn }
}

#[cfg(test)]
#[path = "../../tests/server/backend.rs"]
mod protocol_tests;
