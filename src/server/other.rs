use std::sync::Arc;

use claviron::edge::OtherHandler;
use claviron::http::deadline::head_within;
use claviron::http::ext::{ClientAuthStatus, ConnCtx, ConnStateBuilder};
use claviron::http::policy::HttpPolicy;
use claviron::http::{RouteBody, RouteFuture, RouteResponse, boxed_body};
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

impl OtherHandler for ManagementGrpcHandler {
    fn name(&self) -> &'static str {
        "management_grpc"
    }

    fn times_its_head(&self) -> bool {
        true
    }

    fn call(
        &self,
        mut req: Request<RouteBody>,
    ) -> RouteFuture {
        let version = req.version();
        // Framing and TLS belong to the accepting Edge transport. Tonic's
        // service consumes the same request body/trailer contract on H2/H3.
        if !matches!(version, http::Version::HTTP_2 | http::Version::HTTP_3) {
            return Box::pin(async move {
                Ok(status_response(
                    Status::failed_precondition(
                        "management gRPC requires HTTP/2 or HTTP/3",
                    ),
                    version,
                ))
            });
        }

        let conn_ctx = req.extensions().get::<Arc<ConnCtx>>();
        let client_cert_present =
            conn_ctx.is_some_and(|ctx| verified_peer(ctx).is_some());
        let conn_info = conn_ctx.map(|ctx| Arc::new(conn_info_from_ctx(ctx)));
        if let Some(status) =
            self.auth_guard.connection_status(client_cert_present)
        {
            return Box::pin(
                async move { Ok(status_response(status, version)) },
            );
        }

        let conn_ctx = conn_ctx
            .expect("verified client certificate requires connection context");
        // Prepared once, when the connection was accepted; every request of
        // the connection shares its decision.
        let Some(session) =
            conn_ctx.state.get::<Arc<super::access::Session>>().cloned()
        else {
            return Box::pin(async move {
                Ok(status_response(
                    Status::internal(
                        "no management session was prepared when this connection was accepted",
                    ),
                    version,
                ))
            });
        };
        let transport = ManagementTransport(conn_ctx.listener.clone());
        if let Some(conn_info) = conn_info {
            req.extensions_mut().insert(conn_info);
        }
        req.extensions_mut().insert(transport);

        let routes = self.routes.clone();
        let operation = req.uri().path().to_owned();
        let head_timeout = req
            .extensions()
            .get::<HttpPolicy>()
            .and_then(|policy| policy.requests.head_timeout);
        let mut req = req.map(|body| {
            let body = body.map_err(|err| Status::internal(err.to_string()));
            tonic::body::Body::new(body)
        });

        Box::pin(async move {
            let serve = async {
                let admitted = session.admit(operation).await?;
                req.extensions_mut().insert(admitted);
                let response = routes
                    .oneshot(req)
                    .await
                    .unwrap_or_else(|err| match err {});
                Ok::<_, Status>(response)
            };
            match head_within(head_timeout, serve).await {
                Some(Ok(resp)) => Ok(route_response(resp, version)),
                Some(Err(status)) => Ok(status_response(status, version)),
                None => Ok(status_response(
                    Status::deadline_exceeded("gRPC response head timed out"),
                    version,
                )),
            }
        })
    }
}

/// The peer whose client certificate the handshake verified.
fn verified_peer(
    connection: &ConnCtx
) -> Option<Arc<claviron::ssl::peer::PeerIdentity>> {
    let tls = connection.tls.as_ref()?;
    matches!(tls.client_auth, ClientAuthStatus::Verified)
        .then(|| tls.client_cert.clone())
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
            Some(peer),
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
#[path = "../../tests/server/bypass_protocol.rs"]
mod protocol_tests;
