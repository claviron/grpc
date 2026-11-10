use super::*;
use crate::server::greeter::helloworld::{
    HelloReply, HelloRequest,
    greeter_server::{Greeter, GreeterServer},
};
use claviron::http::ext::{ClientAuthStatus, RequestArrival, TlsInfo};
use claviron::pipeline::plan::{HostExecution, HostPipelineBuilder};
use prost::Message;

struct Echo;

#[tonic::async_trait]
impl Greeter for Echo {
    async fn say_hello(
        &self,
        request: tonic::Request<HelloRequest>,
    ) -> Result<tonic::Response<HelloReply>, Status> {
        let owner =
            &request.extensions().get::<ManagementTransport>().unwrap().0;
        let identity = request.extensions().get::<Arc<ConnInfo>>().unwrap();
        assert_eq!(identity.client_cn.as_deref(), Some("operator"));
        Ok(tonic::Response::new(HelloReply {
            message: format!("{owner}:{}", request.get_ref().name),
        }))
    }
}

struct Input {
    request: Request<RouteBody>,
    connection: Arc<ConnCtx>,
}

struct TestHost(HostExecution);

impl TestHost {
    async fn call(
        &self,
        input: Input,
    ) -> Result<RouteResponse, std::convert::Infallible> {
        assert!(input.request.extensions().get::<Arc<ConnCtx>>().is_none());
        assert!(input.request.extensions().get::<HttpPolicy>().is_none());
        self.0
            .handle_in(
                input.request,
                Some(HostContext::new(
                    &input.connection,
                    RequestArrival::Established,
                )),
            )
            .await
    }
}

fn handler() -> TestHost {
    handler_with_policy(HttpPolicy::unlimited())
}

fn handler_with_policy(policy: HttpPolicy) -> TestHost {
    let owner = ManagementGrpcHandler::with_routes(
        tonic::service::Routes::new(GreeterServer::new(Echo)).prepare(),
        "management.example.test".to_owned(),
    );
    prepared(owner, policy)
}

fn prepared(
    owner: ManagementGrpcHandler,
    policy: HttpPolicy,
) -> TestHost {
    let config = Arc::new(
        serde_yaml::from_str::<claviron::pipeline::Site>(
            "root: .\ntry_files: false",
        )
        .unwrap(),
    );
    let scope =
        PreparedScope { config: &config, policy, accepts_applications: true };
    let mut layer = HostLayerBuilder::default();
    owner.prepare_scoped(&mut layer, &scope).unwrap();
    TestHost(HostPipelineBuilder::<()>::from(layer).build().into_execution())
}

/// A request on a connection accepted for a state with nothing registered.
fn request(
    version: http::Version,
    verified: bool,
) -> Input {
    let state =
        claviron::runtime::AppState::standalone("grpc-admission-test", ".");
    accepted(&state, unaccepted(version, verified))
}

/// Stand in for the edge: prepare the request's connection as its acceptance
/// under `state` would, so its requests find what the handler reads.
fn accepted(
    state: &claviron::runtime::AppState,
    mut input: Input,
) -> Input {
    let connection = Arc::get_mut(&mut input.connection).unwrap();
    let mut conn = claviron::http::ext::ConnStateBuilder::default();
    prepare_connection(state, connection, &mut conn);
    connection.state = conn.build();
    input
}

fn unaccepted(
    version: http::Version,
    verified: bool,
) -> Input {
    let proto = if version == http::Version::HTTP_3 {
        claviron::tls::Proto::H3
    } else {
        claviron::tls::Proto::H2
    };
    let payload = HelloRequest { name: "hello".to_owned() }.encode_to_vec();
    let mut frame = vec![0]; // gRPC's uncompressed message flag.
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    let request = Request::builder().method("POST").version(version)
        .uri("https://management.example.test/claviron.helloworld.Greeter/SayHello")
        .header("content-type", "application/grpc").header("te", "trailers")
        .body(claviron::http::bytes_body(frame.into())).unwrap();
    let connection = Arc::new(ConnCtx {
        transport: claviron::http::listener::ListenerTransport::Tcp,
        state: Default::default(),
        listener: "management".parse().unwrap(),
        proto: Some(proto),
        remote: "192.0.2.1:12345".parse().unwrap(),
        local_ip: "192.0.2.2".parse().unwrap(),
        local_port: 443,
        real_ip: None,
        country_code: None,
        tls: Some(TlsInfo {
            protocol_version: None,
            cipher_suite: None,
            client_auth: if verified {
                ClientAuthStatus::Verified
            } else {
                ClientAuthStatus::NotProvided
            },
            client_cert: Some(Arc::new(claviron::ssl::peer::PeerIdentity {
                certificate: Arc::from([]),
                subject_dn: "CN=operator".into(),
                issuer_dn: "CN=example CA".into(),
                common_names: Box::new(["operator".into()]),
                subject_uris: Box::new(["urn:example:subject:one".into()]),
            })),
        }),
    });
    Input { request, connection }
}

#[tokio::test]
async fn grpc_h2_h3_dispatch_preserves_messages_identity_and_status_trailers() {
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let response = handler().call(request(version, true)).await.unwrap();
        assert_eq!(response.version(), version);
        assert_eq!(response.headers()["content-type"], "application/grpc");
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["grpc-status"], "0");
        let bytes = body.to_bytes();
        let reply = HelloReply::decode(&bytes[5..]).unwrap();
        assert_eq!(reply.message, "management:hello");
    }
}

#[tokio::test]
async fn grpc_h3_requires_verified_mtls_and_http1_remains_rejected() {
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let response = handler().call(request(version, false)).await.unwrap();
        assert_eq!(response.version(), version);
        assert_eq!(response.headers()["grpc-status"], "16");
    }
    let mut missing_context = request(http::Version::HTTP_3, true);
    missing_context.request.extensions_mut().insert(missing_context.connection);
    let response = handler().0.handle(missing_context.request).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "16");
    let response =
        handler().call(unaccepted(http::Version::HTTP_2, true)).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "13");
    let response =
        handler().call(request(http::Version::HTTP_11, true)).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "9");
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn metrics_uses_the_same_native_connection_admission() {
    let state = AppState::standalone("grpc-metrics-test", ".");
    state
        .registry_ref()
        .insert(Arc::new(claviron::runtime::metrics::MetricsProvider::new()))
        .unwrap();
    let metrics =
        claviron::http::metrics::routes(&state).with_state(state.clone());
    let routes = tonic::service::Routes::new(GreeterServer::new(Echo))
        .into_axum_router()
        .merge(metrics)
        .into();
    let owner = prepared(
        ManagementGrpcHandler::with_routes(
            routes,
            "management.example.test".into(),
        ),
        HttpPolicy::unlimited(),
    );
    let input = |version, verified| {
        let mut input = unaccepted(version, verified);
        *input.request.method_mut() = http::Method::GET;
        *input.request.uri_mut() = "/metrics".parse().unwrap();
        *input.request.body_mut() = claviron::http::empty_body();
        accepted(&state, input)
    };
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let response = owner.call(input(version, true)).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; version=0.0.4"
        );
        let response = owner.call(input(version, false)).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "16");
    }
    let policy = Arc::new(AccessCheck {
        allow: std::sync::atomic::AtomicBool::new(false),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    state.registry_ref().insert(policy).unwrap();
    state
        .registry_ref()
        .bind_dyn::<dyn crate::access::GrpcAccessPolicy, AccessCheck>(
            |policy| policy,
        )
        .unwrap();
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let response = owner.call(input(version, true)).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "7");
    }
}

#[tokio::test]
async fn grpc_response_head_uses_the_effective_http_deadline() {
    struct PendingAdmission;

    #[async_trait::async_trait]
    impl crate::access::GrpcAccessPolicy for PendingAdmission {
        async fn authorize(
            &self,
            _peer: &claviron::ssl::peer::PeerIdentity,
        ) -> Result<
            Option<claviron::auth::AnyAuthenticated>,
            crate::access::AccessError,
        > {
            std::future::pending().await
        }
    }

    let state = AppState::standalone("grpc-deadline-test", ".");
    state.registry_ref().insert(Arc::new(PendingAdmission)).unwrap();
    state
        .registry_ref()
        .bind_dyn::<dyn crate::access::GrpcAccessPolicy, PendingAdmission>(
            |value| value,
        )
        .unwrap();
    let request = accepted(&state, unaccepted(http::Version::HTTP_2, true));
    let mut policy = HttpPolicy::unlimited();
    policy.responses.idle_timeout = Some(std::time::Duration::ZERO);
    let response = handler_with_policy(policy).call(request).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "4");
}

struct AccessCheck {
    allow: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl crate::access::GrpcAccessPolicy for AccessCheck {
    async fn authorize(
        &self,
        peer: &claviron::ssl::peer::PeerIdentity,
    ) -> Result<
        Option<claviron::auth::AnyAuthenticated>,
        crate::access::AccessError,
    > {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            *peer.subject_uris,
            ["urn:example:subject:one"].map(Box::<str>::from)
        );
        if self.allow.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(None)
        } else {
            Err(crate::access::AccessError::Forbidden)
        }
    }
}
#[tokio::test]
async fn grpc_access_policy_is_shared_by_h2_h3_connection_and_resets_on_reconnect()
 {
    use std::sync::atomic::{AtomicBool, Ordering};
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let state = AppState::standalone("grpc-access-test", ".");
        let policy = Arc::new(AccessCheck {
            allow: AtomicBool::new(true),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        state.registry_ref().insert(policy.clone()).unwrap();
        state
            .registry_ref()
            .bind_dyn::<dyn crate::access::GrpcAccessPolicy, AccessCheck>(
                |value| value,
            )
            .unwrap();
        let handler = handler();
        let first = accepted(&state, unaccepted(version, true));
        let connection = first.connection.clone();
        let response = handler.call(first).await.unwrap();
        assert!(!response.headers().contains_key("grpc-status"));
        policy.allow.store(false, Ordering::SeqCst);
        let mut same_connection = request(version, true);
        same_connection.connection = connection;
        let response = handler.call(same_connection).await.unwrap();
        assert!(!response.headers().contains_key("grpc-status"));
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);

        let denied = accepted(&state, unaccepted(version, true));
        let denied_connection = denied.connection.clone();
        let response = handler.call(denied).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "7");
        policy.allow.store(true, Ordering::SeqCst);
        let mut still_denied = request(version, true);
        still_denied.connection = denied_connection;
        still_denied
            .request
            .headers_mut()
            .insert("x-access-target", "allowed".parse().unwrap());
        let response = handler.call(still_denied).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "7");
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
        let response = handler.call(request(version, false)).await.unwrap();
        assert_eq!(response.headers()["grpc-status"], "16");
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
    }
}
