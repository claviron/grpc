use super::*;
use async_trait::async_trait;
use std::any::Any;
use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tonic::Code;

struct Actor;
impl claviron::auth::Authenticated for Actor {
    fn auth_subject(&self) -> Cow<'_, str> {
        "bound-subject".into()
    }
    fn auth_identifier(&self) -> &str {
        "display-name"
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
struct Policy {
    calls: AtomicUsize,
    result: Mutex<Option<PolicyResult>>,
}
type PolicyResult = Result<Option<AnyAuthenticated>, AccessError>;
#[async_trait]
impl GrpcAccessPolicy for Policy {
    async fn authorize(
        &self,
        peer: &PeerIdentity,
    ) -> Result<Option<AnyAuthenticated>, AccessError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(*peer.common_names, ["operator"].map(Box::<str>::from));
        self.result.lock().unwrap().take().expect("one admission per session")
    }
}
fn peer() -> PeerIdentity {
    PeerIdentity {
        certificate: Arc::from([]),
        subject_dn: "CN=operator".into(),
        issuer_dn: "CN=example CA".into(),
        common_names: Box::new(["operator".into()]),
        subject_uris: Box::new([]),
    }
}
fn bind(
    state: &AppState,
    result: Result<Option<AnyAuthenticated>, AccessError>,
) -> Arc<Policy> {
    let policy = Arc::new(Policy {
        calls: AtomicUsize::new(0),
        result: Mutex::new(Some(result)),
    });
    state.registry_ref().insert(policy.clone()).unwrap();
    state
        .registry_ref()
        .bind_dyn::<dyn GrpcAccessPolicy, Policy>(|value| value)
        .unwrap();
    policy
}
fn session(
    state: AppState,
    peer: Option<Arc<PeerIdentity>>,
) -> Session {
    Session::new(state, peer)
}
#[tokio::test]
async fn access_no_policy_preserves_peer_only_admission_without_a_user_model() {
    let state = AppState::standalone("access-test", ".");
    let session = session(state, None);
    let admission = session.admit("inspect".into()).await.unwrap();
    assert!(admission.actor.is_none());
}
#[tokio::test]
async fn access_session_shares_one_actor_across_concurrent_operations() {
    let state = AppState::standalone("access-test", ".");
    let policy = bind(&state, Ok(Some(Arc::new(Actor))));
    let session = session(state, Some(Arc::new(peer())));
    let (first, second) = tokio::join!(
        session.admit("inspect".into()),
        session.admit("update".into()),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.operation, "inspect");
    assert_eq!(second.operation, "update");
    assert!(Arc::ptr_eq(
        first.actor.as_ref().unwrap(),
        second.actor.as_ref().unwrap()
    ));
    assert_eq!(first.actor.unwrap().auth_subject(), "bound-subject");
    assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn access_session_retains_denials_without_rechecking_or_falling_back() {
    for (error, code) in [
        (AccessError::Forbidden, Code::PermissionDenied),
        (AccessError::Unauthenticated, Code::Unauthenticated),
        (AccessError::Unavailable, Code::Unavailable),
    ] {
        let state = AppState::standalone("access-test", ".");
        let policy = bind(&state, Err(error));
        let session = session(state, Some(Arc::new(peer())));
        for operation in ["inspect", "update"] {
            let Err(status) = session.admit(operation.into()).await else {
                panic!("policy error must not fall back")
            };
            assert_eq!(status.code(), code);
        }
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn access_session_requires_peer_facts_when_policy_is_registered() {
    let state = AppState::standalone("access-test", ".");
    let policy = bind(&state, Ok(None));
    let session = session(state, None);
    let Err(status) = session.admit("inspect".into()).await else {
        panic!("missing identity must fail")
    };
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(policy.calls.load(Ordering::SeqCst), 0);
}
