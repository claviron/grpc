//! Application-owned admission for an authenticated gRPC client connection.
use async_trait::async_trait;
use claviron::auth::AnyAuthenticated;
use claviron::ssl::peer::PeerIdentity;

/// Safe admission failures; infrastructure diagnostics remain application-owned.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccessError {
    #[error("peer identity is not accepted")]
    Unauthenticated,
    #[error("access is forbidden")]
    Forbidden,
    #[error("access policy is unavailable")]
    Unavailable,
}

/// Optional gRPC admission after mTLS validation, evaluated once per connection.
/// Register through the application's registry. A denial never falls back to
/// certificate-only admission. `Ok(None)` admits the peer without a user;
/// `Ok(Some(actor))` also binds an application identity for management handlers.
/// Managers retain their own current resource and operation authorization.
#[async_trait]
pub trait GrpcAccessPolicy: Send + Sync + 'static {
    async fn authorize(
        &self,
        peer: &PeerIdentity,
    ) -> Result<Option<AnyAuthenticated>, AccessError>;
}
