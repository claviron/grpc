//! One gRPC admission per connection, with request-local operation identity.
use std::sync::Arc;

use crate::access::{AccessError, GrpcAccessPolicy};
use claviron::auth::AnyAuthenticated;
use claviron::runtime::AppState;
use claviron::ssl::peer::PeerIdentity;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, Shared};
use tonic::Status;

#[derive(Clone)]
pub(crate) struct Admission {
    pub(crate) operation: String,
    pub(crate) actor: Option<AnyAuthenticated>,
}

type Decision = Result<Option<AnyAuthenticated>, Status>;

/// Retained by the accepted connection, never by a global client/certificate map.
pub(crate) struct Session {
    decision: Shared<BoxFuture<'static, Decision>>,
}

impl Session {
    pub(crate) fn new(
        state: AppState,
        peer: Option<Arc<PeerIdentity>>,
    ) -> Self {
        let decision = async move {
            let client_cn = peer.as_ref().and_then(|peer| {
                match &*peer.common_names {
                    [name] => Some(&**name),
                    _ => None,
                }
            });
            let decision: Decision = async {
                let Some(policy) =
                    state.registry_ref().resolve_dyn::<dyn GrpcAccessPolicy>()
                else {
                    return Ok(None);
                };
                let peer = peer.as_deref().ok_or_else(|| {
                    Status::unauthenticated(
                        "verified certificate identity is unavailable",
                    )
                })?;
                let actor =
                    policy.authorize(peer).await.map_err(|error| {
                        let message = error.to_string();
                        match error {
                            AccessError::Unauthenticated => {
                                Status::unauthenticated(message)
                            }
                            AccessError::Forbidden => {
                                Status::permission_denied(message)
                            }
                            AccessError::Unavailable => {
                                Status::unavailable(message)
                            }
                        }
                    })?;
                tracing::info!(
                    service = "grpc",
                    operation = "connect",
                    client_cn,
                    code = ?tonic::Code::Ok,
                    "✅ gRPC access policy accepted a TLS-authenticated peer"
                );
                Ok(actor)
            }
            .await;
            if let Err(error) = &decision {
                match error.code() {
                    tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => {
                        tracing::warn!(
                            service = "grpc",
                            operation = "connect",
                            client_cn,
                            code = ?error.code(),
                            error = %error.message(),
                            "gRPC access policy rejected a TLS-authenticated peer"
                        );
                    }
                    _ => {
                        tracing::error!(
                            service = "grpc",
                            operation = "connect",
                            client_cn,
                            code = ?error.code(),
                            error = %error.message(),
                            "gRPC access policy admission failed"
                        );
                    }
                }
            }
            decision
        }
        .boxed()
        .shared();
        Self { decision }
    }

    pub(crate) async fn admit(
        &self,
        operation: String,
    ) -> Result<Admission, Status> {
        // Concurrent streams share initialization and the terminal result,
        // including a denial. Cancelling one RPC does not restart validation.
        let actor = self.decision.clone().await?;
        Ok(Admission { operation, actor })
    }
}

#[cfg(test)]
#[path = "../../tests/access.rs"]
mod tests;
