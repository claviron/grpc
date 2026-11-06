use std::sync::Arc;

use claviron::runtime::AppState;
use tonic::{Request, Response, Status};
use tracing::{debug, warn};

pub mod helloworld {
    include!(concat!(env!("OUT_DIR"), "/claviron.helloworld.rs"));
}
use helloworld::greeter_server::{Greeter, GreeterServer};
use helloworld::{HelloReply, HelloRequest};

use crate::server::service::ConnInfo;

pub struct MyGreeter {
    state: AppState,
}

impl MyGreeter {
    fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        req: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        // Extract connection info (mTLS metadata)
        let conn =
            req.extensions().get::<Arc<ConnInfo>>().cloned().ok_or_else(
                || Status::unauthenticated("missing connection info (mTLS)"),
            )?;

        let name = req.get_ref().name.as_str();

        // Require client CN to match the requested name
        match conn.client_cn.as_deref() {
            Some(cn) if cn == name => {
                debug!(
                    peer = ?conn.addr,
                    cn = %cn,
                    "authorized hello"
                );
            }
            Some(cn) => {
                warn!(
                    peer = ?conn.addr,
                    cn = %cn,
                    requested = %name,
                    "forbidden: CN/name mismatch"
                );
                return Err(Status::permission_denied(
                    "forbidden: CN/name mismatch",
                ));
            }
            None => {
                warn!(peer = ?conn.addr, "forbidden: no client CN");
                return Err(Status::permission_denied(
                    "forbidden: no client CN",
                ));
            }
        }

        let name = name.to_string();
        Ok(Response::new(HelloReply {
            message: format!("Hello, {name}! from {}", self.state.name()),
        }))
    }
}

// Expose a ready-to-serve Greeter gRPC service
pub fn create_hello_service(state: AppState) -> GreeterServer<MyGreeter> {
    GreeterServer::new(MyGreeter::new(state))
}
