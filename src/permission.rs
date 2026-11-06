//! gRPC-owned permission definitions. Hosts register the definitions they expose
//! and decide their effect through GrpcAccessPolicy; this module grants no access.
use claviron::auth::permission::PermissionDefinition;

pub struct GrpcAccess;

impl PermissionDefinition for GrpcAccess {
    const NAME: &'static str = "grpc.access";
}
