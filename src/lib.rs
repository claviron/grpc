#[cfg(feature = "server")]
pub mod access;

#[cfg(feature = "server")]
pub mod permission;

#[cfg(feature = "registration")]
pub use server::management::registration;

#[cfg(feature = "mtls-manager")]
pub use server::management::mtls as mtls_manager;

#[cfg(feature = "certificate-manager")]
pub use server::management::certificates as certificate_manager;

#[cfg(feature = "server")]
pub mod error;
#[cfg(feature = "server")]
pub mod server;

pub mod proto {
    pub mod management {
        tonic::include_proto!("claviron.management");
    }
    pub mod users {
        tonic::include_proto!("claviron.users");
    }
    pub mod certificates {
        tonic::include_proto!("claviron.certificates");
    }
    pub mod mtls {
        include!(concat!(env!("OUT_DIR"), "/claviron.mtls.rs"));
    }
    pub mod dns {
        include!(concat!(env!("OUT_DIR"), "/claviron.dns.rs"));
    }
    pub mod domains {
        include!(concat!(env!("OUT_DIR"), "/claviron.domains.rs"));
    }
    pub mod acme {
        include!(concat!(env!("OUT_DIR"), "/claviron.acme.rs"));
    }
    pub mod aliases {
        include!(concat!(env!("OUT_DIR"), "/claviron.aliases.rs"));
    }
    pub mod applications {
        include!(concat!(env!("OUT_DIR"), "/claviron.applications.rs"));
    }
    pub mod helloworld {
        include!(concat!(env!("OUT_DIR"), "/claviron.helloworld.rs"));
    }
    pub mod server {
        include!(concat!(env!("OUT_DIR"), "/claviron.server.rs"));
    }
    pub mod services {
        include!(concat!(env!("OUT_DIR"), "/claviron.services.rs"));
    }
    pub mod tasks {
        include!(concat!(env!("OUT_DIR"), "/claviron.tasks.rs"));
    }
    pub mod workers {
        include!(concat!(env!("OUT_DIR"), "/claviron.workers.rs"));
    }
}

#[cfg(test)]
#[path = "../tests/users_protocol.rs"]
mod users_protocol_tests;

#[cfg(feature = "server")]
pub fn register(
    state: &claviron::runtime::AppState
) -> claviron::runtime::registry::Result<()> {
    use claviron::runtime::Register;
    server::provider::GrpcServiceProvider::register(state)
}
