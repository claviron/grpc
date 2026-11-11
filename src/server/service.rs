use std::net::SocketAddr;

use claviron::runtime::AppState;
use claviron::runtime::registry::Error;
use tonic_reflection::server::Builder as ReflBuilder;

#[cfg(feature = "acme")]
use crate::server::acme::create_acme_service;
use crate::server::aliases::create_hosting_service;
use crate::server::applications::create_application_manager;
use crate::server::control::create_server_service;
use crate::server::greeter::create_hello_service;
use crate::server::services::create_service_manager;
#[cfg(feature = "tasks")]
use crate::server::tasks::create_task_service;
#[cfg(feature = "workers")]
use crate::server::workers::create_worker_service;

const DESCRIPTORS: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/descriptors.bin"));

pub(crate) fn create_management_routes(
    state: AppState
) -> claviron::runtime::registry::Result<tonic::service::Routes> {
    let hello_service = create_hello_service(state.clone());

    let hosting_service = create_hosting_service(state.clone())
        .map_err(|s| Error::msg(s.to_string()))?;
    let server_service =
        create_server_service(state.clone(), management_capabilities());
    let service_manager = create_service_manager(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    let application_manager = create_application_manager(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;
    #[cfg(feature = "acme")]
    let acme_service = create_acme_service(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    #[cfg(feature = "tasks")]
    let task_service = create_task_service(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    #[cfg(feature = "workers")]
    let worker_service = create_worker_service(state.clone())
        .map_err(|status| Error::msg(status.to_string()))?;

    let reflection_service = ReflBuilder::configure()
        .register_encoded_file_descriptor_set(DESCRIPTORS)
        .build_v1()
        .expect("reflection");

    let routes = tonic::service::Routes::new(hello_service)
        .add_service(hosting_service)
        .add_service(server_service)
        .add_service(service_manager)
        .add_service(application_manager);

    #[cfg(feature = "acme")]
    let routes = routes.add_service(acme_service);

    #[cfg(any(feature = "users", feature = "authorization"))]
    let routes = routes
        .add_service(super::management::users::create_service(state.clone()));

    #[cfg(feature = "tasks")]
    let routes = routes.add_service(task_service);

    #[cfg(feature = "workers")]
    let routes = routes.add_service(worker_service);

    #[cfg(feature = "mtls")]
    let routes = routes
        .add_service(crate::server::mtls::create_mtls_service(state.clone()));

    #[cfg(feature = "certificates")]
    let routes = routes.add_service(
        crate::server::certificates::create_certificate_transfer(state.clone()),
    );

    let routes = routes.add_service(reflection_service);

    #[cfg(feature = "dns")]
    let routes = routes
        .add_service(crate::server::dns::create_dns_service(state.clone()));

    #[cfg(feature = "domains")]
    let routes = routes.add_service(
        crate::server::domains::create_domain_service(state.clone()),
    );

    #[cfg(feature = "metrics")]
    let routes = with_metrics_route(routes, state);

    Ok(routes.prepare())
}

// These declarations mirror the routes installed below; they describe this
// endpoint, not whether every backing provider is currently available.
fn management_capabilities() -> Vec<String> {
    let names = vec![
        "server",
        "services",
        "applications",
        "hosting",
        "reflection",
        #[cfg(feature = "users")]
        "users",
        #[cfg(feature = "authorization")]
        "authorization",
        #[cfg(feature = "tasks")]
        "tasks",
        #[cfg(feature = "workers")]
        "workers",
        #[cfg(feature = "acme")]
        "acme",
        #[cfg(feature = "mtls")]
        "mtls",
        #[cfg(feature = "certificates")]
        "certificates",
        #[cfg(feature = "dns")]
        "dns",
        #[cfg(feature = "domains")]
        "domains",
        #[cfg(feature = "metrics")]
        "metrics",
    ];
    names.into_iter().map(String::from).collect()
}

#[cfg(feature = "metrics")]
fn with_metrics_route(
    routes: tonic::service::Routes,
    state: AppState,
) -> tonic::service::Routes {
    let metrics = claviron::http::metrics::routes(&state).with_state(state);
    routes.into_axum_router().merge(metrics).into()
}

#[derive(Debug)]
pub(crate) struct ConnInfo {
    pub(crate) addr: SocketAddr,
    pub(crate) client_cn: Option<String>,
}
