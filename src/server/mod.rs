pub(crate) mod access;
#[cfg(feature = "acme")]
pub(crate) mod acme;
pub(crate) mod aliases;
pub(crate) mod applications;
pub(crate) mod backend;
pub(crate) mod config;
pub(crate) mod control;
#[cfg(feature = "dns")]
pub(crate) mod dns;
#[cfg(feature = "domains")]
pub(crate) mod domains;
pub mod greeter;
pub(crate) mod linked;
pub mod management;
pub mod provider;
pub mod service;
pub(crate) mod services;
#[cfg(feature = "tasks")]
pub(crate) mod tasks;
#[cfg(feature = "workers")]
pub(crate) mod workers;

#[cfg(feature = "mtls")]
pub(crate) mod mtls;

#[cfg(feature = "certificates")]
pub(crate) mod certificates;

/// A reply that stalls before its head is a gap in that reply, bounded by the
/// same `responses.idle_timeout` as the gaps after it. Without one it waits.
pub(crate) async fn head_within<F: std::future::Future>(
    limit: Option<std::time::Duration>,
    head: F,
) -> Option<F::Output> {
    match limit {
        Some(limit) => tokio::time::timeout(limit, head).await.ok(),
        None => Some(head.await),
    }
}
