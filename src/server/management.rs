//! Server-side management operations and enrollment.

#[cfg(feature = "certificate-manager")]
pub mod certificates;
#[cfg(feature = "mtls-manager")]
pub mod mtls;
#[cfg(feature = "registration")]
pub mod registration;
#[cfg(any(feature = "users", feature = "authorization"))]
pub(crate) mod users;

#[cfg(any(feature = "users", feature = "authorization"))]
pub use users::Limits;
