//! Server-side management operations and enrollment.

#[cfg(feature = "certificate-manager")]
pub mod certificates;
#[cfg(feature = "enroll")]
pub mod enroll;
#[cfg(feature = "mtls-manager")]
pub mod mtls;
#[cfg(any(feature = "users", feature = "authorization"))]
pub(crate) mod users;

#[cfg(any(feature = "users", feature = "authorization"))]
pub use users::Limits;
