//! Crate-local error type for the grpc server's config / boot path.
//!
//! "owned-error-per-capability-crate" pattern instead of a single
//! monolith error union. Conversions from std::io and
//! claviron::runtime::registry are provided so call sites can use `?`
//! through the registry-resolve paths. `grpc.yaml` itself is read by
//! Congif, whose errors surface through the runtime.

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Convenience wrapper for "I just want to surface a string" — keeps
    /// call sites short and avoids ad-hoc `Error::Other(format!(...))`.
    pub fn msg(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<claviron::runtime::registry::Error> for Error {
    fn from(error: claviron::runtime::registry::Error) -> Self {
        Error::Other(error.to_string())
    }
}

// `claviron::runtime::registry::Error` already provides a blanket
// `From<E: std::error::Error + Send + Sync + 'static>`, so our local
// `Error` (derives `thiserror::Error` → impls std::error::Error) flows
// upward via `?` automatically. No explicit forward impl needed.
