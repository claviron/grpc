use claviron::edge::Host;
use claviron::helpers::de::one_or_many;
use serde::Deserialize;

/// What the management service's configuration file is called in the config
/// directory.
pub const CONFIG_FILE: &str = "grpc.yaml";

/// Selects the resolved Edge vhost keys that carry the management service.
#[derive(Deserialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    #[cfg(any(feature = "users", feature = "authorization"))]
    #[serde(default)]
    pub user_management: Option<super::management::Limits>,
    #[serde(default, deserialize_with = "one_or_many", alias = "vhost")]
    vhosts: Vec<Host>,
}

impl GrpcConfig {
    pub fn vhosts(&self) -> &[Host] {
        &self.vhosts
    }
}

#[cfg(test)]
#[path = "../../tests/ingress_config.rs"]
mod tests;
