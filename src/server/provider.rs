use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use claviron::edge::{
    Host, HostBindingProvider, HostConfig, OtherService, RouteBinding,
};
use claviron::runtime::congif::{
    self, ConfigFile, ConfigObserver, Configurable,
};
use claviron::runtime::registry::{
    Component, Error, Reloadable, Result, priority,
};
use claviron::runtime::{AppState, Register};

use super::config::{CONFIG_FILE, GrpcConfig};
use super::other::ManagementGrpcHandler;

/// The owner of `grpc.yaml`: binds the management service to the vhost keys the
/// file names. Registered in every process; without the file the service
/// matches no host until a reload or a source change declares some.
pub struct GrpcServiceProvider {
    config_path: PathBuf,
    config: RwLock<Arc<GrpcConfig>>,
    routes: RwLock<Option<tonic::service::Routes>>,
}

impl GrpcServiceProvider {
    pub fn new(state: &AppState) -> Self {
        Self {
            config_path: state.config_dir().join(CONFIG_FILE),
            config: RwLock::new(Arc::new(GrpcConfig::default())),
            routes: RwLock::new(None),
        }
    }

    fn apply(
        &self,
        cfg: &GrpcConfig,
    ) {
        *self.config.write().expect("grpc config lock poisoned") =
            Arc::new(cfg.clone());
    }

    pub(crate) fn config(&self) -> Arc<GrpcConfig> {
        self.config.read().expect("grpc config lock poisoned").clone()
    }

    pub(crate) fn handler(
        &self,
        state: AppState,
        host: String,
    ) -> Result<ManagementGrpcHandler> {
        let mut routes =
            self.routes.write().expect("grpc routes lock poisoned");
        if routes.is_none() {
            *routes =
                Some(super::service::create_management_routes(state.clone())?);
        }
        let routes = routes.as_ref().expect("prepared routes");
        Ok(ManagementGrpcHandler::with_routes(routes.clone(), host))
    }
}

impl Register<AppState> for GrpcServiceProvider {
    fn register(state: &AppState) -> Result<()> {
        state.bind_config_environment::<Self>()?;
        let provider = Arc::new(Self::new(state));
        claviron::edge::register_host_binding_provider(
            state,
            provider.clone(),
        )?;
        // A management connection's access session is prepared once, when the
        // connection is accepted, and read by each of its requests.
        let (hosts, accepting) = (provider.clone(), state.clone());
        claviron::edge::register_accept_layer(
            state,
            move |host, _, _| hosts.config().vhosts().contains(host),
            move |accepted: &claviron::edge::Accepted<'_>,
                  conn: &mut claviron::http::ext::ConnStateBuilder| {
                super::other::prepare_connection(
                    &accepting,
                    accepted.connection,
                    conn,
                )
            },
        )?;
        #[cfg(feature = "registration")]
        super::management::registration::register_routes(state, provider)?;
        Ok(())
    }
}

#[async_trait]
impl Component<AppState> for GrpcServiceProvider {
    type Deps = ();

    fn name(&self) -> &'static str {
        "GrpcServiceProvider"
    }

    fn as_reloadable(&self) -> Option<&dyn Reloadable<AppState>> {
        Some(self)
    }

    fn as_configurable(&self) -> Option<&dyn congif::ConfigRegistration> {
        Some(self)
    }
}

#[async_trait]
impl Configurable for GrpcServiceProvider {
    type Config = GrpcConfig;

    fn source(&self) -> ConfigFile {
        ConfigFile::yaml(&self.config_path)
    }

    fn absent_source(&self) -> Option<GrpcConfig> {
        Some(GrpcConfig::default())
    }

    fn as_config_observer(
        &self
    ) -> Option<&dyn ConfigObserver<Config = Self::Config>> {
        Some(self)
    }

    async fn configure(
        &self,
        config: &GrpcConfig,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }

    #[cfg(feature = "registration")]
    fn validate_config(
        &self,
        config: &GrpcConfig,
    ) -> congif::Result<()> {
        if config.registration.iter().any(|host| config.vhosts().contains(host))
        {
            return Err(congif::Error::invalid(
                "gRPC registration and management require different vhosts",
            ));
        }
        if !config.registration.is_empty()
            && config.registration_validity_days.is_none()
        {
            return Err(congif::Error::invalid(
                "registration_validity_days is required for registration",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl ConfigObserver for GrpcServiceProvider {
    async fn config_changed(
        &self,
        config: &GrpcConfig,
    ) -> congif::Result<()> {
        self.apply(config);
        Ok(())
    }
}

#[async_trait]
impl Reloadable<AppState> for GrpcServiceProvider {
    fn priority(&self) -> Option<u8> {
        Some(priority::NORMAL)
    }

    async fn reload(
        &self,
        state: &AppState,
    ) -> Result<()> {
        let config = state.config_reader().snapshot::<Self>()?;
        self.apply(&config);
        Ok(())
    }
}

impl HostBindingProvider for GrpcServiceProvider {
    fn match_host(
        &self,
        key: &Host,
        _host: &HostConfig,
    ) -> bool {
        let cfg = self.config();
        cfg.vhosts().contains(key)
    }

    fn binding(
        &self,
        key: &Host,
        host: Arc<HostConfig>,
    ) -> Result<Option<RouteBinding>> {
        let host_key = key.to_string();
        let host_client_auth_required =
            host.tls_policy().client_auth.is_required();
        if !host_client_auth_required {
            return Err(Error::msg(format!(
                "management gRPC vhost '{host_key}' requires tls.client_auth.mode=required"
            )));
        }

        let factory = Arc::new(
            move |state: AppState, _host: Host, _host_cfg: Arc<HostConfig>| {
                let service =
                    state.registry_ref().resolve::<Self>().ok_or_else(
                        || Error::msg("GrpcServiceProvider is not registered"),
                    )?;
                let handler = service.handler(state, host_key.clone())?;
                Ok(OtherService::new(handler))
            },
        );

        Ok(Some(RouteBinding::Other(factory)))
    }
}
