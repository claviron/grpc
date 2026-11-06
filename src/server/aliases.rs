//! Virtual Hosting Management gRPC Service

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use claviron::edge::VhostResolver;
use claviron::hosting::{HostingService, HostingStore, VhostAlias};
use claviron::runtime::AppState;
use claviron::ssl::Host;
use tonic::{Request, Response, Status};

pub mod aliases_proto {
    include!(concat!(env!("OUT_DIR"), "/claviron.aliases.rs"));
}

use aliases_proto::alias_manager_server::AliasManager;
use aliases_proto::{
    AddAliasRequest, AddVhostToServersRequest, AliasResponse, HostingVhostInfo,
    ListAliasesRequest, ListAliasesResponse, ListHostingRequest,
    ListHostingResponse, ListServersByVhostRequest, ListServersResponse,
    ListVhostsByServerRequest, ListVhostsResponse, OperationResponse,
    ReloadRequest, RemoveAliasRequest, RemoveVhostFromServersRequest,
    ReplaceAliasRequest, ServerInfo, VhostInfo,
};

#[derive(Clone)]
pub struct AliasService {
    state: AppState,
    vhosts: Arc<VhostResolver>,
}

impl AliasService {
    pub fn new(state: AppState) -> Result<Self, Status> {
        let vhosts = state
            .registry_ref()
            .resolve::<VhostResolver>()
            .ok_or_else(|| {
                Status::failed_precondition("VhostResolver is not registered")
            })?;
        Ok(Self { state, vhosts })
    }

    fn hosting(&self) -> Result<Arc<HostingService>, Status> {
        self.state.registry_ref().resolve::<HostingService>().ok_or_else(|| {
            Status::failed_precondition("HostingService is not registered")
        })
    }

    // Listing needs only the resolver. Persistence is opened for writes and
    // explicit database relationship queries, through the announcing service.
    fn store(&self) -> Result<HostingStore, Status> {
        self.hosting()?.store().map_err(db_status)
    }

    fn server_id(&self) -> Result<i32, Status> {
        self.hosting()?
            .require_server_id()
            .map_err(|error| Status::failed_precondition(error.to_string()))
    }

    /// The hosting store's aliases, applied one alias at a time. The store
    /// only contributes aliases to the vhost table; replacing the whole table
    /// (`replace_all`) would fail this worker's listeners closed until a full
    /// reload rebuilds transport policy.
    async fn reload_vhosts(&self) -> Result<(), Status> {
        self.vhosts.apply_stored_aliases(&self.state).await.map(|_| ()).map_err(
            |error| {
                Status::internal(format!("Failed to reload vhosts: {error}"))
            },
        )
    }

    fn parse_host(
        &self,
        raw: &str,
        field: &str,
    ) -> Result<Host, Status> {
        Host::from_str(raw).map_err(|error| {
            Status::invalid_argument(format!(
                "Invalid {field} '{raw}': {error}"
            ))
        })
    }
}

#[tonic::async_trait]
impl AliasManager for AliasService {
    #[tracing::instrument(skip_all, fields(operation = "add_alias", alias = %request.get_ref().hostname, canonical = %request.get_ref().vhost_name), err(level = "warn"))]
    async fn add_alias(
        &self,
        request: Request<AddAliasRequest>,
    ) -> Result<Response<AliasResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("gRPC alias addition requested");
        let (alias_host, canonical_host) = validate_alias_target(
            &self.vhosts,
            &req.hostname,
            &req.vhost_name,
            false,
        )?;
        let canonical_name = canonical_host.to_string();
        let alias = self
            .store()?
            .add_alias_for_server(
                self.server_id()?,
                &canonical_name,
                &alias_host.to_string(),
            )
            .await
            .map_err(db_status)?;
        self.vhosts.upsert_alias(alias_host, canonical_host).map_err(
            |error| {
                Status::internal(format!(
                    "Failed to update vhost snapshot: {error}"
                ))
            },
        )?;

        tracing::info!("gRPC alias addition committed and published locally");
        Ok(Response::new(AliasResponse {
            alias: Some(alias_info(alias)),
            vhost_name: canonical_name,
        }))
    }

    #[tracing::instrument(skip_all, fields(operation = "remove_alias", alias = %request.get_ref().hostname), err(level = "warn"))]
    async fn remove_alias(
        &self,
        request: Request<RemoveAliasRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("gRPC alias removal requested");
        let alias = self.parse_host(&req.hostname, "alias hostname")?;
        ensure_alias_mutable(&self.vhosts, &alias)?;
        if !self
            .store()?
            .remove_alias(&alias.to_string())
            .await
            .map_err(db_status)?
        {
            return Err(Status::not_found(format!(
                "Alias '{}' not found",
                req.hostname
            )));
        }
        self.vhosts.delete_alias(&alias);
        tracing::info!("gRPC alias removal committed and published locally");
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!("Removed alias '{}'", req.hostname)),
        }))
    }

    #[tracing::instrument(skip_all, fields(operation = "replace_alias", alias = %request.get_ref().hostname, canonical = %request.get_ref().vhost_name), err(level = "warn"))]
    async fn replace_alias(
        &self,
        request: Request<ReplaceAliasRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let req = request.into_inner();
        tracing::info!("gRPC alias move requested");
        let (alias, canonical) = validate_alias_target(
            &self.vhosts,
            &req.hostname,
            &req.vhost_name,
            true,
        )?;
        let previous = self
            .vhosts
            .snapshot()
            .resolve_exact(&alias)
            .map(|(host, _)| host.to_string());
        self.store()?
            .replace_alias_for_server(
                self.server_id()?,
                &canonical.to_string(),
                &alias.to_string(),
            )
            .await
            .map_err(db_status)?;
        self.vhosts.upsert_alias(alias, canonical).map_err(|error| {
            Status::internal(format!(
                "Failed to update vhost snapshot: {error}"
            ))
        })?;
        tracing::info!(previous_canonical = ?previous, "gRPC alias move committed and published locally");
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!(
                "Moved alias '{}' to vhost '{}'",
                req.hostname, req.vhost_name
            )),
        }))
    }

    async fn list_aliases(
        &self,
        request: Request<ListAliasesRequest>,
    ) -> Result<Response<ListAliasesResponse>, Status> {
        let req = request.into_inner();
        let vhosts = runtime_hosting(&self.vhosts);
        let filter = req
            .vhost_name
            .as_deref()
            .map(|name| {
                self.parse_host(name, "vhost name").map(|host| host.to_string())
            })
            .transpose()?;
        if let Some(name) = &filter
            && !vhosts.iter().any(|hosted| {
                hosted.vhost.as_ref().is_some_and(|host| &host.name == name)
            })
        {
            return Err(Status::not_found(format!("Vhost '{name}' not found")));
        }
        let aliases = vhosts
            .into_iter()
            .filter_map(|hosted| {
                let host = hosted.vhost?;
                if filter.as_ref().is_some_and(|name| name != &host.name) {
                    return None;
                }
                Some(hosted.aliases.into_iter().map(move |alias| {
                    AliasResponse {
                        alias: Some(alias),
                        vhost_name: host.name.clone(),
                    }
                }))
            })
            .flatten()
            .collect();
        Ok(Response::new(ListAliasesResponse { aliases }))
    }

    async fn list_hosting(
        &self,
        _request: Request<ListHostingRequest>,
    ) -> Result<Response<ListHostingResponse>, Status> {
        Ok(Response::new(ListHostingResponse {
            vhosts: runtime_hosting(&self.vhosts),
        }))
    }

    async fn reload_vhosts(
        &self,
        _request: Request<ReloadRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        self.reload_vhosts().await?;
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(
                "Reloaded persisted aliases into the vhost table".to_owned(),
            ),
        }))
    }

    async fn add_vhost_to_servers(
        &self,
        request: Request<AddVhostToServersRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let req = request.into_inner();
        let added = self
            .store()?
            .add_vhost_to_servers(&req.vhost_name, &req.server_names)
            .await
            .map_err(db_status)?;
        self.reload_vhosts().await?;
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!(
                "Added vhost '{}' to {} server(s)",
                req.vhost_name, added
            )),
        }))
    }

    async fn remove_vhost_from_servers(
        &self,
        request: Request<RemoveVhostFromServersRequest>,
    ) -> Result<Response<OperationResponse>, Status> {
        let req = request.into_inner();
        let removed = self
            .store()?
            .remove_vhost_from_servers(&req.vhost_name, &req.server_names)
            .await
            .map_err(db_status)?;
        self.reload_vhosts().await?;
        Ok(Response::new(OperationResponse {
            success: true,
            message: Some(format!(
                "Removed vhost '{}' from {} server(s)",
                req.vhost_name, removed
            )),
        }))
    }

    async fn list_vhosts_by_server(
        &self,
        request: Request<ListVhostsByServerRequest>,
    ) -> Result<Response<ListVhostsResponse>, Status> {
        let req = request.into_inner();
        let server = self
            .store()?
            .server_by_name(&req.server_name)
            .await
            .map_err(db_status)?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "Server '{}' not found",
                    req.server_name
                ))
            })?;
        let vhosts = self
            .store()?
            .vhosts_for_server(server.id)
            .await
            .map_err(db_status)?
            .into_iter()
            .map(|vhost| VhostInfo {
                id: vhost.id,
                name: vhost.name,
                enabled: vhost.enabled,
                read_only: true,
                read_only_reason: Some(host_read_only_reason().to_owned()),
            })
            .collect();
        Ok(Response::new(ListVhostsResponse { vhosts }))
    }

    async fn list_servers_by_vhost(
        &self,
        request: Request<ListServersByVhostRequest>,
    ) -> Result<Response<ListServersResponse>, Status> {
        let req = request.into_inner();
        let servers = self
            .store()?
            .servers_for_vhost(&req.vhost_name)
            .await
            .map_err(db_status)?
            .into_iter()
            .map(|server| ServerInfo {
                id: server.id,
                name: server.name,
                enabled: server.enabled,
            })
            .collect();
        Ok(Response::new(ListServersResponse { servers }))
    }
}

pub fn create_hosting_service(
    state: AppState
) -> Result<
    aliases_proto::alias_manager_server::AliasManagerServer<AliasService>,
    Status,
> {
    Ok(aliases_proto::alias_manager_server::AliasManagerServer::new(
        AliasService::new(state)?,
    ))
}

fn db_status(error: claviron::hosting::HostingError) -> Status {
    match error {
        claviron::hosting::HostingError::NotFound(message) => {
            Status::not_found(message)
        }
        claviron::hosting::HostingError::InvalidInput(message) => {
            Status::invalid_argument(message)
        }
        claviron::hosting::HostingError::Conflict(message) => {
            Status::already_exists(message)
        }
        error => Status::internal(error.to_string()),
    }
}

fn alias_info(alias: VhostAlias) -> aliases_proto::AliasInfo {
    aliases_proto::AliasInfo {
        id: alias.id,
        hostname: alias.hostname,
        enabled: None,
        read_only: false,
        read_only_reason: None,
    }
}

/// One immutable runtime view; no persistence IDs or cross-server inventory.
fn runtime_hosting(resolver: &VhostResolver) -> Vec<HostingVhostInfo> {
    let snapshot = resolver.snapshot();
    let mut static_aliases = BTreeMap::new();
    let mut hosts: BTreeMap<_, _> = snapshot
        .canonical_entries()
        .map(|(name, record)| {
            let name = name.to_string();
            // Keep declared aliases visible even if a prior dynamic update
            // removed their live key; only configuration can release them.
            let aliases = record
                .config
                .aliases()
                .iter()
                .filter(|alias| snapshot.canonical_config(alias).is_none())
                .map(|alias| {
                    static_aliases.insert(alias.to_string(), name.clone());
                    aliases_proto::AliasInfo {
                        id: 0,
                        hostname: alias.to_string(),
                        enabled: None,
                        read_only: true,
                        read_only_reason: Some(
                            alias_read_only_reason().to_owned(),
                        ),
                    }
                })
                .collect();
            (
                name.clone(),
                HostingVhostInfo {
                    vhost: Some(VhostInfo {
                        id: 0,
                        name,
                        enabled: true,
                        read_only: true,
                        read_only_reason: Some(
                            host_read_only_reason().to_owned(),
                        ),
                    }),
                    aliases,
                    servers: Vec::new(),
                },
            )
        })
        .collect();
    for (alias, canonical) in snapshot.alias_entries() {
        if static_aliases.contains_key(&alias.to_string()) {
            continue;
        }
        if let Some(hosted) = hosts.get_mut(&canonical.to_string()) {
            hosted.aliases.push(aliases_proto::AliasInfo {
                id: 0,
                hostname: alias.to_string(),
                enabled: None,
                read_only: false,
                read_only_reason: None,
            });
        }
    }
    for hosted in hosts.values_mut() {
        hosted.aliases.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        hosted.aliases.dedup_by(|a, b| a.hostname == b.hostname);
    }
    hosts.into_values().collect()
}

fn host_read_only_reason() -> &'static str {
    "This host is statically configured; change the host configuration to edit it. Dynamic aliases may still be added."
}

fn alias_read_only_reason() -> &'static str {
    "This alias is statically configured; change the host configuration to edit or remove it."
}

fn ensure_alias_mutable(
    resolver: &VhostResolver,
    alias: &Host,
) -> Result<(), Status> {
    let snapshot = resolver.snapshot();
    if snapshot.canonical_config(alias).is_some() {
        return Err(Status::failed_precondition(host_read_only_reason()));
    }
    if snapshot
        .canonical_entries()
        .any(|(_, record)| record.config.aliases().contains(alias))
    {
        return Err(Status::failed_precondition(alias_read_only_reason()));
    }
    Ok(())
}

fn validate_alias_target(
    resolver: &VhostResolver,
    hostname: &str,
    vhost_name: &str,
    replace: bool,
) -> Result<(Host, Host), Status> {
    let alias: Host = hostname.parse().map_err(|error| {
        Status::invalid_argument(format!(
            "Invalid alias hostname '{hostname}': {error}"
        ))
    })?;
    ensure_alias_mutable(resolver, &alias)?;
    let canonical: Host = vhost_name.parse().map_err(|error| {
        Status::invalid_argument(format!(
            "Invalid vhost name '{vhost_name}': {error}"
        ))
    })?;
    let snapshot = resolver.snapshot();
    if snapshot.canonical_config(&canonical).is_none() {
        return Err(Status::not_found(format!(
            "Configured vhost '{canonical}' not found"
        )));
    }
    if snapshot.canonical_config(&alias).is_some() {
        return Err(Status::invalid_argument(
            "An alias cannot overwrite a canonical host",
        ));
    }
    // Match the table's supported alias/host families before committing a row.
    if !matches!(
        (&canonical, &alias),
        (Host::Dns(_), Host::Dns(_))
            | (Host::Ip(_), Host::Ip(_))
            | (_, Host::Single(_))
            | (Host::Single(_), _)
    ) {
        return Err(Status::invalid_argument(
            "Alias and canonical host types do not match",
        ));
    }
    if !replace
        && let Some((existing, _)) = snapshot.resolve_exact(&alias)
        && existing != canonical
    {
        return Err(Status::already_exists(format!(
            "Alias '{alias}' already belongs to '{existing}'"
        )));
    }
    Ok((alias, canonical))
}

#[cfg(test)]
#[path = "../../tests/server/aliases.rs"]
mod tests;
