//! Thin management adapter: storage and validation stay in claviron-dns.
use claviron::runtime::AppState;
use claviron_dns::{DnsProvider, management as domain};
use tonic::{Request, Response, Status};

use crate::proto::dns::dns_manager_server::{DnsManager, DnsManagerServer};
use crate::proto::dns::*;

pub struct DnsService {
    state: AppState,
}

impl DnsService {
    fn store(&self) -> Result<domain::DnsStore, Status> {
        self.state
            .registry_ref()
            .resolve::<DnsProvider>()
            .ok_or_else(|| {
                Status::failed_precondition("DNS provider is not registered")
            })?
            .store()
            .map_err(|e| Status::failed_precondition(e.to_string()))
    }
}

fn db_status(e: domain::ManagementError) -> Status {
    match e {
        domain::ManagementError::Invalid(s) => Status::invalid_argument(s),
        domain::ManagementError::NotFound => Status::not_found(e.to_string()),
        domain::ManagementError::NonemptyZone => {
            Status::failed_precondition(e.to_string())
        }
        domain::ManagementError::Database(ref db)
            if db
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation()) =>
        {
            Status::already_exists("DNS entry already exists")
        }
        _ => {
            tracing::error!(error = %e, "DNS management failed");
            Status::internal("DNS database operation failed")
        }
    }
}

fn id(n: u64) -> Result<i32, Status> {
    i32::try_from(n).ok().filter(|n| *n > 0).ok_or_else(|| {
        Status::invalid_argument("id must be a positive database identifier")
    })
}
fn int(n: u32) -> Result<i32, Status> {
    i32::try_from(n).map_err(|_| {
        Status::invalid_argument("value exceeds database integer range")
    })
}
fn zone_input(
    id: i32,
    c: Option<ZoneConfig>,
) -> Result<domain::Zone, Status> {
    let c =
        c.ok_or_else(|| Status::invalid_argument("zone config is required"))?;
    let s = c
        .soa
        .ok_or_else(|| Status::invalid_argument("SOA config is required"))?;
    Ok(domain::Zone {
        id,
        domain: c.domain,
        enabled: c.enabled,
        soa_serial: 0,
        soa_mname: s.mname,
        soa_rname: s.rname,
        soa_refresh: int(s.refresh)?,
        soa_retry: int(s.retry)?,
        soa_expire: int(s.expire)?,
        soa_minimum: int(s.minimum)?,
    })
}
fn zone_info(z: domain::Zone) -> Result<ZoneInfo, Status> {
    let unsigned = |n: i32| {
        u32::try_from(n)
            .map_err(|_| Status::internal("invalid persisted SOA value"))
    };
    Ok(ZoneInfo {
        id: u64::try_from(z.id)
            .map_err(|_| Status::internal("invalid zone id"))?,
        serial: u32::try_from(z.soa_serial)
            .map_err(|_| Status::internal("invalid persisted SOA serial"))?,
        config: Some(ZoneConfig {
            domain: z.domain,
            enabled: z.enabled,
            soa: Some(SoaConfig {
                mname: z.soa_mname,
                rname: z.soa_rname,
                refresh: unsigned(z.soa_refresh)?,
                retry: unsigned(z.soa_retry)?,
                expire: unsigned(z.soa_expire)?,
                minimum: unsigned(z.soa_minimum)?,
            }),
        }),
    })
}
fn record_input(
    id: i32,
    c: Option<RecordConfig>,
) -> Result<domain::Record, Status> {
    let c =
        c.ok_or_else(|| Status::invalid_argument("record config is required"))?;
    Ok(domain::Record {
        id,
        zone_id: 0,
        name: c.name,
        record_type: c.r#type,
        value: c.value,
        ttl: int(c.ttl)?,
        priority: c.priority.map(int).transpose()?,
        weight: c.weight.map(int).transpose()?,
        port: c.port.map(int).transpose()?,
        enabled: c.enabled,
    })
}
fn record_info(
    r: domain::Record,
    zone: String,
) -> Result<RecordInfo, Status> {
    let unsigned = |n: i32| {
        u32::try_from(n)
            .map_err(|_| Status::internal("invalid persisted record value"))
    };
    Ok(RecordInfo {
        id: u64::try_from(r.id)
            .map_err(|_| Status::internal("invalid record id"))?,
        zone,
        config: Some(RecordConfig {
            name: r.name,
            r#type: r.record_type,
            value: r.value,
            ttl: unsigned(r.ttl)?,
            priority: r.priority.map(unsigned).transpose()?,
            weight: r.weight.map(unsigned).transpose()?,
            port: r.port.map(unsigned).transpose()?,
            enabled: r.enabled,
        }),
    })
}
fn record_response(
    (r, z): (domain::Record, domain::Zone)
) -> Result<Response<RecordResponse>, Status> {
    let z = zone_info(z)?;
    Ok(Response::new(RecordResponse {
        zone_serial: z.serial,
        record: Some(record_info(r, z.config.unwrap().domain)?),
    }))
}

#[tonic::async_trait]
impl DnsManager for DnsService {
    async fn list_zones(
        &self,
        req: Request<ListZonesRequest>,
    ) -> Result<Response<ListZonesResponse>, Status> {
        let zones = self
            .store()?
            .list_zones(req.into_inner().enabled_only)
            .await
            .map_err(db_status)?
            .into_iter()
            .map(zone_info)
            .collect::<Result<_, _>>()?;
        Ok(Response::new(ListZonesResponse { zones }))
    }
    async fn get_zone(
        &self,
        req: Request<GetZoneRequest>,
    ) -> Result<Response<ZoneResponse>, Status> {
        let z = self
            .store()?
            .get_zone(&req.into_inner().domain)
            .await
            .map_err(db_status)?;
        Ok(Response::new(ZoneResponse { zone: Some(zone_info(z)?) }))
    }
    async fn add_zone(
        &self,
        req: Request<AddZoneRequest>,
    ) -> Result<Response<ZoneResponse>, Status> {
        let z = self
            .store()?
            .save_zone(zone_input(0, req.into_inner().config)?, false)
            .await
            .map_err(db_status)?;
        Ok(Response::new(ZoneResponse { zone: Some(zone_info(z)?) }))
    }
    async fn update_zone(
        &self,
        req: Request<UpdateZoneRequest>,
    ) -> Result<Response<ZoneResponse>, Status> {
        let req = req.into_inner();
        let z = self
            .store()?
            .save_zone(zone_input(id(req.id)?, req.config)?, true)
            .await
            .map_err(db_status)?;
        Ok(Response::new(ZoneResponse { zone: Some(zone_info(z)?) }))
    }
    async fn remove_zone(
        &self,
        req: Request<RemoveZoneRequest>,
    ) -> Result<Response<MutationResponse>, Status> {
        let req = req.into_inner();
        let zone = self
            .store()?
            .remove_zone(id(req.id)?, req.cascade)
            .await
            .map_err(db_status)?;
        Ok(Response::new(MutationResponse { zone, zone_serial: None }))
    }
    async fn list_records(
        &self,
        req: Request<ListRecordsRequest>,
    ) -> Result<Response<ListRecordsResponse>, Status> {
        let req = req.into_inner();
        let store = self.store()?;
        let zone = store.get_zone(&req.zone).await.map_err(db_status)?;
        let records = store
            .list_records(&zone.domain, req.enabled_only)
            .await
            .map_err(db_status)?
            .into_iter()
            .map(|r| record_info(r, zone.domain.clone()))
            .collect::<Result<_, _>>()?;
        Ok(Response::new(ListRecordsResponse { records }))
    }
    async fn add_record(
        &self,
        req: Request<AddRecordRequest>,
    ) -> Result<Response<RecordResponse>, Status> {
        let req = req.into_inner();
        record_response(
            self.store()?
                .save_record(Some(&req.zone), record_input(0, req.config)?)
                .await
                .map_err(db_status)?,
        )
    }
    async fn update_record(
        &self,
        req: Request<UpdateRecordRequest>,
    ) -> Result<Response<RecordResponse>, Status> {
        let req = req.into_inner();
        record_response(
            self.store()?
                .save_record(None, record_input(id(req.id)?, req.config)?)
                .await
                .map_err(db_status)?,
        )
    }
    async fn remove_record(
        &self,
        req: Request<RemoveRecordRequest>,
    ) -> Result<Response<MutationResponse>, Status> {
        let z = zone_info(
            self.store()?
                .remove_record(id(req.into_inner().id)?)
                .await
                .map_err(db_status)?,
        )?;
        Ok(Response::new(MutationResponse {
            zone: z.config.unwrap().domain,
            zone_serial: Some(z.serial),
        }))
    }
    async fn reload_dns(
        &self,
        _: Request<ReloadDnsRequest>,
    ) -> Result<Response<ReloadDnsResponse>, Status> {
        self.store()?.request_reload().await.map_err(db_status)?;
        Ok(Response::new(ReloadDnsResponse { accepted: true }))
    }
}

pub fn create_dns_service(state: AppState) -> DnsManagerServer<DnsService> {
    DnsManagerServer::new(DnsService { state })
}
