//! Thin management adapter: every call maps a `claviron.domains` message
//! onto `claviron_domains::Domains` and the answer back. Registrar quirks,
//! the store and the pools stay below.
use claviron::runtime::AppState;
use claviron_domains::registrar::{
    DomainInfo as RegistrarDomainInfo, RegistrarRecord,
};
use claviron_domains::store;
use claviron_domains::{Domains, Error, SyncReport, TemplateRecord};
use tonic::{Request, Response, Status};

use crate::proto::domains::domain_manager_server::{
    DomainManager, DomainManagerServer,
};
use crate::proto::domains::*;

pub struct DomainService {
    state: AppState,
}

impl DomainService {
    fn domains(&self) -> Result<Domains, Status> {
        Domains::from_state(&self.state).map_err(status)
    }
}

fn status(error: Error) -> Status {
    match error {
        Error::UnknownRegistrar(_) | Error::NotFound(_) => {
            Status::not_found(error.to_string())
        }
        Error::NotConfigured(_) | Error::InUse(_) | Error::StoreUnavailable => {
            Status::failed_precondition(error.to_string())
        }
        Error::Invalid(message) => Status::invalid_argument(message),
        Error::Registrar(inner) => {
            use claviron_domains::registrar::Error as R;
            match inner {
                R::Unsupported { .. } => {
                    Status::unimplemented(inner.to_string())
                }
                R::Invalid(message) => Status::invalid_argument(message),
                R::RateLimited { .. } => {
                    Status::resource_exhausted(inner.to_string())
                }
                R::Cancelled => Status::cancelled("cancelled"),
                // Claviron answered; the registrar is what refused or could
                // not be reached. `UNAVAILABLE` would tell a client that this
                // server is gone, so it is never the code for a registrar.
                R::Api { .. } => {
                    tracing::error!(error = %inner, "registrar refused the call");
                    Status::failed_precondition(inner.to_string())
                }
                _ => {
                    tracing::error!(error = %inner, "registrar call failed");
                    Status::unknown(inner.to_string())
                }
            }
        }
        Error::Database(inner) => {
            tracing::error!(error = %inner, "domain store query failed");
            Status::internal("domain store operation failed")
        }
    }
}

fn domain_name(name: &str) -> Result<&str, Status> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Status::invalid_argument("domain name is required"));
    }
    Ok(name)
}

fn registrar_name(name: &str) -> Result<&str, Status> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Status::invalid_argument("registrar is required"));
    }
    Ok(name)
}

fn timestamp(value: time::OffsetDateTime) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.unix_timestamp(),
        nanos: value.nanosecond() as i32,
    }
}

fn domain_status(value: store::DomainStatus) -> DomainStatus {
    match value {
        store::DomainStatus::Pending => DomainStatus::Pending,
        store::DomainStatus::Active => DomainStatus::Active,
        store::DomainStatus::Expired => DomainStatus::Expired,
        store::DomainStatus::Suspended => DomainStatus::Suspended,
        store::DomainStatus::Transferring => DomainStatus::Transferring,
        store::DomainStatus::Failed => DomainStatus::Failed,
    }
}

fn store_status(value: DomainStatus) -> Option<store::DomainStatus> {
    match value {
        DomainStatus::Unspecified => None,
        DomainStatus::Pending => Some(store::DomainStatus::Pending),
        DomainStatus::Active => Some(store::DomainStatus::Active),
        DomainStatus::Expired => Some(store::DomainStatus::Expired),
        DomainStatus::Suspended => Some(store::DomainStatus::Suspended),
        DomainStatus::Transferring => Some(store::DomainStatus::Transferring),
        DomainStatus::Failed => Some(store::DomainStatus::Failed),
    }
}

fn domain_message(domain: store::Domain) -> Result<Domain, Status> {
    Ok(Domain {
        id: u64::try_from(domain.id)
            .map_err(|_| Status::internal("invalid domain id"))?,
        name: domain.name,
        registrar: claviron_domains::registrar_name(domain.registrar_id)
            .to_owned(),
        registrar_ref: domain.register_ref.to_string(),
        dns_provider: domain
            .dns_provider_id
            .map(|id| claviron_domains::registrar_name(id).to_owned())
            .unwrap_or_default(),
        status: domain_status(domain.status).into(),
        registered_at: Some(timestamp(domain.registered_at)),
        expires_at: Some(timestamp(domain.expires_at)),
        auto_renew: domain.auto_renew,
        renew_before_days: u32::try_from(domain.renew_before_days)
            .unwrap_or_default(),
        whois_privacy: domain.whois_privacy,
        updated_at: Some(timestamp(domain.updated_at)),
    })
}

fn domain_response(
    domain: store::Domain
) -> Result<Response<DomainResponse>, Status> {
    Ok(Response::new(DomainResponse { domain: Some(domain_message(domain)?) }))
}

fn info_message(
    registrar: &str,
    info: RegistrarDomainInfo,
) -> DomainInfo {
    DomainInfo {
        name: info.name,
        registrar: registrar.to_owned(),
        registrar_ref: info
            .reference
            .map(|r| r.to_string())
            .unwrap_or_default(),
        registered_at: info.registered_at.map(timestamp),
        expires_at: info.expires_at.map(timestamp),
        auto_renew: info.auto_renew,
        whois_privacy: info.whois_privacy,
        nameservers: info.nameservers.unwrap_or_default(),
        registrar_status: info.status,
    }
}

fn contact_message(contact: claviron_domains::templates::Contact) -> Contact {
    Contact {
        first_name: contact.first_name,
        last_name: contact.last_name,
        address1: contact.address1,
        address2: contact.address2.unwrap_or_default(),
        city: contact.city,
        state_province: contact.state_province,
        postal_code: contact.postal_code,
        country: contact.country,
        phone: contact.phone,
        email: contact.email,
    }
}

fn contacts_message(
    contacts: claviron_domains::templates::Contacts
) -> Contacts {
    Contacts {
        registrant: Some(contact_message(contacts.registrant)),
        admin: contacts.admin.map(contact_message),
        tech: contacts.tech.map(contact_message),
        billing: contacts.billing.map(contact_message),
    }
}

/// A contact the registrars will accept: every field they all require is
/// present. Nothing is filled in on the operator's behalf.
fn contact_input(
    role: &str,
    contact: Contact,
) -> Result<claviron_domains::templates::Contact, Status> {
    let required = [
        ("first_name", &contact.first_name),
        ("last_name", &contact.last_name),
        ("address1", &contact.address1),
        ("city", &contact.city),
        ("state_province", &contact.state_province),
        ("postal_code", &contact.postal_code),
        ("country", &contact.country),
        ("phone", &contact.phone),
        ("email", &contact.email),
    ];
    for (field, value) in required {
        if value.trim().is_empty() {
            return Err(Status::invalid_argument(format!(
                "{role} contact: {field} is required"
            )));
        }
    }
    if contact.country.trim().len() != 2 {
        return Err(Status::invalid_argument(format!(
            "{role} contact: country must be a two-letter ISO code"
        )));
    }
    Ok(claviron_domains::templates::Contact {
        first_name: contact.first_name,
        last_name: contact.last_name,
        address1: contact.address1,
        address2: (!contact.address2.trim().is_empty())
            .then_some(contact.address2),
        city: contact.city,
        state_province: contact.state_province,
        postal_code: contact.postal_code,
        country: contact.country.to_ascii_uppercase(),
        phone: contact.phone,
        email: contact.email,
    })
}

fn template_input(
    request: PutTemplateRequest
) -> Result<(String, claviron_domains::templates::DomainTemplateData), Status> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err(Status::invalid_argument("template name is required"));
    }
    let contacts = request
        .contacts
        .ok_or_else(|| Status::invalid_argument("contacts are required"))?;
    let registrant = contacts.registrant.ok_or_else(|| {
        Status::invalid_argument("registrant contact is required")
    })?;
    let data = claviron_domains::templates::DomainTemplateData {
        contacts: claviron_domains::templates::Contacts {
            registrant: contact_input("registrant", registrant)?,
            admin: contacts
                .admin
                .map(|c| contact_input("admin", c))
                .transpose()?,
            tech: contacts
                .tech
                .map(|c| contact_input("tech", c))
                .transpose()?,
            billing: contacts
                .billing
                .map(|c| contact_input("billing", c))
                .transpose()?,
        },
        nameservers: (!request.nameservers.is_empty())
            .then_some(request.nameservers),
        dns_records: None,
    };
    Ok((name.to_owned(), data))
}

fn template_message(
    template: TemplateRecord
) -> Result<DomainTemplate, Status> {
    Ok(DomainTemplate {
        id: u64::try_from(template.id)
            .map_err(|_| Status::internal("invalid template id"))?,
        name: template.name,
        contacts: Some(contacts_message(template.data.contacts)),
        nameservers: template.data.nameservers.unwrap_or_default(),
        updated_at: Some(timestamp(template.updated_at)),
    })
}

// The proto message and the facade type share a name; the alias keeps the
// two apart inside this module.
type RegistrarRecordMessage = crate::proto::domains::RegistrarRecord;

fn record_message(record: RegistrarRecord) -> RegistrarRecordMessage {
    RegistrarRecordMessage {
        r#type: record.record_type,
        name: record.name,
        value: record.value,
        ttl: record.ttl,
        priority: record.priority,
        weight: record.weight,
        port: record.port,
    }
}

fn record_input(record: RegistrarRecordMessage) -> RegistrarRecord {
    RegistrarRecord {
        record_type: record.r#type,
        name: record.name,
        value: record.value,
        ttl: record.ttl,
        priority: record.priority,
        weight: record.weight,
        port: record.port,
    }
}

fn records_response(
    name: &str,
    records: Vec<RegistrarRecord>,
) -> Response<RegistrarRecordsResponse> {
    Response::new(RegistrarRecordsResponse {
        name: name.to_owned(),
        records: records.into_iter().map(record_message).collect(),
    })
}

fn nameservers_response(
    name: &str,
    nameservers: Vec<String>,
) -> Response<NameserversResponse> {
    Response::new(NameserversResponse { name: name.to_owned(), nameservers })
}

fn sync_message(report: SyncReport) -> SyncResponse {
    SyncResponse {
        found: u32::try_from(report.found).unwrap_or(u32::MAX),
        skipped: u32::try_from(report.skipped).unwrap_or(u32::MAX),
        created: report.created,
        updated: report.updated,
        failed: report
            .failed
            .into_iter()
            .map(|(domain, message)| SyncFailure { domain, message })
            .collect(),
    }
}

fn glue_input(
    host: &str,
    ip: &str,
) -> Result<(), Status> {
    if host.is_empty() {
        return Err(Status::invalid_argument("glue host is required"));
    }
    ip.parse::<std::net::IpAddr>().map_err(|_| {
        Status::invalid_argument(format!("`{ip}` is not an IP address"))
    })?;
    Ok(())
}

#[tonic::async_trait]
impl DomainManager for DomainService {
    async fn list_registrars(
        &self,
        _: Request<ListRegistrarsRequest>,
    ) -> Result<Response<ListRegistrarsResponse>, Status> {
        let registrars = Domains::registrars()
            .into_iter()
            .map(|entry| RegistrarInfo {
                name: entry.name.to_owned(),
                configured: entry.configured,
                supports_registration: entry.supports_registration,
                supports_dns: entry.supports_dns,
                supports_glue: entry.supports_glue,
            })
            .collect();
        Ok(Response::new(ListRegistrarsResponse { registrars }))
    }

    async fn list_domains(
        &self,
        request: Request<ListDomainsRequest>,
    ) -> Result<Response<ListDomainsResponse>, Status> {
        let request = request.into_inner();
        let registrar = (!request.registrar.is_empty())
            .then_some(request.registrar.as_str());
        let status_filter = store_status(request.status());
        let expiring = (request.expiring_within_days > 0)
            .then_some(request.expiring_within_days);
        let domains = self
            .domains()?
            .list(registrar, status_filter, expiring)
            .await
            .map_err(status)?
            .into_iter()
            .map(domain_message)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListDomainsResponse { domains }))
    }

    async fn get_domain(
        &self,
        request: Request<GetDomainRequest>,
    ) -> Result<Response<DomainResponse>, Status> {
        let name = request.into_inner().name;
        let domain =
            self.domains()?.get(domain_name(&name)?).await.map_err(status)?;
        domain_response(domain)
    }

    async fn add_domain(
        &self,
        request: Request<AddDomainRequest>,
    ) -> Result<Response<DomainResponse>, Status> {
        let request = request.into_inner();
        let domain = self
            .domains()?
            .record(
                registrar_name(&request.registrar)?,
                domain_name(&request.name)?,
            )
            .await
            .map_err(status)?;
        domain_response(domain)
    }

    async fn refresh_domain(
        &self,
        request: Request<RefreshDomainRequest>,
    ) -> Result<Response<DomainResponse>, Status> {
        let name = request.into_inner().name;
        let domain = self
            .domains()?
            .refresh(domain_name(&name)?)
            .await
            .map_err(status)?;
        domain_response(domain)
    }

    async fn get_domain_info(
        &self,
        request: Request<GetDomainInfoRequest>,
    ) -> Result<Response<DomainInfoResponse>, Status> {
        let request = request.into_inner();
        let registrar = registrar_name(&request.registrar)?;
        let info = self
            .domains()?
            .info(registrar, domain_name(&request.name)?)
            .await
            .map_err(status)?;
        Ok(Response::new(DomainInfoResponse {
            info: Some(info_message(registrar, info)),
        }))
    }

    async fn get_contacts(
        &self,
        request: Request<GetContactsRequest>,
    ) -> Result<Response<ContactsResponse>, Status> {
        let request = request.into_inner();
        let contacts = self
            .domains()?
            .contacts(
                registrar_name(&request.registrar)?,
                domain_name(&request.name)?,
            )
            .await
            .map_err(status)?;
        Ok(Response::new(ContactsResponse {
            contacts: Some(contacts_message(contacts)),
        }))
    }

    async fn register_domain(
        &self,
        request: Request<RegisterDomainRequest>,
    ) -> Result<Response<DomainResponse>, Status> {
        let request = request.into_inner();
        let template = request.template.trim();
        if template.is_empty() {
            return Err(Status::invalid_argument("template is required"));
        }
        let years = u8::try_from(request.years)
            .ok()
            .filter(|years| (1..=10).contains(years))
            .ok_or_else(|| {
                Status::invalid_argument("years must be between 1 and 10")
            })?;
        let domain = self
            .domains()?
            .register(
                registrar_name(&request.registrar)?,
                domain_name(&request.name)?,
                template,
                years,
            )
            .await
            .map_err(status)?;
        domain_response(domain)
    }

    async fn renew_domain(
        &self,
        request: Request<RenewDomainRequest>,
    ) -> Result<Response<DomainResponse>, Status> {
        let request = request.into_inner();
        let years = u8::try_from(request.years)
            .ok()
            .filter(|years| (1..=10).contains(years))
            .ok_or_else(|| {
                Status::invalid_argument("years must be between 1 and 10")
            })?;
        let domain = self
            .domains()?
            .renew(domain_name(&request.name)?, years)
            .await
            .map_err(status)?;
        domain_response(domain)
    }

    async fn get_nameservers(
        &self,
        request: Request<GetNameserversRequest>,
    ) -> Result<Response<NameserversResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let nameservers = self
            .domains()?
            .nameservers(registrar_name(&request.registrar)?, name)
            .await
            .map_err(status)?;
        Ok(nameservers_response(name, nameservers))
    }

    async fn set_nameservers(
        &self,
        request: Request<SetNameserversRequest>,
    ) -> Result<Response<NameserversResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let nameservers = self
            .domains()?
            .set_nameservers(
                registrar_name(&request.registrar)?,
                name,
                &request.nameservers,
            )
            .await
            .map_err(status)?;
        Ok(nameservers_response(name, nameservers))
    }

    async fn use_claviron_nameservers(
        &self,
        request: Request<UseClavironNameserversRequest>,
    ) -> Result<Response<NameserversResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let nameservers = self
            .domains()?
            .use_claviron_nameservers(registrar_name(&request.registrar)?, name)
            .await
            .map_err(status)?;
        Ok(nameservers_response(name, nameservers))
    }

    async fn create_glue_record(
        &self,
        request: Request<CreateGlueRecordRequest>,
    ) -> Result<Response<GlueRecordResponse>, Status> {
        let request = request.into_inner();
        glue_input(&request.host, &request.ip)?;
        self.domains()?
            .create_glue(
                registrar_name(&request.registrar)?,
                domain_name(&request.name)?,
                &request.host,
                &request.ip,
            )
            .await
            .map_err(status)?;
        Ok(Response::new(GlueRecordResponse {
            host: request.host,
            ip: request.ip,
        }))
    }

    async fn update_glue_record(
        &self,
        request: Request<UpdateGlueRecordRequest>,
    ) -> Result<Response<GlueRecordResponse>, Status> {
        let request = request.into_inner();
        glue_input(&request.host, &request.ip)?;
        self.domains()?
            .update_glue(
                registrar_name(&request.registrar)?,
                domain_name(&request.name)?,
                &request.host,
                &request.ip,
                request.old_ip.as_deref(),
            )
            .await
            .map_err(status)?;
        Ok(Response::new(GlueRecordResponse {
            host: request.host,
            ip: request.ip,
        }))
    }

    async fn list_registrar_records(
        &self,
        request: Request<ListRegistrarRecordsRequest>,
    ) -> Result<Response<RegistrarRecordsResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let records = self
            .domains()?
            .records(registrar_name(&request.registrar)?, name, &request.r#type)
            .await
            .map_err(status)?;
        Ok(records_response(name, records))
    }

    async fn replace_registrar_records(
        &self,
        request: Request<ReplaceRegistrarRecordsRequest>,
    ) -> Result<Response<RegistrarRecordsResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let records: Vec<_> =
            request.records.into_iter().map(record_input).collect();
        let records = self
            .domains()?
            .replace_records(
                registrar_name(&request.registrar)?,
                name,
                &records,
            )
            .await
            .map_err(status)?;
        Ok(records_response(name, records))
    }

    async fn upsert_registrar_records(
        &self,
        request: Request<UpsertRegistrarRecordsRequest>,
    ) -> Result<Response<RegistrarRecordsResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let records: Vec<_> =
            request.records.into_iter().map(record_input).collect();
        let records = self
            .domains()?
            .upsert_records(registrar_name(&request.registrar)?, name, &records)
            .await
            .map_err(status)?;
        Ok(records_response(name, records))
    }

    async fn remove_registrar_record(
        &self,
        request: Request<RemoveRegistrarRecordRequest>,
    ) -> Result<Response<RegistrarRecordsResponse>, Status> {
        let request = request.into_inner();
        let name = domain_name(&request.name)?;
        let records = self
            .domains()?
            .remove_records(
                registrar_name(&request.registrar)?,
                name,
                &request.r#type,
                &request.record_name,
            )
            .await
            .map_err(status)?;
        Ok(records_response(name, records))
    }

    async fn list_templates(
        &self,
        _: Request<ListTemplatesRequest>,
    ) -> Result<Response<ListTemplatesResponse>, Status> {
        let templates = self
            .domains()?
            .templates()
            .await
            .map_err(status)?
            .into_iter()
            .map(template_message)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListTemplatesResponse { templates }))
    }

    async fn put_template(
        &self,
        request: Request<PutTemplateRequest>,
    ) -> Result<Response<TemplateResponse>, Status> {
        let (name, data) = template_input(request.into_inner())?;
        let template =
            self.domains()?.put_template(&name, &data).await.map_err(status)?;
        Ok(Response::new(TemplateResponse {
            template: Some(template_message(template)?),
        }))
    }

    async fn remove_template(
        &self,
        request: Request<RemoveTemplateRequest>,
    ) -> Result<Response<RemoveTemplateResponse>, Status> {
        let name = request.into_inner().name;
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("template name is required"));
        }
        let removed =
            self.domains()?.remove_template(&name).await.map_err(status)?;
        Ok(Response::new(RemoveTemplateResponse { removed }))
    }

    async fn sync_domains(
        &self,
        request: Request<SyncDomainsRequest>,
    ) -> Result<Response<SyncResponse>, Status> {
        let request = request.into_inner();
        let registrar = (!request.registrar.is_empty())
            .then_some(request.registrar.as_str());
        let report =
            self.domains()?.sync_domains(registrar).await.map_err(status)?;
        Ok(Response::new(sync_message(report)))
    }

    async fn sync_dns_records(
        &self,
        request: Request<SyncDnsRecordsRequest>,
    ) -> Result<Response<SyncResponse>, Status> {
        let request = request.into_inner();
        let only = (!request.name.is_empty()).then_some(request.name.as_str());
        let report =
            self.domains()?.sync_records(only).await.map_err(status)?;
        Ok(Response::new(sync_message(report)))
    }
}

pub fn create_domain_service(
    state: AppState
) -> DomainManagerServer<DomainService> {
    DomainManagerServer::new(DomainService { state })
}
