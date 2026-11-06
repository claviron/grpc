//! Shared database-backed certificate operations for management and application callers.
//!
//! Callers authorize operations before invoking this manager. It performs no
//! authentication and creates no HTTP routes. It uses the crate's protobuf DTOs
//! and `tonic::Status` errors, but requires no gRPC request, connection or server.
//! Private keys are only exported when explicitly requested.
use claviron::hosting::{
    CertificateKind, HostedCertificate, HostingError, HostingService,
    HostingStore, IssuerKind, NewCertificate,
};
use claviron::runtime::AppState;
use claviron::ssl::{formatters, transfer};
use tonic::Status;

use crate::proto::certificates::{
    CertificateInfo as TransferInfo, ExportCertificateRequest,
    ExportCertificateResponse, ImportCertificateRequest,
};
/// Certificate import/export, independent of the issuance service.
///
/// Application handlers must enforce their own enrollment/authorization policy.
/// The manager never derives permission from a request's chosen CN or issuer.
pub struct CertificateManager {
    store: HostingStore,
    server_id: Option<i32>,
}

impl CertificateManager {
    /// Use an explicit store. A server id is required only for server certificates.
    pub fn new(
        store: HostingStore,
        server_id: Option<i32>,
    ) -> Self {
        Self { store, server_id }
    }

    /// Resolve the application's managed hosting store and server identity.
    pub fn from_state(state: &AppState) -> Result<Self, Status> {
        let hosting = state
            .registry_ref()
            .resolve::<HostingService>()
            .ok_or_else(|| {
                Status::failed_precondition("HostingService is not registered")
            })?;
        let store = hosting.store().map_err(|_| {
            Status::failed_precondition("HostingService is not initialized")
        })?;
        Ok(Self::new(store, hosting.server_id()))
    }
    /// Import local CA material without overwriting existing identities.
    /// Self-signed roots bootstrap a new local issuer; ACME imports use local tooling.
    pub async fn import_certificate(
        &self,
        request: ImportCertificateRequest,
    ) -> Result<TransferInfo, Status> {
        let store = &self.store;
        let server_id = self.server_id;
        let selected = if let Some(name) = request.issuer.as_deref() {
            Some(
                store
                    .issuer_by_name(name)
                    .await
                    .map_err(storage_status)?
                    .ok_or_else(|| {
                        Status::not_found("local certificate issuer not found")
                    })?,
            )
        } else {
            None
        };
        if selected
            .as_ref()
            .is_some_and(|issuer| issuer.kind == IssuerKind::Acme)
        {
            return Err(Status::failed_precondition(
                "ACME certificate import is unavailable through this manager; use the local hosting CLI",
            ));
        }
        let selected_id = selected.as_ref().map(|issuer| issuer.id);
        let issuers = store
            .local_issuer_certificates()
            .await
            .map_err(storage_status)?
            .into_iter()
            .filter(|(id, _)| {
                selected_id.is_none_or(|selected| selected == *id)
            })
            .map(|(id, certs_der)| transfer::IssuerCandidate { id, certs_der })
            .collect::<Vec<_>>();
        let plan = tokio::task::spawn_blocking(move || {
            transfer::plan_import(
                request.certificate_chain_pem.as_bytes(),
                request.private_key_pem.as_bytes(),
                &issuers,
            )
        })
        .await
        .map_err(|_| Status::internal("certificate import task failed"))?
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
        if selected_id.is_some() && plan.issuer_id != selected_id {
            return Err(Status::invalid_argument(
                "selected local issuer does not match the certificate; root imports must omit issuer",
            ));
        }
        if store
            .certificate_by_cn(plan.common_name.as_str())
            .await
            .map_err(storage_status)?
            .is_some()
        {
            return Err(Status::already_exists(
                "certificate CN already exists",
            ));
        }
        let issuer = issuer_name(store, plan.issuer_id).await?;
        let new = NewCertificate {
            kind: plan.kind,
            issuer_id: plan.issuer_id,
            cn: plan.common_name.into(),
            certs_der: plan.certs_der,
            key_der: plan.key_der,
            expires_at: plan.expires_at,
            issued_at: plan.issued_at,
            enabled: true,
        };
        let aliases: Vec<String> = plan.aliases.into();
        let saved = if plan.kind == CertificateKind::Server {
            let id = server_id.ok_or_else(|| {
                Status::failed_precondition(
                    "server identity is not initialized",
                )
            })?;
            store.insert_certificate(new, &aliases, id).await
        } else {
            store.insert_unassigned_certificate(new, &aliases).await
        }
        .map_err(storage_status)?;
        Ok(transfer_info(saved, issuer))
    }

    /// Export by canonical CN; private key material requires explicit opt-in.
    pub async fn export_certificate(
        &self,
        request: ExportCertificateRequest,
    ) -> Result<ExportCertificateResponse, Status> {
        let store = &self.store;
        let saved = store
            .certificate_by_cn(&request.common_name)
            .await
            .map_err(storage_status)?
            .ok_or_else(|| Status::not_found("certificate CN not found"))?;
        let issuer = issuer_name(store, saved.certificate.issuer_id).await?;
        tokio::task::spawn_blocking(move || {
            let chain = formatters::certificate_chain_to_pem(
                &saved.certificate.certs_der,
            )
            .map_err(|_| {
                Status::internal("stored certificate chain is invalid")
            })?;
            let key = if request.include_private_key
                && !saved.certificate.key_der.is_empty()
            {
                Some(
                    transfer::private_key_to_pem(&saved.certificate.key_der)
                        .map_err(|_| {
                            Status::internal("stored private key is invalid")
                        })?,
                )
            } else {
                None
            };
            Ok(ExportCertificateResponse {
                certificate: Some(transfer_info(saved, issuer)),
                certificate_chain_pem: chain,
                private_key_pem: key,
            })
        })
        .await
        .map_err(|_| Status::internal("certificate export task failed"))?
    }
}

fn storage_status(error: HostingError) -> Status {
    match error {
        HostingError::Conflict(_) => Status::already_exists(
            "a certificate with this common name already exists",
        ),
        HostingError::InvalidInput(message) => {
            Status::invalid_argument(message)
        }
        other => {
            tracing::error!(error = %other, "certificate transfer storage failed");
            Status::internal("certificate transfer storage failed")
        }
    }
}

async fn issuer_name(
    store: &HostingStore,
    id: Option<i32>,
) -> Result<Option<String>, Status> {
    let Some(id) = id else { return Ok(None) };
    let issuer = store
        .issuer_by_id(id)
        .await
        .map_err(storage_status)?
        .ok_or_else(|| {
            Status::failed_precondition("certificate issuer no longer exists")
        })?;
    Ok(Some(issuer.name))
}

fn transfer_info(
    saved: HostedCertificate,
    issuer: Option<String>,
) -> TransferInfo {
    let cert = saved.certificate;
    TransferInfo {
        id: cert.id,
        common_name: cert.cn,
        aliases: saved.aliases.into_iter().map(|a| a.hostname).collect(),
        kind: match cert.kind {
            CertificateKind::Server => {
                crate::proto::certificates::CertificateKind::Server as i32
            }
            CertificateKind::Client => {
                crate::proto::certificates::CertificateKind::Client as i32
            }
            CertificateKind::Ca => {
                crate::proto::certificates::CertificateKind::Ca as i32
            }
        },
        issuer,
        issued_at: Some(prost_types::Timestamp {
            seconds: cert.issued_at.unix_timestamp(),
            nanos: cert.issued_at.nanosecond() as i32,
        }),
        expires_at: Some(prost_types::Timestamp {
            seconds: cert.expires_at.unix_timestamp(),
            nanos: cert.expires_at.nanosecond() as i32,
        }),
        enabled: cert.enabled,
    }
}

#[cfg(test)]
#[path = "../../../tests/certificate_manager.rs"]
mod tests;
