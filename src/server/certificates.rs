//! gRPC adapter for the shared certificate manager.
use claviron::runtime::AppState;
use tonic::{Request, Response, Status};

use super::management::certificates::CertificateManager;
use crate::proto::certificates::certificate_transfer_server::{
    CertificateTransfer, CertificateTransferServer,
};
use crate::proto::certificates::{
    CertificateInfo, ExportCertificateRequest, ExportCertificateResponse,
    ImportCertificateRequest,
};

pub(crate) struct TransferService {
    state: AppState,
}
pub(crate) fn create_certificate_transfer(
    state: AppState
) -> CertificateTransferServer<TransferService> {
    CertificateTransferServer::new(TransferService { state })
}

#[tonic::async_trait]
impl CertificateTransfer for TransferService {
    async fn import_certificate(
        &self,
        request: Request<ImportCertificateRequest>,
    ) -> Result<Response<CertificateInfo>, Status> {
        CertificateManager::from_state(&self.state)?
            .import_certificate(request.into_inner())
            .await
            .map(Response::new)
    }
    async fn export_certificate(
        &self,
        request: Request<ExportCertificateRequest>,
    ) -> Result<Response<ExportCertificateResponse>, Status> {
        CertificateManager::from_state(&self.state)?
            .export_certificate(request.into_inner())
            .await
            .map(Response::new)
    }
}
