mod error;
mod types;
mod server;

pub use server::*;

use anyhow::Error;
use async_trait::async_trait;
use serde_json::{
    Value,
    json
};
use xelis_common::{
    crypto::elgamal::PublicKey as DecompressedPublicKey,
    rpc_server::{
        InternalRpcError,
        RPCHandler,
        RpcRequest,
        RpcResponseError
    },
    tokio::sync::Semaphore
};
use log::debug;

pub use error::XSWDError;
pub use types::*;

// XSWD Protocol (XELIS Secure WebSocket DApp)
// is a way to communicate with the XELIS Wallet
// from a web browser through a websocket.
// XSWD is exactly as the JSON RPC api
// but an application must authenticate itself first
// by providing all the required permissions
// Also, each permission will be re-asked to the user
// to ensure he is validating each action.
pub struct XSWD {
    // websocket: Arc<WebSocketServer<XSWDWebSocketHandler<W>>>,
    // This is used to limit to one at a time a permission request
    semaphore: Semaphore
}

#[async_trait]
pub trait XSWDHandler {
    // Handler function to request permission to user
    async fn request_permission(&self, app_state: &AppStateShared, request: PermissionRequest<'_>) -> Result<PermissionResult, Error>;

    // Handler function to cancel the request permission from app (app has disconnected)
    async fn cancel_request_permission(&self, app_state: &AppStateShared) -> Result<(), Error>;

    // Public key to use to verify the signature
    async fn get_public_key(&self) -> Result<&DecompressedPublicKey, Error>;

    // Call a node RPC method through the wallet current connection
    async fn call_node_with(&self, request: RpcRequest) -> Result<Value, RpcResponseError>;

    // When an application has disconnected
    async fn on_app_disconnect(&self, app_state: AppStateShared) -> Result<(), Error>;
}

#[async_trait]
pub trait XSWDProvider {
    async fn has_app_with_id(&self, id: &str) -> bool;
}

impl XSWD {
    pub fn new() -> Self {
        Self {
            semaphore: Semaphore::new(1)
        }
    }

    pub async fn verify_application<W, P>(&self, provider: &P, handler: &RPCHandler<W>, app_data: &ApplicationData) -> Result<(), RpcResponseError>
    where
        W: Clone + Send + Sync + 'static,
        P: XSWDProvider,
    {
        if app_data.get_id().len() != 64 {
            return Err(RpcResponseError::new(None, XSWDError::InvalidApplicationId))
        }

        hex::decode(&app_data.get_id())
            .map_err(|_| RpcResponseError::new(None, XSWDError::InvalidHexaApplicationId))?;

        if app_data.get_name().len() > 32 {
            return Err(RpcResponseError::new(None, XSWDError::ApplicationNameTooLong))
        }

        if app_data.get_description().len() > 255 {
            return Err(RpcResponseError::new(None, XSWDError::ApplicationDescriptionTooLong))
        }

        if let Some(url) = &app_data.get_url() {
            if url.len() > 255 {
                return Err(RpcResponseError::new(None, XSWDError::InvalidURLFormat))
            }

            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(RpcResponseError::new(None, XSWDError::InvalidURLFormat))
            }
        }

        if app_data.get_permissions().len() > 255 {
            return Err(RpcResponseError::new(None, XSWDError::TooManyPermissions))
        }

        for perm in app_data.get_permissions() {
            if !handler.has_method(perm) {
                debug!("Permission '{}' is unknown", perm);
                return Err(RpcResponseError::new(None, XSWDError::UnknownMethodInPermissionsList))
            }
        }

        // Verify that this app ID is not already in use
        if provider.has_app_with_id(&app_data.get_id()).await {
            return Err(RpcResponseError::new(None, XSWDError::ApplicationIdAlreadyUsed))
        }

        Ok(())
    }

    pub async fn add_application<W>(&self, handler: &RPCHandler<W>, state: &AppStateShared) -> Result<Value, RpcResponseError>
    where
        W: Clone + Send + Sync + XSWDHandler + 'static
    {
        // Request permission to user
        let _permit = self.semaphore.acquire().await
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::InternalError("Permission handler semaphore error")))?;

        let wallet = handler.get_data();
        state.set_requesting(true);
        let permission = match wallet.request_permission(&state, PermissionRequest::Application).await {
            Ok(v) => v,
            Err(e) => {
                debug!("Error while requesting permission: {}", e);
                PermissionResult::Reject
            }
        };
        state.set_requesting(false);

        if !permission.is_positive() {
            return Err(RpcResponseError::new(None, XSWDError::PermissionDenied))
        }

        Ok(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "result": {
                "message": "Application has been registered",
                "success": true
            }
        }))
    }

    // verify the permission for a request
    // if the permission is not set, it will request it to the user
    async fn verify_permission_for_request<W, P>(&self, provider: &P, handler: &RPCHandler<W>, app: &AppStateShared, request: &RpcRequest) -> Result<(), RpcResponseError>
    where
        W: Clone + Send + Sync + XSWDHandler + 'static,
        P: XSWDProvider,
    {
        let _permit = self.semaphore.acquire().await
            .map_err(|_| RpcResponseError::new(request.id.clone(), InternalRpcError::InternalError("Permission handler semaphore error")))?;

        // We acquired the lock, lets check that the app is still registered
        if !provider.has_app_with_id(app.get_id()).await {
            return Err(RpcResponseError::new(request.id.clone(), XSWDError::ApplicationNotFound))
        }

        let permission = {
            let permissions = app.get_permissions().lock().await;
            permissions.get(&request.method)
                .copied()
        };

        match permission {
            // If the permission wasn't mentionned at AppState creation
            // It is directly rejected
            None =>  Err(RpcResponseError::new(request.id.clone(), XSWDError::PermissionInvalid)),
            // User has already accepted this method
            Some(Permission::Allow) => Ok(()),
            // User has denied access to this method
            Some(Permission::Reject) => Err(RpcResponseError::new(request.id.clone(), XSWDError::PermissionDenied)),
            // Request permission from user
            Some(Permission::Ask) => {
                let result = handler.get_data()
                    .request_permission(app, PermissionRequest::Request(request)).await
                    .map_err(|err| RpcResponseError::new(request.id.clone(), InternalRpcError::CustomAny(0, err)))?;

                match result {
                    PermissionResult::Accept => Ok(()),
                    PermissionResult::Reject => Err(RpcResponseError::new(request.id.clone(), XSWDError::PermissionDenied)),
                    PermissionResult::AlwaysAccept => {
                        let mut permissions = app.get_permissions().lock().await;
                        permissions.insert(request.method.clone(), Permission::Allow);
                        Ok(())
                    },
                    PermissionResult::AlwaysReject => {
                        let mut permissions = app.get_permissions().lock().await;
                        permissions.insert(request.method.clone(), Permission::Allow);
                        Err(RpcResponseError::new(request.id.clone(), XSWDError::PermissionDenied))
                    }   
                }
            }
        }
    }
}
