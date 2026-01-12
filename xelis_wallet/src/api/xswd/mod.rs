mod error;
mod types;
mod relayer;

use std::borrow::Cow;

use anyhow::Error;
use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::{
    Value,
    json
};
use xelis_common::{
    api::wallet::NotifyEvent,
    context::Context,
    crypto::elgamal::PublicKey as DecompressedPublicKey,
    rpc::{
        InternalRpcError,
        RPCHandler,
        RpcRequest,
        RpcResponse,
        RpcResponseError
    },
    tokio::sync::Semaphore
};
use log::{debug, info};

pub use error::XSWDError;
pub use types::*;
pub use relayer::{XSWDRelayer, XSWDRelayerShared};

// XSWD Protocol (XELIS Secure WebSocket DApp)
// is a way to communicate with the XELIS Wallet
// from a web browser through a websocket.
// XSWD is exactly as the JSON RPC api
// but an application must authenticate itself first
// by providing all the required permissions
// Also, each permission will be re-asked to the user
// to ensure he is validating each action.
pub struct XSWD<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static {
    handler: RPCHandler<W>,
    // This is used to limit to one at a time a permission request
    semaphore: Semaphore
}

// WASM doesn't support Send bounds (single-threaded)
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
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

    // On grouped permissions request
    // This is optional and can be ignored by default
    async fn on_prefetch_permissions_request(&self, _: &AppStateShared, _: InternalPrefetchPermissions) -> Result<IndexMap<String, Permission>, Error> {
        Ok(IndexMap::new())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait XSWDProvider {
    async fn has_app_with_id(&self, id: &str) -> bool;
}

pub enum OnRequestResult {
    Return(Option<Value>),
    Request {
        request: RpcRequest,
        event: NotifyEvent,
        is_subscribe: bool,
    }
}

impl<W> XSWD<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    pub fn new(handler: RPCHandler<W>) -> Self {
        Self {
            handler,
            semaphore: Semaphore::new(1)
        }
    }

    pub fn handler(&self) -> &RPCHandler<W> {
        &self.handler
    }

    pub async fn verify_application<P>(&self, provider: &P, app_data: &ApplicationData) -> Result<(), XSWDError>
    where
        P: XSWDProvider,
    {
        if app_data.get_id().len() != 64 {
            return Err(XSWDError::InvalidApplicationId)
        }

        hex::decode(&app_data.get_id())
            .map_err(|_| XSWDError::InvalidHexaApplicationId)?;

        if app_data.get_name().len() > 32 {
            return Err(XSWDError::ApplicationNameTooLong)
        }

        if app_data.get_description().len() > 255 {
            return Err(XSWDError::ApplicationDescriptionTooLong)
        }

        if let Some(url) = &app_data.get_url() {
            if url.len() > 255 {
                return Err(XSWDError::InvalidURLFormat)
            }

            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(XSWDError::InvalidURLFormat)
            }
        }

        if app_data.get_permissions().len() > 255 {
            return Err(XSWDError::TooManyPermissions)
        }

        for perm in app_data.get_permissions() {
            if !self.handler.has_method(perm) {
                debug!("Permission '{}' is unknown", perm);
                return Err(XSWDError::UnknownMethodInPermissionsList)
            }
        }

        // Verify that this app ID is not already in use
        if provider.has_app_with_id(&app_data.get_id()).await {
            return Err(XSWDError::ApplicationIdAlreadyUsed)
        }

        Ok(())
    }

    pub async fn add_application(&self, state: &AppStateShared) -> Result<Value, XSWDError> {
        // Request permission to user
        let _permit = self.semaphore.acquire().await
            .map_err(|_| XSWDError::SemaphoreError)?;

        let wallet = self.handler.get_data();
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
            return Err(XSWDError::PermissionDenied)
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

    async fn on_internal_request(&self, app: &AppStateShared, mut request: RpcRequest) -> Result<OnRequestResult, RpcResponseError> {
        let _permit = self.semaphore.acquire().await
            .map_err(|_| RpcResponseError::new(request.id.clone(), InternalRpcError::InternalError("Permission handler semaphore error")))?;

        match request.method.as_str() {
            "prefetch_permissions" => {
                let wallet = self.handler.get_data();
                let params = request.params
                    .ok_or_else(|| RpcResponseError::new(request.id.take(), InternalRpcError::ExpectedParams))?;
                let params: InternalPrefetchPermissions = serde_json::from_value(params)
                    .map_err(|e| RpcResponseError::new(request.id.take(), InternalRpcError::InvalidJSONParams(e)))?;

                if params.permissions.is_empty() {
                    return Err(RpcResponseError::new(request.id.take() , InternalRpcError::InvalidParams("Permissions list cannot be empty".into())))
                }

                app.set_requesting(true);
                let res = wallet.on_prefetch_permissions_request(app, params).await
                    .map_err(|e| RpcResponseError::new(request.id.take(), e))?;

                if !res.is_empty() {
                    let mut permissions = app.get_permissions().lock().await;
                    for (method, perm) in res {
                        permissions.insert(method, perm);
                    }
                }
                app.set_requesting(false);

                Ok(OnRequestResult::Return(if request.id.is_some() {
                    Some(json!(RpcResponse::new(Cow::Owned(request.id), Cow::Owned(Value::Bool(true)))))
                } else {
                    None
                }))
            },
            _ => Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        }
    }

    pub async fn on_request<P>(&self, provider: &P, app: &AppStateShared, message: &[u8]) -> Result<OnRequestResult, RpcResponseError>
    where
        P: XSWDProvider
    {
        let mut request = self.handler.parse_request_from_bytes(message)?;
        // Redirect all node methods to the node method handler
        if request.method.starts_with("node.") {
            // Remove the 5 first chars (node.)
            request.method = request.method[5..].into();
            return self.handler.get_data().call_node_with(request).await.map(|v| OnRequestResult::Return(Some(v)))
        }

        if request.method.starts_with("xswd.") {
            request.method = request.method[5..].into();
            return self.on_internal_request(app, request).await
        }

        // Verify that the method start with "wallet."
        if !request.method.starts_with("wallet.") {
            return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        }
        request.method = request.method[7..].into();

        // Verify first if the method exist (and that its not a built-in one)
        let is_subscribe = request.method == "subscribe";
        let is_unsubscribe = request.method == "unsubscribe";
        if !self.handler.has_method(&request.method) && !is_subscribe && !is_unsubscribe {
            return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        }

        // let's check the permission set by user for this method
        app.set_requesting(true);
        self.verify_permission_for_request(provider, &app, &request).await?;
        app.set_requesting(false);

        if !is_subscribe && !is_unsubscribe {
            return self.execute_method(app.id(), request).await.map(OnRequestResult::Return)
        }

        let event = serde_json::from_value(
            request.params.take()
                .ok_or_else(|| RpcResponseError::new(request.id.clone(), InternalRpcError::ExpectedParams))?)
            .map_err(|e| RpcResponseError::new(request.id.clone(), InternalRpcError::InvalidJSONParams(e))
        )?;

        Ok(OnRequestResult::Request { event, request, is_subscribe })
    }

    pub async fn on_close(&self, app: AppStateShared) -> Result<(), Error> {
        info!("Application {} has disconnected", app.get_name());
        if app.is_requesting() {
            debug!("Application {} is requesting a permission, aborting...", app.get_name());
            self.handler.get_data().cancel_request_permission(&app).await?;
        }

        self.handler.get_data().on_app_disconnect(app).await
    }

    pub async fn execute_method(&self, id: XSWDAppId, request: RpcRequest) -> Result<Option<Value>, RpcResponseError> {
        // Call the method
        let mut context = Context::default();
        context.store(self.handler.get_data().clone());
        // Store the app id
        context.store(id);
        self.handler.execute_method(&context, request).await
    }

    // verify the permission for a request
    // if the permission is not set, it will request it to the user
    pub async fn verify_permission_for_request<P>(&self, provider: &P, app: &AppStateShared, request: &RpcRequest) -> Result<(), RpcResponseError>
    where
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
                let result = self.handler.get_data()
                    .request_permission(app, PermissionRequest::Request(request)).await
                    .map_err(|err| RpcResponseError::new(request.id.clone(), InternalRpcError::AnyError(err)))?;

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
