mod error;
mod types;
mod relayer;

use anyhow::{Context as _, Error};
use async_trait::async_trait;
use indexmap::IndexMap;
use serde_json::{
    Value,
    json
};
use xelis_common::{
    error::ErrorWithKind,
    api::{
        wallet::{NotifyEvent, XSWDPrefetchPermissions},
        daemon::NotifyEvent as DaemonNotifyEvent
    },
    async_handler,
    crypto::elgamal::PublicKey as DecompressedPublicKey,
    rpc::*,
    tokio::sync::{Semaphore, broadcast}
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
    W: ShareableTid<'static> + XSWDHandler
{
    // Event manager per application
    events: Events<AppStateShared, NotifyEvent>,
    handler: RPCHandler<W>,
    // This is used to limit to one at a time a permission request
    semaphore: Semaphore
}

pub enum XSWDResponse {
    Request(Option<Value>),
    Event(DaemonNotifyEvent, Option<(broadcast::Receiver<Value>, Option<Id>)>, Option<Value>)
}

#[async_trait]
pub trait XSWDHandler {
    // Handler function to request permission to user
    async fn request_permission(&self, app_state: &AppStateShared, request: PermissionRequest<'_>) -> Result<PermissionResult, ErrorWithKind>;

    // Handler function to cancel the request permission from app (app has disconnected)
    async fn cancel_request_permission(&self, app_state: &AppStateShared) -> Result<(), ErrorWithKind>;

    // Public key to use to verify the signature
    async fn get_public_key(&self) -> Result<&DecompressedPublicKey, ErrorWithKind>;

    // Call a node RPC method through the wallet current connection
    async fn call_node_with(&self, app_state: &AppStateShared, request: RpcRequest) -> Result<XSWDResponse, RpcResponseError>;

    // When an application has disconnected
    async fn on_app_disconnect(&self, app_state: AppStateShared) -> Result<(), Error>;

    // On grouped permissions request
    // This is optional and can be ignored by default
    async fn on_prefetch_permissions_request(&self, _: &AppStateShared, _: XSWDPrefetchPermissions) -> Result<IndexMap<String, Permission>, Error> {
        Ok(IndexMap::new())
    }
}

#[async_trait]
pub trait XSWDProvider {
    async fn has_app_with_id(&self, id: &str) -> bool;
}

impl<W> XSWD<W>
where
    W: ShareableTid<'static> + XSWDHandler
{
    /// Create a new XSWD instance with the given RPC handler
    pub fn new(mut handler: RPCHandler<W>) -> Self {
        // Register internal methods
        handler.register_method_with_params("xswd.prefetch_permissions", async_handler!(prefetch_permissions::<W>));

        Self {
            events: Events::new(&mut handler),
            handler,
            semaphore: Semaphore::new(1)
        }
    }

    /// Get the RPC handler
    #[inline(always)]
    pub fn handler(&self) -> &RPCHandler<W> {
        &self.handler
    }

    /// Events manager
    #[inline(always)]
    pub fn events(&self) -> &Events<AppStateShared, NotifyEvent> {
        &self.events
    }

    /// Verify the application data
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
            let trimmed_perm = if perm.starts_with("wallet.") {
                &perm[7..]
            } else {
                perm.as_str()
            };

            if !self.handler.has_method(trimmed_perm) {
                debug!("Permission '{}' is unknown", perm);
                return Err(XSWDError::UnknownMethodInPermissionsList(perm.clone()))
            }
        }

        // Verify that this app ID is not already in use
        if provider.has_app_with_id(&app_data.get_id()).await {
            return Err(XSWDError::ApplicationIdAlreadyUsed)
        }

        Ok(())
    }

    pub async fn add_application(&self, state: &AppStateShared) -> Result<Value, XSWDError> {
        debug!("Adding application {} with id {}", state.get_name(), state.get_id());
        // Request permission to user
        let _permit = self.semaphore.acquire().await
            .map_err(|_| XSWDError::SemaphoreError)?;

        debug!("Requesting permission for application {}", state.get_name());

        let wallet = self.handler.get_data();
        state.set_requesting(true);
        let permission = match wallet.request_permission(&state, PermissionRequest::Application).await {
            Ok(v) => v,
            Err(e) => {
                debug!("Error while requesting permission: {}", e.error);
                PermissionResult::Reject
            }
        };
        state.set_requesting(false);

        debug!("Permission result acquired for application {}", state.get_name());

        if !permission.is_positive() {
            return Err(XSWDError::PermissionDenied)
        }

        Ok(json!({
            "jsonrpc": "2.0",
            "id": state.get_id(),
            "result": {
                "message": "Application has been registered",
                "success": true
            }
        }))
    }

    pub async fn on_request<P>(&self, provider: &P, app: &AppStateShared, message: &[u8]) -> Result<XSWDResponse, RpcResponseError>
    where
        P: XSWDProvider
    {
        let mut request = parse_request_from_bytes(message)?;
        // Redirect all node methods to the node method handler
        if request.method.starts_with("node.") {
            // Remove the 5 first chars (node.)
            request.method = request.method[5..].into();
            return self.handler.get_data().call_node_with(app, request).await
        }

        // Verify that the method start with "wallet."
        if request.method.starts_with("wallet.") {
            request.method = request.method[7..].into();
        }

        if !self.handler.has_method(&request.method) {
            return Err(RpcResponseError::new(request.id, InternalRpcError::MethodNotFound(request.method)))
        }

        // let's check the permission set by user for this method
        // Special case: internal xswd methods are always allowed
        if !request.method.starts_with("xswd.") {
            app.set_requesting(true);
            self.verify_permission_for_request(provider, &app, &request).await
                .map_err(|e| RpcResponseError::new(request.id.clone(), e))?;
            app.set_requesting(false);
        }

        Ok(XSWDResponse::Request(self.execute_method(app, request).await))
    }

    pub async fn on_close(&self, app: AppStateShared) -> Result<(), Error> {
        info!("Application {} has disconnected", app.get_name());
        if app.is_requesting() {
            debug!("Application {} is requesting a permission, aborting...", app.get_name());
            self.handler.get_data().cancel_request_permission(&app).await?;
            debug!("Permission request for application {} has been cancelled", app.get_name());
        }

        self.events.on_close(&app).await;

        self.handler.get_data().on_app_disconnect(app).await
    }

    pub async fn execute_method(&self, app: &AppStateShared, request: RpcRequest) -> Option<Value> {
        // Call the method
        let mut context = Context::default();
        context.insert_ref(&self.handler);
        // Store the app id
        context.insert_ref(app);
        // store the events manager
        context.insert_ref(&self.events);

        self.handler.execute_method(&mut context, request).await
    }

    // verify the permission for a request
    // if the permission is not set, it will request it to the user
    async fn verify_permission_for_request<P>(&self, provider: &P, app: &AppStateShared, request: &RpcRequest) -> Result<(), InternalRpcError>
    where
        P: XSWDProvider,
    {
        let _permit = self.semaphore.acquire().await
            .map_err(|_| InternalRpcError::InternalError("Permission handler semaphore error"))?;

        // We acquired the lock, lets check that the app is still registered
        if !provider.has_app_with_id(app.get_id()).await {
            return Err(XSWDError::ApplicationNotFound.into())
        }

        let permission = {
            let permissions = app.get_permissions().lock().await;
            permissions.get(&request.method)
                .copied()
        };

        debug!("permission for method '{}' is '{:?}'", request.method, permission);
        match permission {
            // If the permission wasn't mentionned at AppState creation
            // It is directly rejected
            None =>  Err(XSWDError::PermissionUnknown.into()),
            // User has already accepted this method
            Some(Permission::Allow) => Ok(()),
            // User has denied access to this method
            Some(Permission::Reject) => Err(XSWDError::PermissionDenied.into()),
            // Request permission from user
            Some(Permission::Ask) => {
                let result = self.handler.get_data()
                    .request_permission(app, PermissionRequest::Request(request)).await?;

                debug!("Permission request result for method '{}' is '{:?}'", request.method, result);

                match result {
                    PermissionResult::Accept => Ok(()),
                    PermissionResult::Reject => Err(XSWDError::PermissionDenied.into()),
                    PermissionResult::AlwaysAccept => {
                        let mut permissions = app.get_permissions().lock().await;
                        permissions.insert(request.method.clone(), Permission::Allow);
                        Ok(())
                    },
                    PermissionResult::AlwaysReject => {
                        let mut permissions = app.get_permissions().lock().await;
                        permissions.insert(request.method.clone(), Permission::Allow);
                        Err(XSWDError::PermissionDenied.into())
                    }   
                }
            }
        }
    }
}

/// Internal RPC method used by XSWD
/// To request in one time the permissions
pub async fn prefetch_permissions<W: ShareableTid<'static> + XSWDHandler>(context: &Context<'_, '_>, params: XSWDPrefetchPermissions) -> Result<bool, InternalRpcError> {
    if params.permissions.is_empty() {
        return Err(InternalRpcError::InvalidParams("Permissions list cannot be empty"))
    }

    let handler: &RPCHandler<W> = context.get()
        .context("XSWD RPC Handler not found in context")?;
    let app: &AppStateShared = context.get()
        .context("XSWD App State not found in context")?;

    if params.permissions.is_empty() {
        return Err(InternalRpcError::InvalidParams("No permissions requested"))
    }

    if params.permissions.len() > 255 {
        return Err(InternalRpcError::InvalidParams("Too many permissions requested"))
    }

    {
        let lock = app.get_permissions().lock().await;
        for perm in params.permissions.iter() {
            if !lock.contains_key(perm) {
                debug!("Permission '{}' is unknown", perm);
                return Err(InternalRpcError::InvalidParams("Unknown method in permissions list"))
            }
        }
    }

    let wallet = handler.get_data();

    app.set_requesting(true);
    let res = wallet.on_prefetch_permissions_request(app, params).await?;

    if !res.is_empty() {
        let mut permissions = app.get_permissions().lock().await;
        for (method, perm) in res {
            permissions.insert(method, perm);
        }
    }
    app.set_requesting(false);

    Ok(true)
}