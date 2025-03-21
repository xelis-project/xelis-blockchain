mod error;
mod types;

use std::{
    borrow::Cow,
    collections::{
        HashMap,
        HashSet
    },
    sync::Arc
};
use anyhow::Error;
use async_trait::async_trait;
use actix_web::{
    get,
    web::{
        Data,
        Payload,
        self,
        Bytes
    },
    HttpRequest,
    Responder,
    HttpServer,
    App,
    dev::ServerHandle,
    HttpResponse
};
use serde_json::{
    Value,
    json
};
use xelis_common::{
    api::{
        wallet::NotifyEvent,
        EventResult
    },
    context::Context,
    crypto::elgamal::PublicKey as DecompressedPublicKey,
    rpc_server::{
        websocket::{
            WebSocketHandler,
            WebSocketServer,
            WebSocketSessionShared
        },
        Id,
        InternalRpcError,
        RPCHandler,
        RpcRequest,
        RpcResponse,
        RpcResponseError
    },
    tokio::{
        spawn_task,
        sync::{
            Mutex,
            RwLock,
            Semaphore
        }
    }
};
use crate::config::XSWD_BIND_ADDRESS;
use log::{
    debug,
    info,
    error,
};

pub use error::XSWDError;
pub use types::*;

// XSWD Protocol (XELIS Secure WebSocket DApp)
// is a way to communicate with the XELIS Wallet
// from a web browser through a secure websocket.
// The idea is that a token is generated on websocket side
// and send through the WS connection to the wallet.
// The wallet then signs the token and send it back to the WS.
// On browser side we can save it in local storage and use it
// to communicate and request data from wallet.
// Each action will require the validation of the user
// based on the permission configured.
// The token is saved also in wallet side for a reminder of
// all applications allowed.
// For security reasons, in case the signed token leaks, at each connection,
// the wallet will request the authorization of the user
// but will keep already-configured permissions.
pub struct XSWD<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    websocket: Arc<WebSocketServer<XSWDWebSocketHandler<W>>>,
    handle: ServerHandle
}

#[async_trait]
pub trait XSWDPermissionHandler {
    // Handler function to request permission to user
    async fn request_permission(&self, app_state: &AppStateShared, request: PermissionRequest<'_>) -> Result<PermissionResult, Error>;
    // Handler function to cancel the request permission from app (app has disconnected)
    async fn cancel_request_permission(&self, app_state: &AppStateShared) -> Result<(), Error>;
    // Public key to use to verify the signature
    async fn get_public_key(&self) -> Result<&DecompressedPublicKey, Error>;
}

#[async_trait]
pub trait XSWDNodeMethodHandler {
    async fn call_node_with(&self, request: RpcRequest) -> Result<Value, RpcResponseError>;
}

impl<W> XSWD<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    pub fn new(rpc_handler: RPCHandler<W>) -> Result<Self, anyhow::Error> {
        info!("Starting XSWD Server...");
        let websocket = WebSocketServer::new(XSWDWebSocketHandler::new(rpc_handler));
        let cloned_websocket = websocket.clone();
        let http_server = HttpServer::new(move || {
            let server = Arc::clone(&cloned_websocket);
            App::new()
                .app_data(Data::from(server))
                .service(index)
                .route("/xswd", web::get().to(endpoint::<W>))
        })
        .disable_signals()
        .bind(&XSWD_BIND_ADDRESS)?
        .run();

        let handle = http_server.handle();
        spawn_task("xswd-server", http_server);

        info!("XSWD is listening on ws://{}", XSWD_BIND_ADDRESS);

        Ok(Self {
            websocket,
            handle
        })
    }

    pub fn get_handler(&self) -> &XSWDWebSocketHandler<W> {
        self.websocket.get_handler()
    }

    pub async fn stop(&self) {
        info!("Stopping XSWD...");
        self.handle.stop(false).await;
        info!("XSWD has been stopped !");
    }
}

pub struct XSWDWebSocketHandler<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    // RPC handler for methods
    handler: RPCHandler<W>,
    // All applications connected to the wallet
    applications: RwLock<HashMap<WebSocketSessionShared<Self>, AppStateShared>>,
    // Applications listening for events
    listeners: Mutex<HashMap<WebSocketSessionShared<Self>, HashMap<NotifyEvent, Option<Id>>>>,
    // This is used to limit to one at a time a permission request
    permission_handler_semaphore: Semaphore
}

impl<W> XSWDWebSocketHandler<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    pub fn new(handler: RPCHandler<W>) -> Self {
        Self {
            handler,
            applications: RwLock::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            permission_handler_semaphore: Semaphore::new(1)
        }
    }

    // This method is used to get the applications HashMap
    // be careful by using it, and if you delete a session, please disconnect it
    pub fn get_applications(&self) -> &RwLock<HashMap<WebSocketSessionShared<Self>, AppStateShared>> {
        &self.applications
    }

    // get a HashSet of all events tracked
    pub async fn get_tracked_events(&self) -> HashSet<NotifyEvent> {
        let sessions = self.listeners.lock().await;
        HashSet::from_iter(sessions.values().map(|e| e.keys().cloned()).flatten())
    }

    // verify if a event is tracked by XSWD
    pub async fn is_event_tracked(&self, event: &NotifyEvent) -> bool {
        let sessions = self.listeners.lock().await;
        sessions
            .values()
            .find(|e| e.keys().into_iter().find(|x| *x == event).is_some())
            .is_some()
    }

    // notify a new event to all connected WebSocket
    pub async fn notify(&self, event: &NotifyEvent, value: Value) {
        let value = json!(EventResult { event: Cow::Borrowed(event), value });
        let sessions = self.listeners.lock().await;
        for (session, subscriptions) in sessions.iter() {
            if let Some(id) = subscriptions.get(event) {
                let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value)));
                let session = session.clone();
                spawn_task("xswd-notify", async move {
                    if let Err(e) = session.send_text(response.to_string()).await {
                        debug!("Error occured while notifying a new event: {}", e);
                    };
                });
            }
        }
    }

    // verify the permission for a request
    // if the permission is not set, it will request it to the user
    async fn verify_permission_for_request(&self, app: &AppStateShared, request: &RpcRequest) -> Result<(), RpcResponseError> {
        let _permit = self.permission_handler_semaphore.acquire().await
            .map_err(|_| RpcResponseError::new(request.id.clone(), InternalRpcError::InternalError("Permission handler semaphore error")))?;
        let mut permissions = app.get_permissions().lock().await;

        // We acquired the lock, lets check that the app is still registered
        if !self.has_app_with_id(app.get_id()).await {
            return Err(RpcResponseError::new(request.id.clone(), XSWDError::ApplicationNotFound))
        }

        let permission = permissions.get(&request.method)
            .copied();

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
                .map_err(|err| RpcResponseError::new(request.id.clone(), InternalRpcError::CustomAny(0, err)))?;

                match result {
                    PermissionResult::Accept => Ok(()),
                    PermissionResult::Reject => Err(RpcResponseError::new(request.id.clone(), XSWDError::PermissionDenied)),
                    PermissionResult::AlwaysAccept => {
                        permissions.insert(request.method.clone(), Permission::Allow);
                        Ok(())
                    },
                    PermissionResult::AlwaysReject => {
                        permissions.insert(request.method.clone(), Permission::Allow);
                        Err(RpcResponseError::new(request.id.clone(), XSWDError::PermissionDenied))
                    }   
                }
            }
        }
    }

    // register a new application
    // if the application is already registered, it will return an error
    async fn add_application(&self, session: &WebSocketSessionShared<Self>, app_data: ApplicationData) -> Result<Value, RpcResponseError> {
        // Sanity check
        debug!("sanity check for add application");
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

                // Check if we have a header origin
                if let Some(origin) = session.get_request().headers().get("Origin") {
                    // We have a header origin, check that its equal to the url passed in param
                    if origin != url {
                        return Err(RpcResponseError::new(None, XSWDError::InvalidOrigin))
                    }
                }
            }

            if app_data.get_permissions().len() > 255 {
                return Err(RpcResponseError::new(None, XSWDError::TooManyPermissions))
            }

            for perm in app_data.get_permissions() {
                if !self.handler.has_method(perm) {
                    debug!("Permission '{}' is unknown", perm);
                    return Err(RpcResponseError::new(None, XSWDError::UnknownMethodInPermissionsList))
                }
            }
        }

        // Verify that this app ID is not already in use
        if self.has_app_with_id(&app_data.get_id()).await {
            return Err(RpcResponseError::new(None, XSWDError::ApplicationIdAlreadyUsed))
        }

        let state = Arc::new(AppState::new(app_data));
        {
            let mut applications = self.applications.write().await;
            applications.insert(session.clone(), state.clone());
        }

        // Request permission to user
        let _permit = self.permission_handler_semaphore.acquire().await
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::InternalError("Permission handler semaphore error")))?;

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
            // Permission was rejected, delete it from our list
            let mut applications = self.applications.write().await;
            applications.remove(session)
                .ok_or_else(|| RpcResponseError::new(None, XSWDError::ApplicationNotFound))?;

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

    // register a new event listener for the specified connection/application
    async fn subscribe_session_to_event(&self, session: &WebSocketSessionShared<Self>, event: NotifyEvent, id: Option<Id>) -> Result<(), RpcResponseError> {
        let mut listeners = self.listeners.lock().await;
        let events = listeners.entry(session.clone()).or_insert_with(HashMap::new);

        if events.contains_key(&event) {
            return Err(RpcResponseError::new(id, InternalRpcError::EventAlreadySubscribed));
        }

        events.insert(event, id);

        Ok(())
    }

    // unregister an event listener for the specified connection/application
    async fn unsubscribe_session_from_event(&self, session: &WebSocketSessionShared<Self>, event: NotifyEvent, id: Option<Id>) -> Result<(), RpcResponseError> {
        let mut listeners = self.listeners.lock().await;
        let events = listeners.get_mut(session).ok_or_else(|| RpcResponseError::new(id.clone(), InternalRpcError::EventNotSubscribed))?;

        if events.remove(&event).is_none() {
            return Err(RpcResponseError::new(id, InternalRpcError::EventNotSubscribed));
        }

        Ok(())
    }

    // Verify if an application is already registered
    // ID must be unique and not used by another application
    async fn has_app_with_id(&self, id: &String) -> bool {
        let applications = self.applications.read().await;
        applications.values().find(|e| e.get_id() == id).is_some()
    }

    // Internal method to handle the message received from the WebSocket connection
    // This method will parse the message and call the appropriate method if app is registered
    // Otherwise, it expects a JSON object with the application data to register it
    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        let (request, is_subscribe, is_unsubscribe) = {
            let app_state = {
                let applications = self.applications.read().await;
                applications.get(session).cloned()
            };

            // Application is already registered, verify permission and call the method
            if let Some(app) = app_state {
                let mut request: RpcRequest = self.handler.parse_request_from_bytes(message)?;
                // Redirect all node methods to the node method handler
                if request.method.starts_with("node.") {
                    // Remove the 5 first chars (node.)
                    request.method = request.method[5..].into();
                    return self.handler.get_data().call_node_with(request).await.map(|v| Some(v))
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
                self.verify_permission_for_request(&app, &request).await?;
                app.set_requesting(false);

                (request, is_subscribe, is_unsubscribe)
            } else {
                let app_data: ApplicationData = serde_json::from_slice(&message)
                    .map_err(|_| RpcResponseError::new(None, XSWDError::InvalidApplicationData))?;

                // Application is not registered, register it
                return match self.add_application(session, app_data).await {
                    Ok(v) => Ok(Some(v)),
                    Err(e) => {
                        debug!("Error while adding application: {}", e);
                        if !session.is_closed().await {
                            // Send error message and then close the session
                            if let Err(e) = session.send_text(&e.to_json().to_string()).await {
                                error!("Error while sending error message to session: {}", e);
                            }
                        }

                        if let Err(e) = session.close(None).await {
                            error!("Error while closing session: {}", e);
                        }

                        Ok(None)
                    }
                }
            }
        };

        if is_subscribe || is_unsubscribe {
            // retrieve the event variant
            let event = serde_json::from_value(
                request.params.ok_or_else(|| RpcResponseError::new(request.id.clone(), InternalRpcError::ExpectedParams))?)
                .map_err(|e| RpcResponseError::new(request.id.clone(), InternalRpcError::InvalidJSONParams(e))
            )?;
            if is_subscribe {
                self.subscribe_session_to_event(session, event, request.id).await.map(|_| None)
            } else {
                self.unsubscribe_session_from_event(session, event, request.id).await.map(|_| None)
            }
        } else {
            // Call the method
            let mut context = Context::default();
            context.store(self.handler.get_data().clone());
            // Store the session
            context.store(session.clone());
            self.handler.execute_method(&context, request).await
        }
    }
}

#[async_trait]
impl<W> WebSocketHandler for XSWDWebSocketHandler<W>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let mut applications = self.applications.write().await;
        if let Some(app) = applications.remove(session) {            
            info!("Application {} has disconnected", app.get_name());
            if app.is_requesting() {
                debug!("Application {} is requesting a permission, aborting...", app.get_name());
                self.handler.get_data().cancel_request_permission(&app).await?;
            }
        }

        let mut listeners = self.listeners.lock().await;
        listeners.remove(session);

        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: Bytes) -> Result<(), anyhow::Error> {
        let response: Value = match self.on_message_internal(&session, &message).await {
            Ok(result) => match result {
                Some(v) => v,
                None => return Ok(()),
            },
            Err(e) => e.to_json(),
        };

        session.send_text(response.to_string()).await?;
        Ok(())
    }
}

#[get("/")]
async fn index() -> Result<impl Responder, actix_web::Error> {
    Ok(HttpResponse::Ok().body("XSWD is running !"))
}

async fn endpoint<W>(server: Data<WebSocketServer<XSWDWebSocketHandler<W>>>, request: HttpRequest, body: Payload) -> Result<impl Responder, actix_web::Error>
where
    W: Clone + Send + Sync + XSWDPermissionHandler + XSWDNodeMethodHandler + 'static
{
    let response = server.handle_connection(request, body).await?;
    Ok(response)
}