use std::{borrow::Cow, collections::{HashMap, HashSet}, sync::Arc};

use actix_web::{dev::ServerHandle, get, web::{self, Data, Payload}, App, HttpRequest, HttpResponse, HttpServer, Responder};
use async_trait::async_trait;
use log::{debug, error, info};
use serde_json::{json, Value};
use xelis_common::{
    api::{wallet::NotifyEvent, EventResult},
    rpc_server::{
        websocket::{WebSocketHandler, WebSocketServer, WebSocketSessionShared},
        Id,
        InternalRpcError,
        RPCHandler,
        RpcResponse,
        RpcResponseError
    },
    tokio::{
        spawn_task,
        sync::{Mutex, RwLock}
    }
};

use crate::config::XSWD_BIND_ADDRESS;
use super::*;

pub struct XSWDServer<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    websocket: Arc<WebSocketServer<XSWDWebSocketHandler<W>>>,
    handle: ServerHandle
}

impl<W> XSWDServer<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    pub fn new(handler: RPCHandler<W>) -> Result<Self, anyhow::Error> {
        let websocket = WebSocketServer::new(XSWDWebSocketHandler::new(handler));
        let this = websocket.clone();
        let http_server = HttpServer::new(move || {
            let server = Arc::clone(&this);
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
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    // All applications connected to the wallet
    applications: RwLock<HashMap<WebSocketSessionShared<Self>, AppStateShared>>,
    // Applications listening for events
    listeners: Mutex<HashMap<WebSocketSessionShared<Self>, HashMap<NotifyEvent, Option<Id>>>>,
    xswd: XSWD<W>,
}

impl<W> XSWDWebSocketHandler<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    pub fn new(handler: RPCHandler<W>) -> Self {
        Self {
            applications: RwLock::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            xswd: XSWD::new(handler),
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

    // register a new application
    // if the application is already registered, it will return an error
    async fn add_application(&self, session: &WebSocketSessionShared<Self>, app_data: ApplicationData) -> Result<Value, RpcResponseError> {
        // Sanity check
        self.xswd.verify_application(self, &app_data).await?;

        let state = Arc::new(AppState::new(app_data));
        {
            let mut applications = self.applications.write().await;
            applications.insert(session.clone(), state.clone());
        }

        self.xswd.add_application(&state).await
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

    // Internal method to handle the message received from the WebSocket connection
    // This method will parse the message and call the appropriate method if app is registered
    // Otherwise, it expects a JSON object with the application data to register it
    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        let app_state = {
            let applications = self.applications.read().await;
            applications.get(session).cloned()
        };

        // Application is already registered, verify permission and call the method
        if let Some(app) = app_state {
            match self.xswd.on_request(self, &app, message).await? {
                OnRequestResult::Return(v) => Ok(v),
                OnRequestResult::Request { request, event, is_subscribe } => {
                    if is_subscribe {
                        self.subscribe_session_to_event(session, event, request.id).await.map(|_| None)
                    } else {
                        self.unsubscribe_session_from_event(session, event, request.id).await.map(|_| None)
                    }
                }
            }
        } else {
            let app_data: ApplicationData = serde_json::from_slice(&message)
                .map_err(|_| RpcResponseError::new(None, XSWDError::InvalidApplicationData))?;

            // Application is not registered, register it
            match self.add_application(session, app_data).await {
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
    }
}

#[async_trait]
impl<W> WebSocketHandler for XSWDWebSocketHandler<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let app = {
            let mut applications = self.applications.write().await;
            applications.remove(session)
        };

        {
            let mut listeners = self.listeners.lock().await;
            listeners.remove(session);
        }

        if let Some(app) = app {
            info!("Application {} has disconnected", app.get_name());
            if app.is_requesting() {
                debug!("Application {} is requesting a permission, aborting...", app.get_name());
                self.xswd.handler().get_data().cancel_request_permission(&app).await?;
            }

            self.xswd.handler().get_data().on_app_disconnect(app).await?;
        }

        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<(), anyhow::Error> {
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

#[async_trait]
impl<W> XSWDProvider for XSWDWebSocketHandler<W>
where
    W: Send + Sync + Clone + XSWDHandler + 'static {
        
    async fn has_app_with_id(&self, id: &str) -> bool {
        let applications = self.applications.read().await;
        applications.values().find(|e| e.get_id() == id).is_some()
    }
}

#[get("/")]
async fn index() -> Result<impl Responder, actix_web::Error> {
    Ok(HttpResponse::Ok().body("XSWD is running !"))
}

async fn endpoint<W>(server: Data<WebSocketServer<XSWDWebSocketHandler<W>>>, request: HttpRequest, body: Payload) -> Result<impl Responder, actix_web::Error>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    let response = server.handle_connection(request, body).await?;
    Ok(response)
}