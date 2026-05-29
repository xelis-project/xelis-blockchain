use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc
};

use actix_web::{
    dev::ServerHandle,
    get,
    web::{self, Data, Payload},
    App,
    HttpRequest,
    HttpResponse,
    HttpServer,
    Responder
};
use async_trait::async_trait;
use futures::{StreamExt, stream};
use log::{debug, error, info};
use serde_json::{json, Value};
use xelis_common::{
    api::{
        EventResult,
        daemon::NotifyEvent as DaemonNotifyEvent,
        wallet::NotifyEvent
    },
    rpc::{
        RPCHandler,
        RpcResponse,
        RpcResponseError,
        ShareableTid,
        server::websocket::{WebSocketHandler, WebSocketServer, WebSocketSessionShared}
    },
    tokio::{
        spawn_task,
        sync::RwLock,
        task
    }
};

use crate::{
    api::{
        AppState,
        AppStateShared,
        ApplicationData,
        XSWDError,
        XSWDProvider,
        XSWDHandler,
        XSWD,
        XSWDResponse,
    },
    config::XSWD_BIND_ADDRESS
};

pub struct XSWDServer<W>
where
    W: ShareableTid<'static> + XSWDHandler
{
    websocket: Arc<WebSocketServer<XSWDWebSocketHandler<W>>>,
    handle: ServerHandle
}

impl<W> XSWDServer<W>
where
    W: ShareableTid<'static> + XSWDHandler
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
    W: ShareableTid<'static> + XSWDHandler
{
    // All applications connected to the wallet
    applications: RwLock<HashMap<WebSocketSessionShared<Self>, AppStateShared>>,
    node_events: RwLock<HashMap<DaemonNotifyEvent, HashMap<AppStateShared, task::JoinHandle<()>>>>,
    xswd: XSWD<W>,
}

impl<W> XSWDWebSocketHandler<W>
where
    W: ShareableTid<'static> + XSWDHandler
{
    // Create a new XSWD WebSocket handler
    #[inline]
    pub fn new(handler: RPCHandler<W>) -> Self {
        Self {
            applications: RwLock::new(HashMap::new()),
            xswd: XSWD::new(handler),
            node_events: RwLock::new(HashMap::new()),
        }
    }

    // This method is used to get the applications HashMap
    // be careful by using it, and if you delete a session, please disconnect it
    #[inline(always)]
    pub fn get_applications(&self) -> &RwLock<HashMap<WebSocketSessionShared<Self>, AppStateShared>> {
        &self.applications
    }

    // get a HashSet of all events tracked
    #[inline(always)]
    pub async fn get_tracked_events(&self) -> HashSet<NotifyEvent> {
        self.xswd.events().get_tracked_events().await
    }

    // verify if a event is tracked by XSWD
    #[inline(always)]
    pub async fn is_event_tracked(&self, event: &NotifyEvent) -> bool {
        self.xswd.events().is_event_tracked(event).await
    }

    // notify a new event to all connected WebSocket
    pub async fn notify(&self, event: &NotifyEvent, value: Value) {
        let value = json!(EventResult { event: Cow::Borrowed(event), value });
        let apps = self.xswd.events().sessions().await;

        let sessions = self.applications.read().await;
        let sessions = &sessions;
        let value = &value;
        stream::iter(apps)
            .for_each_concurrent(None, |(app, subscriptions)| async move {
                if let Some(id) = subscriptions.get(event) {
                    let response = RpcResponse::new(Cow::Borrowed(id), Cow::Borrowed(value));
                    let response = &response;

                    stream::iter(sessions.iter()
                        .filter(|(_, state)| Arc::ptr_eq(state, &app)))
                        .for_each(|(session, _)| async move {
                            if let Err(e) = session.send_json(response).await {
                                error!("Error while sending event notification to session: {}", e);
                            }
                        }).await;
                }
            })
            .await;
    }

    // register a new application
    // if the application is already registered, it will return an error
    async fn add_application(&self, session: &WebSocketSessionShared<Self>, app_data: ApplicationData) -> Result<Value, RpcResponseError> {
        debug!("Adding application {} with id {}", app_data.get_name(), app_data.get_id());

        // Sanity check
        self.xswd.verify_application(self, &app_data).await
            .map_err(|e| RpcResponseError::new(None, e))?;

        debug!("Application {} passed verification", app_data.get_name());

        let state = Arc::new(AppState::new(app_data));

        let response = self.xswd.add_application(&state).await
            .map_err(|e| RpcResponseError::new(None, e))?;

        {
            let mut applications = self.applications.write().await;
            applications.insert(session.clone(), state.clone());
        }

        debug!("Application {} has been added to the applications list", state.get_name());
        Ok(response)
    }

    // Internal method to handle the message received from the WebSocket connection
    // This method will parse the message and call the appropriate method if app is registered
    // Otherwise, it expects a JSON object with the application data to register it
    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        debug!("on message internal");
        let app_state = {
            let applications = self.applications.read().await;
            applications.get(session).cloned()
        };

        // Application is already registered, verify permission and call the method
        if let Some(app) = app_state {
            debug!("Application {} is already registered, handling request...", app.get_name());
            match self.xswd.on_request(self, &app, message).await? {
                XSWDResponse::Request(v) => Ok(v),
                XSWDResponse::Event(event, stream, response) => {
                    let mut events = self.node_events.write().await;
                    let apps = events.entry(event)
                        .or_insert_with(HashMap::new);

                    match stream {
                        Some((mut stream, id), ) => {
                            if !apps.contains_key(&app) {
                                let session = session.clone();
                                let handle = spawn_task("xswd-event-listener", async move {
                                    while let Ok(value) = stream.recv().await {
                                        // we need to map the result to the requested id
                                        let response = RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value));
                                        if let Err(e) = session.send_json(response).await {
                                            error!("Error while sending event notification to session: {}", e);
                                            break;
                                        }
                                    }
                                });

                                apps.insert(app.clone(), handle);
                            }
                        },
                        None => {
                            if let Some(handle) = apps.remove(&app) {
                                handle.abort();
                            }
                        },
                    };

                    Ok(response)
                }
            }
        } else {
            debug!("Application is not registered, registering it...");
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
    W: ShareableTid<'static> + XSWDHandler
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let app = {
            let mut applications = self.applications.write().await;
            applications.remove(session)
        };

        if let Some(app) = app {
            self.xswd.on_close(app).await?;
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
    W: ShareableTid<'static> + XSWDHandler
{
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
    W: ShareableTid<'static> + XSWDHandler
{
    let response = server.handle_connection(request, body).await?;
    Ok(response)
}