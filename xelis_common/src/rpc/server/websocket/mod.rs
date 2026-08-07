mod handler;
mod http_request;

use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
        Mutex as StdMutex
    },
    time::{Duration, Instant}
};
use actix_web::{
    HttpRequest as ActixHttpRequest, HttpResponse, error::{ErrorBadGateway, ErrorInternalServerError}, web::Payload
};
use actix_ws::{
    AggregatedMessage,
    AggregatedMessageStream,
    CloseCode,
    CloseReason,
    Session
};
use async_trait::async_trait;
use futures_util::StreamExt;
use log::{debug, error, trace};
use serde::Serialize;
use serde_json::json;
use runtime_context::tid;
use crate::{
    config::MAX_BLOCK_SIZE,
    immutable::Immutable,
    tokio::{
        Executor,
        select,
        sync::{
            OwnedSemaphorePermit,
            Semaphore,
            mpsc::{
                channel,
                Receiver,
                Sender
            },
            Mutex,
            RwLock
        },
        time::{
            error::Elapsed,
            timeout
        }
    }
};
pub use self::{
    handler::EventWebSocketHandler,
    http_request::HttpRequest,
};

pub type WebSocketServerShared<H> = Arc<WebSocketServer<H>>;
pub type WebSocketSessionShared<H> = Arc<WebSocketSession<H>>;

// Constants
// timeout in seconds for sending a message
const MESSAGE_TIME_OUT: Duration = Duration::from_secs(1);
// interval in seconds to send a ping message
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
// timeout in seconds to receive a pong message
const KEEP_ALIVE_TIME_OUT: Duration = Duration::from_secs(30);
// Maximum number of websocket sessions accepted by one common websocket server.
pub const DEFAULT_MAX_WEBSOCKET_SESSIONS: usize = 1024;
// Maximum number of outbound messages queued per websocket session.
pub const DEFAULT_MAX_SESSION_CHANNEL_SIZE: usize = 256;
// Maximum number of queued RPC messages per websocket session.
// When reached, the websocket reader applies backpressure until queued work drains.
pub const DEFAULT_MAX_SESSION_WORK_QUEUE: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    #[error(transparent)]
    SessionClosed(#[from] actix_ws::Closed),
    #[error("this session was already closed")]
    SessionAlreadyClosed,
    #[error("error while sending message '{}', channel is closed", _0)]
    ChannelClosed(String),
    #[error("error while closing, channel is already closed")]
    ChannelAlreadyClosed,
    #[error(transparent)]
    Elapsed(#[from] Elapsed),
}

enum InnerMessage {
    Text(String),
    Close(Option<CloseReason>),
}

pub struct WebSocketSession<H: WebSocketHandler + 'static> {
    id: u64,
    request: HttpRequest,
    server: WebSocketServerShared<H>,
    inner: Mutex<Option<Session>>,
    // Sender to send messages to the session
    channel: Sender<InnerMessage>,
    ip_session_permit: IpSessionPermit,
    _session_permit: OwnedSemaphorePermit,
}

// A permit for a session associated with an IP address
struct IpSessionPermit {
    sessions: Option<Arc<StdMutex<HashMap<IpAddr, usize>>>>,
    ip: IpAddr
}

impl Drop for IpSessionPermit {
    fn drop(&mut self) {
        let Some(sessions) = self.sessions.take() else {
            return;
        };

        let Ok(mut sessions) = sessions.lock() else {
            return;
        };

        if let Some(count) = sessions.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                sessions.remove(&self.ip);
            }
        }
    }
}

tid! { impl<'a, H: 'static> TidAble<'a> for WebSocketSession<H> where H: WebSocketHandler }

impl<H> WebSocketSession<H>
where
    H: WebSocketHandler + 'static
{
    // Send a text message to the session
    pub async fn send_text<S: Into<String>>(self: &Arc<Self>, value: S) -> Result<(), WebSocketError> {
        self.channel.send(InnerMessage::Text(value.into())).await
            .map_err(|e| WebSocketError::ChannelClosed(e.to_string()))?;

        Ok(())
    }

    // Send a json value
    pub async fn send_json<S: Serialize>(self: &Arc<Self>, value: S) -> Result<(), WebSocketError> {
        self.send_text(json!(value).to_string()).await
    }

    // Send a ping message to the session
    // this must be called from the task handling the session only
    async fn ping(&self) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        let session = inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?;
        timeout(MESSAGE_TIME_OUT, session.ping(b"")).await??;
        Ok(())
    }

    // Send a pong message to the session
    // this must be called from the task handling the session only
    async fn pong(&self) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        let session = inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?;
        timeout(MESSAGE_TIME_OUT, session.pong(b"")).await??;
        Ok(())
    }

    // this must be called from the task handling the session only
    async fn send_text_internal<S: Into<String>>(&self, value: S) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        let session = inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?;
        timeout(MESSAGE_TIME_OUT, session.text(value.into())).await??;
        Ok(())
    }

    // Close the session
    pub async fn close(&self, reason: Option<CloseReason>) -> Result<(), WebSocketError> {
        self.channel.send(InnerMessage::Close(reason)).await
            .map_err(|_| WebSocketError::ChannelAlreadyClosed)?;

        Ok(())
    }

    // this must be called from the task handling the session only
    async fn close_internal(&self, reason: Option<CloseReason>) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        let session = inner.take().ok_or(WebSocketError::SessionAlreadyClosed)?;
        timeout(MESSAGE_TIME_OUT, session.close(reason)).await??;
        Ok(())
    }

    pub async fn is_closed(&self) -> bool {
        self.inner.lock().await.is_none()
    }

    pub fn get_request(&self) -> &HttpRequest {
        &self.request
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }

    pub fn get_ip_addr(&self) -> &IpAddr {
        &self.ip_session_permit.ip
    }

    pub fn get_server(&self) -> &WebSocketServerShared<H> {
        &self.server
    }
}

impl<H> PartialEq for WebSocketSession<H>
where
    H: WebSocketHandler + 'static
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<H> Eq for WebSocketSession<H>
where
    H: WebSocketHandler + 'static
{}

impl<H> Hash for WebSocketSession<H>
where
    H: WebSocketHandler + 'static
{
    fn hash<A: Hasher>(&self, state: &mut A) {
        self.id.hash(state);
    }
}

#[async_trait]
pub trait WebSocketHandler: Sized + Sync + Send {
    // should we check the heartbeat of session
    // by sending ping / pong messages
    async fn check_heartbeat(&self, _: &WebSocketSessionShared<Self>) -> bool {
        true
    }

    // called when a new Session is added in websocket server
    // if an error is returned, maintaining the session is aborted
    async fn on_connection(&self, _: &WebSocketSessionShared<Self>) -> Result<Option<actix_web::HttpResponse>, anyhow::Error> {
        Ok(None)
    }

    // called when a new message is received
    async fn on_message(&self, _: &WebSocketSessionShared<Self>, _: &[u8]) -> Result<(), anyhow::Error> {
        Ok(())
    }

    // called when a Session is closed
    async fn on_close(&self, _: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub struct WebSocketServer<H: WebSocketHandler + 'static + Send + Sync> {
    sessions: RwLock<HashSet<WebSocketSessionShared<H>>>,
    session_permits: Arc<Semaphore>,
    session_channel_size: usize,
    session_work_queue_size: usize,
    max_connections_per_ip: Option<usize>,
    proxy_address_headers: Vec<String>,
    connections_per_ip: Arc<StdMutex<HashMap<IpAddr, usize>>>,
    id_counter: AtomicU64,
    handler: Immutable<H>
}

impl<H> WebSocketServer<H> where H: WebSocketHandler + 'static + Send + Sync {
    pub fn new(handler: impl Into<Immutable<H>>) -> WebSocketServerShared<H> {
        Self::with(
            handler,
            DEFAULT_MAX_WEBSOCKET_SESSIONS,
            DEFAULT_MAX_SESSION_CHANNEL_SIZE,
            DEFAULT_MAX_SESSION_WORK_QUEUE,
            None,
            Vec::new(),
        )
    }

    pub fn with(
        handler: impl Into<Immutable<H>>,
        max_sessions: usize,
        session_channel_size: usize,
        session_work_queue_size: usize,
        max_connections_per_ip: Option<usize>,
        proxy_address_headers: Vec<String>
    ) -> WebSocketServerShared<H> {
        assert!(max_sessions > 0, "max websocket sessions must be greater than 0");
        assert!(session_channel_size > 0, "websocket session channel size must be greater than 0");
        assert!(session_work_queue_size > 0, "websocket session work queue size must be greater than 0");
        assert!(max_connections_per_ip.map_or(true, |v| v > 0), "max connections per IP must be greater than 0");

        Arc::new(Self {
            sessions: RwLock::new(HashSet::new()),
            session_permits: Arc::new(Semaphore::new(max_sessions)),
            session_channel_size,
            session_work_queue_size,
            max_connections_per_ip,
            proxy_address_headers,
            connections_per_ip: Arc::new(StdMutex::new(HashMap::new())),
            id_counter: AtomicU64::new(0),
            handler: handler.into()
        })
    }

    // Turns off all connections
    pub async fn stop(&self) {
        if let Err(e) = self.clear_connections().await {
            error!("Error while clearing connections: {}", e);
        }
    }

    // Returns the number of connections
    pub async fn count_connections(&self) -> usize {
        self.sessions.read().await.len()
    }

    // Turns off all connections
    pub async fn clear_connections(&self) -> Result<(), WebSocketError> {
        let sessions = {
            let mut sessions = self.sessions.write().await;
            sessions.drain().collect::<Vec<_>>()
        };

        debug!("Clear {} connections", sessions.len());
        for session in sessions {
            if let Err(e) = session.close(None).await {
                debug!("Error while requesting session close: {}", e);
            }

            if let Err(e) = self.get_handler().on_close(&session).await {
                debug!("Error while closing session: {}", e);
            }
        }

        Ok(())
    }

    // Returns the RPC handler used for this server
    pub fn get_handler(&self) -> &H {
        self.handler.as_ref()
    }

    // Returns all sessions managed by this server
    pub fn get_sessions(&self) -> &RwLock<HashSet<WebSocketSessionShared<H>>> {
        &self.sessions
    }

    // Handle a new WebSocket connection request, register it and start handling it
    pub async fn handle_connection(self: &Arc<Self>, request: ActixHttpRequest, body: Payload) -> Result<HttpResponse, actix_web::Error> {
        debug!("Handling new WebSocket connection");
        let permit = match Arc::clone(&self.session_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(e) => {
                debug!("Rejecting WebSocket connection, session limit reached: {}", e);
                return Ok(HttpResponse::TooManyRequests().finish());
            }
        };

        let address = self.get_client_address(&request)
            .ok_or_else(|| {
                debug!("Rejecting WebSocket connection, unable to determine client IP address");
                ErrorInternalServerError("Unable to determine client IP address")
            })?;

        let ip_session_permit = self.try_acquire_ip_session(address.ip())?;

        let (response, session, stream) = actix_ws::handle(&request, body)?;
        let id = self.next_id();
        let request = HttpRequest::from(request);
        let (tx, rx) = channel(self.session_channel_size);
        let session = Arc::new(WebSocketSession {
            id,
            request,
            server: Arc::clone(&self),
            inner: Mutex::new(Some(session)),
            channel: tx,
            _session_permit: permit,
            ip_session_permit
        });

        debug!("Created new WebSocketSession with id {}", id);

        // call on_connection
        match self.handler.on_connection(&session).await {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => (),
            Err(e) => {
                debug!("Error while calling on_connection: {}", e);
                return Ok(HttpResponse::InternalServerError().body(e.to_string()));
            }
        };

        {
            debug!("Inserting session #{} into sessions", id);
            let mut sessions = self.sessions.write().await;
            let res = sessions.insert(Arc::clone(&session));
            debug!("Session #{} has been inserted into sessions: {}", id, res);
        }

        actix_rt::spawn(
            Arc::clone(self)
                .handle_ws_internal(
                    session,
                    stream.max_frame_size(MAX_BLOCK_SIZE)
                        .aggregate_continuations(),
                    rx
                )
        );
        Ok(response)
    }

    // Get the client address from the request, considering proxy headers if configured
    fn get_client_address(&self, request: &ActixHttpRequest) -> Option<std::net::SocketAddr> {
        for name in &self.proxy_address_headers {
            if let Some(value) = request.headers().get(name).and_then(|value| value.to_str().ok()) {
                if let Some(ip) = value.split(',').next().map(str::trim).and_then(|value| value.parse::<IpAddr>().ok()) {
                    return Some(std::net::SocketAddr::new(ip, 0));
                }
            }
        }

        request.peer_addr()
    }

    // Try to acquire a session permit for the given IP address
    // Returns Some(IpSessionPermit) if the permit was acquired, None otherwise
    fn try_acquire_ip_session(&self, ip: IpAddr) -> Result<IpSessionPermit, actix_web::Error> {
        let Some(limit) = self.max_connections_per_ip else {
            return Ok(IpSessionPermit {
                sessions: None,
                ip
            });
        };

        let mut sessions = self.connections_per_ip.lock()
            .map_err(|e| {
                error!("Failed to lock connections_per_ip: {}", e);
                ErrorInternalServerError(format!("Failed to lock connections_per_ip: {}", e.to_string()))
            })?;
        let count = sessions.entry(ip).or_insert(0);
        if *count >= limit {
            debug!("Rejecting WebSocket connection from {}: max connections per IP reached", ip);
            return Err(ErrorBadGateway("Max connections per IP reached"));
        }

        *count += 1;
        Ok(IpSessionPermit {
            sessions: Some(Arc::clone(&self.connections_per_ip)),
            ip
        })
    }

    // Internal function to generate a unique id for a session
    fn next_id(&self) -> u64 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    // Delete a session from the server
    pub async fn delete_session(self: &Arc<Self>, session: &WebSocketSessionShared<H>, reason: Option<CloseReason>) {
        trace!("deleting session #{}", session.id);
        // close session
        if let Err(e) = session.close_internal(reason).await {
            debug!("Error while closing session: {}", e);
        }
        trace!("session closed");

        let deleted = {
            let mut sessions = self.sessions.write().await;
            trace!("sessions locked, size: {}", sessions.len());
            sessions.remove(session)
        };

        if deleted {
            debug!("deleted session #{}", session.id);
            // call on_close
            if let Err(e) = self.handler.on_close(&session).await {
                debug!("Error while calling on_close: {}", e);
            }
        }
        trace!("sessions unlocked");
    }

    // Internal function to handle a WebSocket connection
    // This will send a ping every 5 seconds and close the connection if no pong is received within 30 seconds
    // It will also translate all messages to the handler
    async fn handle_ws_internal(self: Arc<Self>, session: WebSocketSessionShared<H>, mut stream: AggregatedMessageStream, mut rx: Receiver<InnerMessage>) {
        let mut interval = actix_rt::time::interval(KEEP_ALIVE_INTERVAL);
        let mut last_pong_received = Instant::now();
        // executor for handling messages
        // we use Executor to limit the number of concurrent tasks to 1 per session
        // but allow queuing multiple tasks
        let mut executor = Executor::new();

        let reason = loop {
            select! {
                // heartbeat
                _ = interval.tick() => {
                    trace!("Sending ping to session #{}", session.id);

                    if session.is_closed().await {
                        debug!("Session is closed, stopping heartbeat");
                        break None;
                    }

                    if self.get_handler().check_heartbeat(&session).await {
                        if last_pong_received.elapsed() > KEEP_ALIVE_TIME_OUT {
                            debug!("session #{} didn't respond in time from our ping", session.id);
                            break None;
                        }

                        if let Err(e) = session.ping().await {
                            debug!("Error while sending ping to session #{}: {}", session.id, e);
                            break None;
                        }
                    }
                },
                Some(_) = executor.next() => {
                    trace!("Executed a task for session #{}", session.id);
                },
                Some(msg) = rx.recv() => {
                    match msg {
                        InnerMessage::Text(text) => {
                            trace!("Sending text message to session #{}: {}", session.id, text);
                            if let Err(e) = session.send_text_internal(text).await {
                                debug!("Error while sending text message to session #{}: {}", session.id, e);
                                break Some(CloseReason::from(CloseCode::Error));
                            }
                        },
                        InnerMessage::Close(reason) => {
                            debug!("Closing session #{} with reason: {:?}", session.id, reason);
                            break reason;
                        }
                    }
                },
                // wait for next message
                res = stream.next(), if executor.len() < self.session_work_queue_size => {
                    trace!("Received stream message for session #{}", session.id);
                    let msg = match res {
                        Some(msg) => match msg {
                            Ok(msg) => msg,
                            Err(e) => {
                                debug!("Error while receiving message: {}", e);
                                break Some(CloseReason::from(CloseCode::Error));
                            }
                        },
                        None => {
                            debug!("Stream closed for session #{}", session.id);
                            break None
                        },
                    };

                    // handle message
                    match msg {
                        AggregatedMessage::Text(text) => {
                            trace!("Received text message for session #{}: {}", session.id, text);
                            let zelf = &self;
                            let session = &session;
                            executor.push_back(async move {
                                if let Err(e) = zelf.handler.on_message(session, text.as_bytes()).await {
                                    debug!("Error while calling on_message: {}", e);
                                }
                            });
                        },
                        AggregatedMessage::Close(reason) => {
                            trace!("Received close message for session #{}: {:?}", session.id, reason);
                            break reason;
                        },
                        AggregatedMessage::Ping(data) => {
                            trace!("Received ping message with size {} bytes from session #{}", data.len(), session.id);
                            if let Err(e) = session.pong().await {
                                debug!("Error received while sending pong response to session #{}: {}", session.id, e);
                                break None;
                            }
                        },
                        AggregatedMessage::Pong(data) => {
                            trace!("received pong!");
                            if !data.is_empty() {
                                debug!("Data in pong message is not empty for session #{}", session.id);
                                break None;
                            }
                            last_pong_received = Instant::now();
                        },
                        msg => {
                            debug!("Received websocket message not supported: {:?}", msg);
                            break None;
                        }
                    }
                }
            };
        };

        debug!("Session #{} is closing", session.id);
        // attempt to close connection gracefully
        self.delete_session(&session, reason).await;
        debug!("Session #{} has been closed", session.id);
    }
}