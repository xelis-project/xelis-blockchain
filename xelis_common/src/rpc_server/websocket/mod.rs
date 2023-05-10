mod handler;

use std::{sync::{Arc, atomic::{AtomicU64, Ordering}}, collections::HashSet, hash::{Hash, Hasher}, time::{Duration, Instant}};
use actix_web::{HttpRequest, web::Payload, HttpResponse};
use actix_ws::{Session, MessageStream, Message, CloseReason, CloseCode};
use async_trait::async_trait;
use futures_util::StreamExt;
use log::{debug, trace};
use tokio::{sync::Mutex, select};

pub use self::handler::EventWebSocketHandler;

pub type WebSocketServerShared<H> = Arc<WebSocketServer<H>>;
pub type WebSocketSessionShared<H> = Arc<WebSocketSession<H>>;

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
const KEEP_ALIVE_TIME_OUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    #[error(transparent)]
    SessionClosed(#[from] actix_ws::Closed),
    #[error("this session was already closed")]
    SessionAlreadyClosed,
}

pub struct WebSocketSession<H: WebSocketHandler + 'static> {
    id: u64,
    server: WebSocketServerShared<H>,
    inner: Mutex<Option<Session>>
}

impl<H> WebSocketSession<H>
where
    H: WebSocketHandler + 'static
{
    pub async fn send_text<S: Into<String>>(self: &Arc<Self>, value: S) -> Result<(), WebSocketError> {
        let res = self.send_text_internal(value).await;
        if res.is_err() {
            self.server.delete_session(self, None).await;
        }
        res
    }

    pub async fn ping(&self) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        let session = inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?;
        session.ping(b"").await?;
        Ok(())
    }

    pub async fn pong(&self) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        let session = inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?;
        session.pong(b"").await?;
        Ok(())
    }

    async fn send_text_internal<S: Into<String>>(&self, value: S) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?.text(value.into()).await?;
        Ok(())
    }

    async fn close(&self, reason: Option<CloseReason>) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        inner.take().ok_or(WebSocketError::SessionAlreadyClosed)?.close(reason).await?;
        Ok(())
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
pub trait WebSocketHandler: Sized {
    // called when a new Session is added in websocket server
    // if an error is returned, maintaining the session is aborted
    async fn on_connection(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error>;

    // called when a new message is received
    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<(), anyhow::Error>;

    // called when a Session is closed
    async fn on_close(&self,session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error>;
}

pub struct WebSocketServer<H: WebSocketHandler + 'static> {
    sessions: Mutex<HashSet<WebSocketSessionShared<H>>>,
    id_counter: AtomicU64,
    handler: H
}

impl<H> WebSocketServer<H> where H: WebSocketHandler + 'static {
    pub fn new(handler: H) -> WebSocketServerShared<H> {
        Arc::new(Self {
            sessions: Mutex::new(HashSet::new()),
            id_counter: AtomicU64::new(0),
            handler
        })
    }

    pub fn get_handler(&self) -> &H {
        &self.handler
    }

    pub fn get_sessions(&self) -> &Mutex<HashSet<WebSocketSessionShared<H>>> {
        &self.sessions
    }

    pub async fn handle_connection(self: &Arc<Self>, request: &HttpRequest, body: Payload) -> Result<HttpResponse, actix_web::Error> {
        debug!("Handling new WebSocket connection");
        let (response, session, stream) = actix_ws::handle(request, body)?;
        let id = self.next_id();
        debug!("Created new WebSocketSession with id {}", id);
        let session = Arc::new(WebSocketSession {
            id,
            server: Arc::clone(&self),
            inner: Mutex::new(Some(session)),
        });

        {
            debug!("Inserting session #{} into sessions", id);
            let mut sessions = self.sessions.lock().await;
            let res = sessions.insert(Arc::clone(&session));
            debug!("Session #{} has been inserted into sessions: {}", id, res);
        }

        actix_rt::spawn(Arc::clone(self).handle_ws_internal(session.clone(), stream));
        Ok(response)
    }

    fn next_id(&self) -> u64 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    async fn delete_session(&self, session: &WebSocketSessionShared<H>, reason: Option<CloseReason>) {
        debug!("deleting session");
        // close session
        if let Err(e) = session.close(reason).await {
            debug!("Error while closing session: {}", e);
        }
        debug!("session closed");

        let mut sessions = self.sessions.lock().await;
        debug!("sessions locked");
        if sessions.remove(session) {
            debug!("deleted session");
            // call on_close
            if let Err(e) = self.handler.on_close(session).await {
                debug!("Error while calling on_close: {}", e);
            }
        }
        debug!("sessions unlocked");
    }
    
    async fn handle_ws_internal(self: Arc<Self>, session: WebSocketSessionShared<H>, mut stream: MessageStream) {
        // call on_connection
        if let Err(e) = self.handler.on_connection(&session).await {
            debug!("Error while calling on_connection: {}", e);
            self.delete_session(&session, Some(CloseReason::from(CloseCode::Error))).await;
            return;
        }

        let mut interval = actix_rt::time::interval(KEEP_ALIVE_INTERVAL);
        let mut last_pong_received = Instant::now();
        let reason = loop {
            select! {
                // heartbeat
                _ = interval.tick() => {
                    trace!("Sending ping to session #{}", session.id);
                    if let Err(e) = session.ping().await {
                        debug!("Error while sending ping to session #{}: {}", session.id, e);
                        break None;
                    }

                    if last_pong_received.elapsed() > KEEP_ALIVE_TIME_OUT {
                        debug!("session #{} didn't respond in time from our ping", session.id);
                        break None;
                    }
                },
                // wait for next message
                res = stream.next() => {
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
                        Message::Text(text) => {
                            debug!("Received text message for session #{}: {}", session.id, text);
                            if let Err(e) = self.handler.on_message(&session, text.as_bytes()).await {
                                debug!("Error while calling on_message: {}", e);
                                break Some(CloseReason::from(CloseCode::Error));
                            }
                        },
                        Message::Close(reason) => {
                            debug!("Received close message for session #{}: {:?}", session.id, reason);
                            break reason;
                        },
                        Message::Ping(data) => {
                            debug!("Received ping message with size {} bytes from session #{}", data.len(), session.id);
                            if let Err(e) = session.pong().await {
                                debug!("Error received while sending pong response to session #{}: {}", session.id, e);
                                break None;
                            }
                        },
                        Message::Pong(data) => {
                            if !data.is_empty() {
                                debug!("Data in pong message is not empty for session #{}", session.id);
                                break None;
                            }
                            last_pong_received = Instant::now();
                        },
                        msg => {
                            debug!("Received websocket message not supported: {:?}", msg);
                        }
                    }
                }
            };
        };

        // attempt to close connection gracefully
        self.delete_session(&session, reason).await;
    }
}