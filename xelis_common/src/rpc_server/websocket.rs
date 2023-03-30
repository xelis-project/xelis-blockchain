use std::{sync::{Arc, atomic::{AtomicU64, Ordering}}, collections::HashSet, hash::{Hash, Hasher}};
use actix_web::{HttpRequest, web::Payload, HttpResponse};
use actix_ws::{Session, MessageStream, Message, CloseReason, CloseCode};
use futures_util::StreamExt;
use log::{info, debug, warn};
use tokio::sync::Mutex;

pub type WebSocketServerShared = Arc<WebSocketServer>;
pub type WebSocketSessionShared = Arc<WebSocketSession>;

#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    #[error(transparent)]
    SessionClosed(#[from] actix_ws::Closed),
    #[error("this session was already closed")]
    SessionAlreadyClosed,
}

struct WebSocketSession {
    id: u64,
    inner: Mutex<Option<Session>>
}

impl WebSocketSession {
    async fn send_text<S: Into<String>>(&self, value: S) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        inner.as_mut().ok_or(WebSocketError::SessionAlreadyClosed)?.text(value.into()).await?;
        Ok(())
    }

    async fn close(&self, reason: Option<CloseReason>) -> Result<(), WebSocketError> {
        let mut inner = self.inner.lock().await;
        inner.take().ok_or(WebSocketError::SessionAlreadyClosed)?.close(reason).await?;
        Ok(())
    }
}

impl PartialEq for WebSocketSession {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for WebSocketSession {}

impl Hash for WebSocketSession {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

pub struct WebSocketServer {
    sessions: Mutex<HashSet<WebSocketSessionShared>>,
    id_counter: AtomicU64
}

impl WebSocketServer {
    pub fn new() -> WebSocketServerShared {
        Arc::new(Self {
            sessions: Mutex::new(HashSet::new()),
            id_counter: AtomicU64::new(0),
        })
    }

    pub fn get_sessions(&self) -> &Mutex<HashSet<WebSocketSessionShared>> {
        &self.sessions
    }

    pub async fn send_text_to<S: Into<String>>(&self, session: &WebSocketSessionShared, value: S) -> Result<(), WebSocketError> {
        let res = session.send_text(value).await;
        if res.is_err() {
            self.delete_session(session, None).await;
        }
        res
    }

    pub async fn handle_connection(self: &Arc<Self>, request: &HttpRequest, body: Payload) -> Result<HttpResponse, actix_web::Error> {
        let (response, session, stream) = actix_ws::handle(request, body)?;
        let session = Arc::new(WebSocketSession {
            id: self.next_id(),
            inner: Mutex::new(Some(session)),
        });

        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(Arc::clone(&session));
        }

        actix_rt::spawn(Arc::clone(self).handle_ws_internal(session.clone(), stream));
        
        Ok(response)
    }

    fn next_id(&self) -> u64 {
        self.id_counter.fetch_add(1, Ordering::SeqCst)
    }

    async fn delete_session(&self, session: &WebSocketSessionShared, reason: Option<CloseReason>) {
        // close session
        if let Err(e) = session.close(reason).await {
            debug!("Error while closing session: {}", e);
        }

        let mut sessions = self.sessions.lock().await;
        sessions.remove(session);
    }
    
    async fn handle_ws_internal(self: Arc<Self>, session: WebSocketSessionShared, mut stream: MessageStream) {
        let reason = loop {
            // wait for next message
            let msg = match stream.next().await {
                Some(msg) => match msg {
                    Ok(msg) => msg,
                    Err(e) => {
                        debug!("Error while receiving message: {}", e);
                        break Some(CloseReason::from(CloseCode::Error));
                    }
                },
                None => break None,
            };
    
            // handle message
            match msg {
                Message::Text(text) => {
                    info!("received: {}", text);
                    // TODO handle
                }
                Message::Ping(msg) => {
                    warn!("ping not supported yet");
                    break Some(CloseReason::from(CloseCode::Unsupported))
                }
                Message::Pong(_) => {
                    debug!("Received pong");
                }
                Message::Close(reason) => {
                    debug!("received close: {:?}", reason);
                    break reason;
                }
                Message::Nop => {
                    debug!("Received a Nop response, ignoring it");
                }
                _ => {
                    debug!("Received an unsupported message!");
                    break Some(CloseReason::from(CloseCode::Unsupported));
                }
            }
        };
    
        // attempt to close connection gracefully
        self.delete_session(&session, reason).await;
    }
}