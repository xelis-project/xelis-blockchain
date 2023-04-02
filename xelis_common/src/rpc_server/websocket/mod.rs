mod handler;

use std::{sync::{Arc, atomic::{AtomicU64, Ordering}}, collections::HashSet, hash::{Hash, Hasher}};
use actix_web::{HttpRequest, web::Payload, HttpResponse};
use actix_ws::{Session, MessageStream, Message, CloseReason, CloseCode};
use async_trait::async_trait;
use futures_util::StreamExt;
use log::debug;
use tokio::sync::Mutex;

pub use self::handler::EventWebSocketHandler;

pub type WebSocketServerShared<H> = Arc<WebSocketServer<H>>;
pub type WebSocketSessionShared<H> = Arc<WebSocketSession<H>>;

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
    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: Message) -> Result<(), anyhow::Error>;

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
        let (response, session, stream) = actix_ws::handle(request, body)?;
        let session = Arc::new(WebSocketSession {
            id: self.next_id(),
            server: Arc::clone(&self),
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

    async fn delete_session(&self, session: &WebSocketSessionShared<H>, reason: Option<CloseReason>) {
        // close session
        if let Err(e) = session.close(reason).await {
            debug!("Error while closing session: {}", e);
        }

        let mut sessions = self.sessions.lock().await;
        if sessions.remove(session) {
            // call on_close
            if let Err(e) = self.handler.on_close(session).await {
                debug!("Error while calling on_close: {}", e);
            }
        }
    }
    
    async fn handle_ws_internal(self: Arc<Self>, session: WebSocketSessionShared<H>, mut stream: MessageStream) {
        // call on_connection
        if let Err(e) = self.handler.on_connection(&session).await {
            debug!("Error while calling on_connection: {}", e);
            self.delete_session(&session, Some(CloseReason::from(CloseCode::Error))).await;
            return;
        }

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
            if let Err(e) = self.handler.on_message(&session, msg).await {
                debug!("Error while calling on_message: {}", e);
                break Some(CloseReason::from(CloseCode::Error));
            }
        };
    
        // attempt to close connection gracefully
        self.delete_session(&session, reason).await;
    }
}