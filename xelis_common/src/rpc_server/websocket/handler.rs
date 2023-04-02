use std::{collections::HashMap, hash::Hash, sync::Arc, borrow::Cow};
use actix_ws::Message;
use async_trait::async_trait;
use log::debug;
use serde_json::{Value, json};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use crate::{rpc_server::{RPCHandler, RpcResponseError, InternalRpcError, RpcRequest, RpcResponse}, api::SubscribeParams};
use super::{WebSocketSessionShared, WebSocketHandler};

// generic websocket handler supporting event subscriptions 
pub struct EventWebSocketHandler<T: Sync + Send + Clone + 'static, E: DeserializeOwned + Send + Eq + Hash + 'static> {
    sessions: Mutex<HashMap<WebSocketSessionShared<Self>, HashMap<E, Option<usize>>>>,
    handler: Arc<RPCHandler<T>>
}

impl<T, E> EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: DeserializeOwned + Send + Eq + Hash + 'static
{
    pub fn new(handler: Arc<RPCHandler<T>>) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            handler
        }
    }

    pub async fn notify(&self, event: &E, value: Value) {
        let sessions = self.sessions.lock().await;
        for (session, subscriptions) in sessions.iter() {
            if let Some(id) = subscriptions.get(event) {
                let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value)));
                if let Err(e) = session.send_text(response.to_string()).await {
                    debug!("Error occured while notifying a new event: {}", e);
                };
            }
        }
    }

    async fn subscribe_session_to_event(&self, session: &WebSocketSessionShared<Self>, event: E, id: Option<usize>) -> Result<(), RpcResponseError> {
        let mut sessions = self.sessions.lock().await;
        let events = sessions.entry(session.clone()).or_insert_with(HashMap::new);
        if events.contains_key(&event) {
            return Err(RpcResponseError::new(id, InternalRpcError::EventAlreadySubscribed));
        }

        events.insert(event, id);
        Ok(())
    }

    async fn unsubscribe_session_from_event(&self, session: &WebSocketSessionShared<Self>, event: E, id: Option<usize>) -> Result<(), RpcResponseError> {
        let mut sessions = self.sessions.lock().await;
        let events = sessions.entry(session.clone()).or_insert_with(HashMap::new);
        if events.contains_key(&event) {
            return Err(RpcResponseError::new(id, InternalRpcError::EventNotSubscribed));
        }

        events.remove(&event);
        Ok(())
    }

    fn parse_event(&self, request: &mut RpcRequest) -> Result<E, RpcResponseError> {
        let value = request.params.take().ok_or_else(|| RpcResponseError::new(request.id, InternalRpcError::ExpectedParams))?;
        let params: SubscribeParams<E> = serde_json::from_value(value).map_err(|e| RpcResponseError::new(request.id, InternalRpcError::InvalidParams(e)))?;
        Ok(params.notify)
    }

    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: Message) -> Result<Value, RpcResponseError> {
        if let Message::Text(text) = message {
            let mut request: RpcRequest = self.handler.parse_request(text.as_bytes())?;
            let response: Value = match request.method.as_str() {
                "subscribe" => {
                    let event = self.parse_event(&mut request)?;
                    self.subscribe_session_to_event(session, event, request.id).await?;
                    json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(json!(true))))
                },
                "unsubscribe" => {
                    let event = self.parse_event(&mut request)?;
                    self.unsubscribe_session_from_event(session, event, request.id).await?;
                    json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(json!(true))))
                },
                _ => match self.handler.handle_request(text.as_bytes()).await {
                    Ok(result) => result,
                    Err(e) => e.to_json(),
                }
            };
            Ok(response)
        } else {
            Err(RpcResponseError::new(None, InternalRpcError::InvalidRequest))
        }
    }
}

#[async_trait]
impl<T, E> WebSocketHandler for EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: DeserializeOwned + Send + Eq + Hash + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session);
        Ok(())
    }

    async fn on_connection(&self, _: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        debug!("New connection detected on websocket");
        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: Message) -> Result<(), anyhow::Error> {
        let response: Value = match self.on_message_internal(session, message).await {
            Ok(result) => result,
            Err(e) => e.to_json(),
        };
        session.send_text(response.to_string()).await?;
        Ok(())
    }
}