use std::{collections::{HashMap, HashSet}, hash::Hash, borrow::Cow};
use actix_web::web::Bytes;
use async_trait::async_trait;
use log::debug;
use serde_json::{Value, json};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::Mutex;
use crate::{rpc_server::{RPCHandler, RpcResponseError, InternalRpcError, RpcRequest, RpcResponse}, api::{SubscribeParams, EventResult}, context::Context};
use super::{WebSocketSessionShared, WebSocketHandler};

// generic websocket handler supporting event subscriptions 
pub struct EventWebSocketHandler<T: Sync + Send + Clone + 'static, E: Serialize + DeserializeOwned + Send + Eq + Hash + Clone + 'static> {
    sessions: Mutex<HashMap<WebSocketSessionShared<Self>, HashMap<E, Option<usize>>>>,
    handler: RPCHandler<T>
}

impl<T, E> EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: Serialize + DeserializeOwned + Send + Eq + Hash + Clone + 'static
{
    pub fn new(handler: RPCHandler<T>) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            handler
        }
    }

    pub async fn get_tracked_events(&self) -> HashSet<E> {
        let sessions = self.sessions.lock().await;
        HashSet::from_iter(sessions.values().map(|e| e.keys().cloned()).flatten())
    }

    pub async fn is_event_tracked(&self, event: &E) -> bool {
        let sessions = self.sessions.lock().await;
        sessions
            .values()
            .find(|e| e.keys().into_iter().find(|x| *x == event).is_some())
            .is_some()
    }

    pub async fn notify(&self, event: &E, value: Value) {
        let value = json!(EventResult { event: Cow::Borrowed(event), value });
        let sessions = self.sessions.lock().await;
        for (session, subscriptions) in sessions.iter() {
            if let Some(id) = subscriptions.get(event) {
                let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value)));
                let session = session.clone();
                tokio::spawn(async move {
                    if let Err(e) = session.send_text(response.to_string()).await {
                        debug!("Error occured while notifying a new event: {}", e);
                    };
                });
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
        if !events.contains_key(&event) {
            return Err(RpcResponseError::new(id, InternalRpcError::EventNotSubscribed));
        }

        events.remove(&event);
        Ok(())
    }

    fn parse_event(&self, request: &mut RpcRequest) -> Result<E, RpcResponseError> {
        let value = request.params.take().ok_or_else(|| RpcResponseError::new(request.id, InternalRpcError::ExpectedParams))?;
        let params: SubscribeParams<E> = serde_json::from_value(value).map_err(|e| RpcResponseError::new(request.id, InternalRpcError::InvalidParams(e)))?;
        Ok(params.notify.into_owned())
    }

    async fn on_message_internal(&self, session: &WebSocketSessionShared<Self>, message: Bytes) -> Result<Value, RpcResponseError> {
        let mut request: RpcRequest = self.handler.parse_request(&message)?;
        let response: Value = match request.method.as_str() {
            "subscribe" => {
                let event = self.parse_event(&mut request)?;
                self.subscribe_session_to_event(&session, event, request.id).await?;
                json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(json!(true))))
            },
            "unsubscribe" => {
                let event = self.parse_event(&mut request)?;
                self.unsubscribe_session_from_event(&session, event, request.id).await?;
                json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(json!(true))))
            },
            _ => {
                let mut context = Context::default();
                context.store(session.clone());
                match self.handler.execute_method(context, request).await {
                    Ok(result) => result,
                    Err(e) => e.to_json(),
                }
            }
        };
        Ok(response)
    }

    pub fn get_rpc_handler(&self) -> &RPCHandler<T> {
        &self.handler
    }
}

#[async_trait]
impl<T, E> WebSocketHandler for EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: Serialize + DeserializeOwned + Send + Eq + Hash + Clone + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        debug!("closing websocket connection");
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session);
        Ok(())
    }

    async fn on_message(&self, session: WebSocketSessionShared<Self>, message: Bytes) -> Result<(), anyhow::Error> {
        debug!("new message received on websocket");
        let response: Value = match self.on_message_internal(&session, message).await {
            Ok(result) => result,
            Err(e) => e.to_json(),
        };
        session.send_text(response.to_string()).await?;
        Ok(())
    }
}