use std::{collections::{HashMap, HashSet}, hash::Hash, borrow::Cow};
use actix_web::web::Bytes;
use async_trait::async_trait;
use log::{trace, debug};
use serde_json::{Value, json};
use serde::{de::DeserializeOwned, Serialize};
use crate::{
    tokio::sync::RwLock,
    api::{EventResult, SubscribeParams},
    context::Context,
    rpc_server::{
        Id,
        InternalRpcError,
        RPCHandler,
        RpcRequest,
        RpcResponse,
        RpcResponseError
    }
};
use super::{WebSocketSessionShared, WebSocketHandler};

// generic websocket handler supporting event subscriptions 
pub struct EventWebSocketHandler<T: Sync + Send + Clone + 'static, E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + 'static> {
    events: RwLock<HashMap<WebSocketSessionShared<Self>, HashMap<E, Option<Id>>>>,
    handler: RPCHandler<T>
}

impl<T, E> EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + 'static
{
    pub fn new(handler: RPCHandler<T>) -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            handler
        }
    }

    pub async fn get_tracked_events(&self) -> HashSet<E> {
        trace!("getting tracked events");
        let sessions = self.events.read().await;
        trace!("tracked events sessions locked");
        HashSet::from_iter(sessions.values().map(|e| e.keys().cloned()).flatten())
    }

    pub async fn is_event_tracked(&self, event: &E) -> bool {
        trace!("checking if event is tracked");
        let sessions = self.events.read().await;
        trace!("tracked events sessions locked");
        sessions
            .values()
            .find(|e| e.keys().into_iter().find(|x| *x == event).is_some())
            .is_some()
    }

    pub async fn notify(&self, event: &E, value: Value) {
        let value = json!(EventResult { event: Cow::Borrowed(event), value });
        debug!("notifying event");
        let sessions = {
            let events = self.events.read().await;
            trace!("events locked for propagation");
            events.clone()
        };

        for (session, subscriptions) in sessions.iter() {
            if let Some(id) = subscriptions.get(event) {
                let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value)));
                trace!("sending event to #{}", session.id);
                if let Err(e) = session.send_text(response.to_string()).await {
                    debug!("Error occured while notifying a new event: {}", e);
                };
                trace!("event sent to #{}", session.id);
            }
        }

        debug!("end event propagation");
    }

    async fn subscribe_session_to_event(&self, session: &WebSocketSessionShared<Self>, event: E, id: Option<Id>) -> Result<(), RpcResponseError> {
        trace!("subscribing session to event");
        let mut sessions = self.events.write().await;
        trace!("subscribe events locked");
        let events = sessions.entry(session.clone()).or_insert_with(HashMap::new);
        if events.contains_key(&event) {
            return Err(RpcResponseError::new(id, InternalRpcError::EventAlreadySubscribed));
        }

        events.insert(event, id);
        Ok(())
    }

    async fn unsubscribe_session_from_event(&self, session: &WebSocketSessionShared<Self>, event: E, id: Option<Id>) -> Result<(), RpcResponseError> {
        trace!("unsubscribing session from event");
        let mut sessions = self.events.write().await;
        trace!("unsubscribe events locked");
        
        let events = sessions.entry(session.clone()).or_insert_with(HashMap::new);
        if !events.contains_key(&event) {
            return Err(RpcResponseError::new(id, InternalRpcError::EventNotSubscribed));
        }

        events.remove(&event);
        Ok(())
    }

    fn parse_event(&self, request: &mut RpcRequest) -> Result<E, RpcResponseError> {
        let value = request.params.take().ok_or_else(|| RpcResponseError::new(request.id.clone(), InternalRpcError::ExpectedParams))?;
        let params: SubscribeParams<E> = serde_json::from_value(value).map_err(|e| RpcResponseError::new(request.id.clone(), InternalRpcError::InvalidJSONParams(e)))?;
        Ok(params.notify.into_owned())
    }

    async fn execute_method_internal(&self, context: &Context, value: Value) -> Result<Option<Value>, RpcResponseError> {
        let mut request = self.handler.parse_request(value)?;
        let method = request.method.clone();
        match method.as_str() {
            "subscribe" => {
                let event = self.parse_event(&mut request)?;
                self.subscribe_session_to_event(context.get::<WebSocketSessionShared<Self>>().unwrap(), event, request.id.clone()).await?;
                Ok(Some(json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(Value::Bool(true))))))
            },
            "unsubscribe" => {
                let event = self.parse_event(&mut request)?;
                self.unsubscribe_session_from_event(context.get::<WebSocketSessionShared<Self>>().unwrap(), event, request.id.clone()).await?;
                Ok(Some(json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(Value::Bool(true))))))
            },
            _ => self.handler.execute_method(context, request).await
        }
    }

    async fn on_message_internal<'a>(&'a self, session: &'a WebSocketSessionShared<Self>, message: Bytes) -> Result<Value, RpcResponseError> {
        let request: Value = serde_json::from_slice(&message)
            .map_err(|_| RpcResponseError::new(None, InternalRpcError::ParseBodyError))?;

        let mut context = Context::default();
        context.store(session.clone());
        context.store(self.handler.get_data().clone());

        match request {
            e @ Value::Object(_) => self.execute_method_internal(&context, e).await.map(|e| e.unwrap_or(Value::Null)),
            Value::Array(requests) => {
                let mut responses = Vec::new();
                for value in requests {
                    if value.is_object() {
                        let response = match self.execute_method_internal(&context, value).await {
                            Ok(response) => json!(response),
                            Err(e) => e.to_json()
                        };
                        responses.push(response);
                    } else {
                        responses.push(RpcResponseError::new(None, InternalRpcError::InvalidJSONRequest).to_json());
                    }
                }
                Ok(serde_json::to_value(responses).map_err(|err| RpcResponseError::new(None, InternalRpcError::SerializeResponse(err)))?)
            },
            _ => return Err(RpcResponseError::new(None, InternalRpcError::InvalidJSONRequest))
        }
    }

    pub fn get_rpc_handler(&self) -> &RPCHandler<T> {
        &self.handler
    }
}

#[async_trait]
impl<T, E> WebSocketHandler for EventWebSocketHandler<T, E>
where
    T: Sync + Send + Clone + 'static,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        trace!("deleting ws session from events");
        let mut sessions = self.events.write().await;
        sessions.remove(session);
        trace!("session deleted from events");
        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: Bytes) -> Result<(), anyhow::Error> {
        debug!("new message received on websocket");
        let response: Value = match self.on_message_internal(session, message).await {
            Ok(result) => result,
            Err(e) => e.to_json(),
        };
        session.send_text(response.to_string()).await?;
        Ok(())
    }
}