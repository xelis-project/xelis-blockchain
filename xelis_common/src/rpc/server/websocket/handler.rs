use std::{
    collections::HashSet,
    hash::Hash,
    borrow::Cow
};
use async_trait::async_trait;
use futures::{stream, StreamExt};
use log::{trace, debug};
use schemars::JsonSchema;
use serde_json::{Value, json};
use serde::{de::DeserializeOwned, Serialize};
use runtime_context::{Context, ShareableTid};
use crate::{
    api::EventResult,
    rpc::{
        RpcResponseError,
        RPCHandler,
        RpcResponse,
        Events,
    }
};
use super::{WebSocketSessionShared, WebSocketHandler};

// generic websocket handler supporting event subscriptions 
pub struct EventWebSocketHandler<T, E>
where
    T: ShareableTid<'static>,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + JsonSchema + 'static
{
    // a map of sessions to events
    events: Events<WebSocketSessionShared<Self>, E>,
    // the RPC handler containing the methods to call
    // when a message is received
    handler: RPCHandler<T>,
    // the number of concurrent notifications to send
    notify_concurrency: usize,
}

impl<T, E> EventWebSocketHandler<T, E>
where
    T: ShareableTid<'static>,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + JsonSchema + 'static
{
    // Creates a new event websocket handler
    // with the given RPC handler and notify concurrency
    #[inline(always)]
    pub fn new(mut handler: RPCHandler<T>, notify_concurrency: usize) -> Self {
        Self {
            events: Events::new(&mut handler),
            handler,
            notify_concurrency
        }
    }

    // Get all the tracked events across all sessions
    #[inline(always)]
    pub async fn get_tracked_events(&self) -> HashSet<E> {
        self.events.get_tracked_events().await
    }

    // Check if an event is tracked by any session
    #[inline(always)]
    pub async fn is_event_tracked(&self, event: &E) -> bool {
        self.events.is_event_tracked(event).await
    }

    // Notify all sessions subscribed to the given event
    // This will send the event concurrently to all sessions
    // based on the provided configuration
    pub async fn notify(&self, event: &E, value: Value) {
        let value = json!(EventResult { event: Cow::Borrowed(event), value });
        debug!("notifying event");
        let sessions = self.events.sessions().await;

        stream::iter(sessions.iter())
            .for_each_concurrent(self.notify_concurrency, |(session, subscriptions)| {
                let data = subscriptions.get(event)
                    .map(|id| json!(RpcResponse::new(Cow::Borrowed(id), Cow::Borrowed(&value))));

                async move {
                    if let Some(data) = data {
                        trace!("sending event to #{}", session.id);
                        if let Err(e) = session.send_text(data.to_string()).await {
                            debug!("Error occured while notifying a new event: {}", e);
                        };
                        trace!("event sent to #{}", session.id);
                    }
                }
            }).await;

        debug!("end event propagation");
    }

    // Handle the message received on the websocket
    async fn on_message_internal<'a>(&'a self, session: &'a WebSocketSessionShared<Self>, message: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        let mut context = Context::default();
        context.insert_ref(session);
        context.insert_ref(&self.handler);
        context.insert_ref(&self.events);

        self.handler.handle_request_with_context(context, message).await
    }

    pub fn get_rpc_handler(&self) -> &RPCHandler<T> {
        &self.handler
    }
}

#[async_trait]
impl<T, E> WebSocketHandler for EventWebSocketHandler<T, E>
where
    T: ShareableTid<'static>,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + JsonSchema + 'static
{
    async fn on_close(&self, session: &WebSocketSessionShared<Self>) -> Result<(), anyhow::Error> {
        trace!("deleting ws session from events");
        self.events.on_close(session).await;
        Ok(())
    }

    async fn on_message(&self, session: &WebSocketSessionShared<Self>, message: &[u8]) -> Result<(), anyhow::Error> {
        trace!("new message received on websocket");
        let response = match self.on_message_internal(session, message).await {
            Ok(result) => result,
            Err(e) => Some(e.to_json()),
        };

        if let Some(response) = response {
            trace!("sending response to websocket");
            session.send_json(response).await?;
        }

        Ok(())
    }
}