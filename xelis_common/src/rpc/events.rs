use std::{collections::{HashMap, HashSet}, hash::Hash};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use log::trace;
use anyhow::Context as _;
use runtime_context::{Context, ShareableTid, tid};
use crate::{
    api::SubscribeParams,
    async_handler,
    rpc::*,
    tokio::sync::RwLock
};

// Events manager to hold the events subscriptions
pub struct Events<K, E>
where
    K: for<'a> ShareableTid<'a> + Hash + Eq + Clone,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + JsonSchema + 'static
{
    inner: RwLock<HashMap<K, HashMap<E, Option<Id>>>>,
}

tid! {
    impl<'a, K: 'static, E: 'static> TidAble<'a> for Events<K, E>
    where
        K: for<'b> ShareableTid<'b> + Hash + Eq + Clone,
        E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + JsonSchema
}

impl<K, E> Events<K, E>
where
    K: for<'a> ShareableTid<'a> + Hash + Eq + Clone,
    E: Serialize + DeserializeOwned + Sync + Send + Eq + Hash + Clone + JsonSchema + 'static
{
    // Creates a new Events structure
    #[inline]
    pub fn new<T: ShareableTid<'static>>(handler: &mut RPCHandler<T>) -> Self {
        handler.register_method_with_params("subscribe", async_handler!(Self::rpc_subscribe));
        handler.register_method_with_params("unsubscribe", async_handler!(Self::rpc_unsubscribe));

        Self {
            inner: RwLock::new(HashMap::new())
        }
    }

    // Get all the sessions and their subscribed events
    pub async fn sessions(&self) -> HashMap<K, HashMap<E, Option<Id>>> {
        let sessions = self.inner.read().await;
        sessions.clone()
    }

    // Get all the tracked events across all sessions
    pub async fn get_tracked_events(&self) -> HashSet<E> {
        trace!("get tracked events");
        let sessions = self.inner.read().await;
        trace!("tracked events sessions locked");
        HashSet::from_iter(sessions.values().map(|e| e.keys().cloned()).flatten())
    }

    // Check if an event is tracked by any session
    pub async fn is_event_tracked(&self, event: &E) -> bool {
        trace!("is event tracked");
        let sessions = self.inner.read().await;
        trace!("tracked events sessions locked");
        sessions
            .values()
            .find(|e| e.keys().into_iter().find(|x| *x == event).is_some())
            .is_some()
    }

    // Called when a session is closed to remove it from the tracked sessions
    pub async fn on_close(&self, session: &K) {
        trace!("on close");
        let mut sessions = self.inner.write().await;
        sessions.remove(session);
    }

    // Subscribe the given session to the given event with the given id
    pub async fn subscribe(&self, session: K, event: E, id: Option<Id>) -> bool {
        trace!("subscribe to event");
        let mut sessions = self.inner.write().await;
        let entry = sessions.entry(session).or_insert_with(HashMap::new);
        if entry.contains_key(&event) {
            trace!("event already subscribed");
            return false;
        }

        entry.insert(event, id);

        true
    }

    // Unsubscribe the given session from the given event
    pub async fn unsubscribe(&self, session: &K, event: &E) -> bool {
        trace!("unsubscribe from event");
        let mut sessions = self.inner.write().await;
        if let Some(entry) = sessions.get_mut(session) {
            if entry.remove(event).is_some() {
                trace!("event unsubscribed");
                return true;
            }
        }

        trace!("event not found");
        false
    }

    // Parse the event from the request
    pub fn parse_event(request: &mut RpcRequest) -> Result<E, RpcResponseError> {
        let value = request.params.take()
            .ok_or_else(|| RpcResponseError::new(request.id.clone(), InternalRpcError::ExpectedParams))?;
        let params: SubscribeParams<E> = serde_json::from_value(value)
            .map_err(|e| RpcResponseError::new(request.id.clone(), InternalRpcError::InvalidJSONParams(e)))?;
    
        Ok(params.notify.into_owned())
    }

    /// RPC method to subscribe to an event
    async fn rpc_subscribe<'ty, 'r>(context: &Context<'ty, 'r>, params: SubscribeParams<'_, E>) -> Result<bool, InternalRpcError> {
        let events: &Events<K, E> = context.get()
            .context("Events manager not found")?;
        let key: K = context.get()
            .cloned()
            .context("Session key not found")?;
        let id: Option<Id> = context.get()
            .cloned()
            .context("Session id not found")?;

        if !events.subscribe(key, params.notify.into_owned(), id).await {
            return Err(InternalRpcError::EventAlreadySubscribed);
        }

        Ok(true)
    }

    /// RPC method to unsubscribe from an event
    async fn rpc_unsubscribe<'ty, 'r>(context: &Context<'ty, 'r>, params: SubscribeParams<'_, E>) -> Result<bool, InternalRpcError> {
        let events: &Events<K, E> = context.get()
            .context("Events manager not found")?;
        let key: K = context.get()
            .cloned()
            .context("Session key not found")?;

        if !events.unsubscribe(&key, &params.notify).await {
            return Err(InternalRpcError::EventNotSubscribed);
        }

        Ok(true)
    }
}

