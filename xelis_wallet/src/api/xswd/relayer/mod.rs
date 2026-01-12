mod client;
mod cipher;

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::{stream, StreamExt};
use log::{debug, error};
use serde::Serialize;
use serde_json::{json, Value};
use xelis_common::{
    api::{wallet::NotifyEvent, EventResult},
    rpc::{
        Id,
        InternalRpcError,
        RPCHandler,
        RpcResponse,
        RpcResponseError
    },
    tokio::sync::RwLock
};

use crate::api::{ApplicationDataRelayer, XSWDError};

use super::{
    AppState,
    AppStateShared,
    OnRequestResult,
    XSWDHandler,
    XSWDProvider,
    XSWD
};

use client::Client;

// XSWD as a client mode
// Instead of being a server
// we connect to a relay that will
// bridge us all the messages
// This can be considered trustless
// as we encrypt & authenticate each messages
// with a common key shared outside of the channel
pub struct XSWDRelayer<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static {
    xswd: XSWD<W>,
    applications: RwLock<HashMap<AppStateShared, (Client, HashMap<NotifyEvent, Option<Id>>)>>,
    concurrency: usize,
}

pub type XSWDRelayerShared<W> = Arc<XSWDRelayer<W>>;

impl<W> XSWDRelayer<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    pub fn new(handler: RPCHandler<W>, concurrency: usize) -> XSWDRelayerShared<W> {
        Arc::new(Self {
            xswd: XSWD::new(handler),
            applications: RwLock::new(HashMap::new()),
            concurrency,
        })
    }

    // On close delete all clients
    pub async fn close(&self) {
        let mut applications = self.applications.write().await;

        stream::iter(applications.drain())
            .for_each_concurrent(self.concurrency, |(_, (client, _))| async move { client.close().await })
            .await;
    }

    // All applications registered / connected
    pub fn applications(&self) -> &RwLock<HashMap<AppStateShared, (Client, HashMap<NotifyEvent, Option<Id>>)>> {
        &self.applications
    }

    // notify a new event to all connected WebSocket
    pub async fn notify_event<V: Serialize>(&self, event: &NotifyEvent, value: V) {
        let value = json!(EventResult { event: Cow::Borrowed(event), value: json!(value) });
        let applications = self.applications.read().await;

        stream::iter(applications.values())
            .for_each_concurrent(self.concurrency, |(client, subscriptions)| async {
                if let Some(id) = subscriptions.get(event) {
                    let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value)));
                    client.send_message(response.to_string()).await;
                }
            })
            .await;
    }

    pub async fn add_application(self: &XSWDRelayerShared<W>, app_data: ApplicationDataRelayer) -> Result<(), anyhow::Error> {
        // Sanity check
        self.xswd.verify_application(self.as_ref(), &app_data.app_data).await?;

        let state = Arc::new(AppState::new(app_data.app_data));
        let client = Client::new(app_data.relayer, Arc::clone(self), app_data.encryption_mode, state.clone()).await?;

        let response = self.xswd.add_application(&state).await?;
        client.send_message(response).await;

        {
            debug!("XSWD Relayer: Added new application #{}", state.get_id());
            let mut applications = self.applications.write().await;
            applications.insert(state.clone(), (client, HashMap::new()));
        }

        Ok(())
    }

    pub async fn on_message(&self, state: &AppStateShared, message: &[u8]) -> Result<Option<Value>, RpcResponseError> {
        match self.xswd.on_request(self, state, message).await? {
            OnRequestResult::Return(value) => Ok(value),
            OnRequestResult::Request { request, event, is_subscribe } => {
                let mut applications = self.applications.write().await;
                let (_, events) = applications.get_mut(state)
                    .ok_or_else(|| RpcResponseError::new(request.id.clone(), XSWDError::ApplicationNotFound))?;

                if events.contains_key(&event) != is_subscribe {
                    return Err(RpcResponseError::new(request.id.clone(), if is_subscribe {
                        InternalRpcError::EventAlreadySubscribed
                    } else {
                        InternalRpcError::EventNotSubscribed
                    }));
                }

                let res = json!(RpcResponse::new(Cow::Borrowed(&request.id), Cow::Owned(Value::Bool(true))));
                if is_subscribe {
                    events.insert(event, request.id);
                } else {
                    events.remove(&event);
                }

                Ok(Some(res))
            }
        }
    }

    pub async fn on_close(&self, state: AppStateShared) {
        {
            let mut applications = self.applications.write().await;
            if applications.remove(&state).is_none() {
                return;
            }
        }

        if let Err(e) = self.xswd.on_close(state).await {
            error!("Error while closing a XSWD Relayer: {}", e);
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<W> XSWDProvider for XSWDRelayer<W>
where
    W: Clone + Send + Sync + XSWDHandler + 'static
{
    async fn has_app_with_id(&self, id: &str) -> bool {
        let applications = self.applications.read().await;

        applications.keys()
            .find(|v| v.get_id() == id)
            .is_some()
    }
}