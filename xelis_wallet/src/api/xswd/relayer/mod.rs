mod client;

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::{stream, StreamExt};
use log::error;
use serde_json::{json, Value};
use xelis_common::{
    api::wallet::NotifyEvent,
    rpc::{
        Id,
        InternalRpcError,
        RPCHandler,
        RpcResponse,
        RpcResponseError
    },
    tokio::sync::RwLock
};

use crate::api::XSWDError;

use super::{
    AppState,
    AppStateShared,
    ApplicationData,
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

    pub async fn close(&self) {
        let mut applications = self.applications.write().await;

        stream::iter(applications.drain())
            .for_each_concurrent(self.concurrency, |(_, (client, _))| async move { client.close().await })
            .await;
    }

    pub async fn add_application(self: &XSWDRelayerShared<W>, relayer: String, app_data: ApplicationData) -> Result<(), anyhow::Error> {
        // Sanity check
        self.xswd.verify_application(self.as_ref(), &app_data).await?;

        let state = Arc::new(AppState::new(app_data));
        let client = Client::new(&relayer, Arc::clone(self), state.clone()).await?;

        {
            let mut applications = self.applications.write().await;
            applications.insert(state.clone(), (client, HashMap::new()));
        }

        self.xswd.add_application(&state).await?;
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
            applications.remove(&state);
        }

        if let Err(e) = self.xswd.on_close(state).await {
            error!("Error while closing a XSWD Relayer: {}", e);
        }
    }
}

#[async_trait]
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