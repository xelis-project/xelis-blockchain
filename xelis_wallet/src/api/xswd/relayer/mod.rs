mod client;
mod cipher;

use std::{borrow::Cow, collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::{stream, StreamExt};
use log::{debug, error};
use serde::Serialize;
use serde_json::json;
use xelis_common::{
    api::{EventResult, wallet::NotifyEvent},
    rpc::{
        RPCHandler,
        RpcResponse,
        RpcResponseError,
        ShareableTid,
    },
    tokio::sync::RwLock
};

use crate::api::ApplicationDataRelayer;

use super::{
    AppState,
    AppStateShared,
    XSWDHandler,
    XSWDProvider,
    XSWD,
    XSWDResponse
};

use client::*;

// XSWD as a client mode
// Instead of being a server
// we connect to a relay that will
// bridge us all the messages
// This can be considered trustless
// as we encrypt & authenticate each messages
// with a common key shared outside of the channel
pub struct XSWDRelayer<W>
where
    W: ShareableTid<'static> + XSWDHandler
{
    xswd: XSWD<W>,
    applications: RwLock<HashMap<AppStateShared, Client>>,
    concurrency: usize,
}

pub type XSWDRelayerShared<W> = Arc<XSWDRelayer<W>>;

impl<W> XSWDRelayer<W>
where
    W: ShareableTid<'static> + XSWDHandler
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
            .for_each_concurrent(self.concurrency, |(_, client)| async move { client.close().await })
            .await;
    }

    // All applications registered / connected
    pub fn applications(&self) -> &RwLock<HashMap<AppStateShared, Client>> {
        &self.applications
    }

    // notify a new event to all connected WebSocket
    pub async fn notify_event<V: Serialize>(&self, event: &NotifyEvent, value: V) {
        let apps = self.xswd.events().sessions().await;
        let value = json!(EventResult { event: Cow::Borrowed(event), value: json!(value) });

        let sessions = self.applications.read().await;
        // We want to copy the applications reference
        let sessions = &sessions;
        let value = &value;
        stream::iter(apps)
            .for_each_concurrent(self.concurrency, |(app, subscriptions)| async move {
                if let Some(id) = subscriptions.get(event) {
                    if let Some(client) = sessions.get(&app) {
                        let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(value)));
                        client.send_message(response.to_string()).await;
                    }
                }
            })
            .await;
    }

    pub async fn add_application(self: &XSWDRelayerShared<W>, app_data: ApplicationDataRelayer) -> Result<(), anyhow::Error> {
        // Sanity check
        self.xswd.verify_application(self.as_ref(), &app_data.app_data).await?;

        let state = Arc::new(AppState::new(app_data.app_data));
        let client = ClientImpl::new(app_data.relayer, Arc::clone(self), app_data.encryption_mode, state.clone(), true).await?;

        let response = self.xswd.add_application(&state).await?;
        client.send_message(response).await;

        {
            debug!("XSWD Relayer: Added new application #{}", state.get_id());
            let mut applications = self.applications.write().await;
            applications.insert(state.clone(), client);
        }

        Ok(())
    }

    #[inline(always)]
    pub async fn on_message(&self, state: &AppStateShared, message: &[u8]) -> Result<XSWDResponse, RpcResponseError> {
        self.xswd.on_request(self, state, message).await
    }

    pub async fn on_close(&self, state: AppStateShared) {
        {
            let mut applications = self.applications.write().await;
            if let Some(client) = applications.remove(&state) {
                client.close().await;
            } else {
                return;
            }
        }

        if let Err(e) = self.xswd.on_close(state).await {
            error!("Error while closing a XSWD Relayer: {}", e);
        }
    }
}

#[async_trait]
impl<W> XSWDProvider for XSWDRelayer<W>
where
    W: ShareableTid<'static> + XSWDHandler
{
    async fn has_app_with_id(&self, id: &str) -> bool {
        let applications = self.applications.read().await;

        applications.keys()
            .find(|v| v.get_id() == id)
            .is_some()
    }
}