use std::{borrow::Cow, collections::HashMap, sync::Arc, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use anyhow::Context;

use futures::{SinkExt, StreamExt};
use log::{debug, error};
use serde_json::json;
use tokio_tungstenite_wasm::{
    WebSocketStream,
    Message,
    connect,
};
use xelis_common::{
    api::daemon::NotifyEvent,
    rpc::{RpcResponse, ShareableTid},
    tokio::{
        select,
        spawn_task,
        time::sleep,
        sync::{Mutex, mpsc},
        task
    }
};
use crate::api::{
    xswd::relayer::{
        cipher::Cipher,
        XSWDRelayerShared
    },
    AppStateShared,
    EncryptionMode,
    XSWDHandler,
    XSWDResponse,
};

pub struct ClientImpl {
    target: String,
    sender: Mutex<Option<mpsc::Sender<String>>>,
    events: Mutex<HashMap<NotifyEvent, task::JoinHandle<()>>>,
    connected: AtomicBool,
    auto_reconnect: bool,
    task_handle: Mutex<Option<task::JoinHandle<()>>>
}

pub type Client = Arc<ClientImpl>;

impl ClientImpl {
    async fn clear_event_listeners(&self) {
        let mut events = self.events.lock().await;
        for (_, handle) in events.drain() {
            handle.abort();
        }
    }

    pub async fn new<W>(
        target: String,
        relayer: XSWDRelayerShared<W>,
        encryption_mode: Option<EncryptionMode>,
        state: AppStateShared,
        registration: String,
        auto_reconnect: bool,
    ) -> Result<Client, anyhow::Error>
    where
        W: ShareableTid<'static> + XSWDHandler
    {
        // Create a cipher based on the provided encryption mode
        let mut cipher = Cipher::new(encryption_mode)?;

        let mut ws = connect(&target).await?;
        let (sender, mut receiver) = mpsc::channel(64);

        let client = Arc::new(Self {
            target,
            sender: Mutex::new(Some(sender)),
            events: Mutex::new(HashMap::new()),
            connected: AtomicBool::new(true),
            auto_reconnect,
            task_handle: Mutex::new(None),
        });

        let task = {
            let client = client.clone();
            spawn_task(format!("xswd-relayer-{}", state.get_id()), async move {
                loop {
                    if let Err(e) = Self::background_task(&client, ws, &state, &relayer, &mut receiver, &mut cipher).await {
                        debug!("Error on xswd relayer #{}: {:#}", state.get_id(), e);
                    }

                    client.connected.store(false, Ordering::SeqCst);
                    // A closed sender means ClientImpl::close() requested shutdown.
                    if client.sender.lock().await.is_none() || !client.auto_reconnect {
                        break;
                    }

                    debug!("Reconnecting to xswd relayer in 5 seconds #{}...", state.get_id());
                    sleep(Duration::from_secs(5)).await;

                    match connect(&client.target).await {
                        Ok(new_ws) => {
                            ws = new_ws;
                            let output = match cipher.encrypt(registration.as_bytes()) {
                                Ok(output) => output.into_owned(),
                                Err(e) => {
                                    error!("Failed to encrypt XSWD relayer registration: {}", e);
                                    break;
                                }
                            };
                            if let Err(e) = ws.send(Message::Binary(output.into())).await {
                                error!("Failed to send XSWD relayer registration: {}", e);
                                break;
                            }
                            client.connected.store(true, Ordering::SeqCst);
                            debug!("Reconnected to xswd relayer #{}", state.get_id());
                        },
                        Err(e) => {
                            error!("Failed to reconnect to xswd relayer #{}: {}", state.get_id(), e);
                            break;
                        }
                    }
                }

                client.clear_event_listeners().await;
                relayer.on_close(state).await;

                client.task_handle.lock().await.take();
            })
        };
        client.task_handle.lock().await.replace(task);

        Ok(client)
    }

    /// Target URL of the relayer
    #[inline(always)]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Whether the relayer websocket is currently connected
    #[inline(always)]
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Send a message to the relayer
    pub async fn send_message<V: ToString>(&self, msg: V) -> bool {
        let lock = self.sender.lock().await;
        let Some(sender) = lock.as_ref() else {
            return false;
        };

        if let Err(e) = sender.send(msg.to_string()).await {
            error!("Error while sending message: {}", e);
            return false;
        }

        true
    }

    /// Close the connection to the relayer
    pub async fn close(&self) {
        debug!("Closing relayer client {}", self.target);

        // Dropping the last sender closes the channel. The receiver side uses
        // that closure as the shutdown signal, so no control message or
        // additional shutdown state is needed.
        if self.sender.lock().await.take().is_none() {
            debug!("Relayer client {} already closed", self.target);
            return;
        }

        let task = { self.task_handle.lock().await.take() };

        match task {
            Some(handle) => if let Err(e) = handle.await {
                error!("Error while waiting for background task to finish: {}", e);
            } else {
                debug!("Background task for relayer client {} finished", self.target);
            },
            None => {
                debug!("No background task to close for relayer client {}", self.target);
            }
        }
    }

    /// start the background task that listens for messages from the relayer and handles them
    async fn background_task<W>(
        client: &Client,
        mut ws: WebSocketStream,
        state: &AppStateShared,
        relayer: &XSWDRelayerShared<W>,
        receiver: &mut mpsc::Receiver<String>,
        cipher: &mut Cipher
    ) -> Result<(), anyhow::Error>
    where
        W: ShareableTid<'static> + XSWDHandler
    {
        loop {
            select! {
                msg = ws.next() => {
                    let msg = match msg {
                        Some(msg) => msg.context("Failed to receive message from XSWD relayer")?,
                        None => break,
                    };

                    let bytes: &[u8] = match &msg {
                        Message::Text(bytes) => bytes.as_ref(),
                        Message::Binary(bytes) => &bytes,
                        Message::Close(reason) => {
                            debug!("XSWD relayer connection closed: {:?}", reason);
                            break;
                        }
                    };

                    let output = cipher.decrypt(bytes)?;
                    let response = match relayer.on_message(state, &output).await {
                        Ok(response) => match response {
                            XSWDResponse::Request(value) => match value {
                                Some(v) => v,
                                None => continue,
                            },
                            XSWDResponse::Event(event, stream, value) => {
                                let mut lock = client.events.lock().await;

                                match stream {
                                    Some((mut stream, id)) => {
                                        if !lock.contains_key(&event) {
                                            // spawn a task to handle the event stream
                                            let client = client.clone();
                                            let handle = spawn_task("xswd-relayer-event-listener", async move {
                                                while let Ok(value) = stream.recv().await {
                                                    let response = json!(RpcResponse::new(Cow::Borrowed(&id), Cow::Borrowed(&value)));
                                                    if !client.send_message(response.to_string()).await {
                                                        break;
                                                    }
                                                }
                                            });

                                            lock.insert(event, handle);
                                        }
                                    },
                                    None => {
                                        if let Some(handle) = lock.remove(&event) {
                                            handle.abort();
                                        }
                                    }
                                }

                                match value {
                                    Some(v) => v,
                                    None => continue,
                                }
                            },
                        },
                        Err(e) => e.to_json()
                    };

                    // Encrypt response before sending
                    let encrypted_response = cipher.encrypt(response.to_string().as_bytes())?
                        .into_owned();
                    ws.send(Message::Binary(encrypted_response.into())).await?;
                },
                msg = receiver.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };

                    let output = cipher.encrypt(msg.as_bytes())?
                        .into_owned();
                    ws.send(Message::Binary(output.into())).await?;
                },
                else => break,
            };
        }

        Ok(())
    }
}