use std::{borrow::Cow, collections::HashMap, sync::Arc, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};

use futures::{SinkExt, StreamExt};
use log::{debug, error, warn};
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

enum InternalMessage {
    Send(String),
    Close,
}

pub struct ClientImpl {
    target: String,
    sender: mpsc::Sender<InternalMessage>,
    events: Mutex<HashMap<NotifyEvent, task::JoinHandle<()>>>,
    connected: AtomicBool,
    auto_reconnect: bool,
    task_handle: Mutex<Option<task::JoinHandle<()>>>
}

pub type Client = Arc<ClientImpl>;

impl ClientImpl {
    pub async fn new<W>(
        target: String,
        relayer: XSWDRelayerShared<W>,
        encryption_mode: Option<EncryptionMode>,
        state: AppStateShared,
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
            sender,
            events: Mutex::new(HashMap::new()),
            connected: AtomicBool::new(true),
            auto_reconnect,
            task_handle: Mutex::new(None),
        });

        let task = {
            let client = client.clone();
            spawn_task(format!("xswd-relayer-{}", state.get_id()), async move {
                loop {
                    match Self::background_task(&client, ws, &state, &relayer, &mut receiver, &mut cipher).await {
                        Ok(()) => {
                            client.connected.store(false, Ordering::SeqCst);
                            break;
                        },
                        Err(e) => {
                            client.connected.store(false, Ordering::SeqCst);
                            debug!("Error on xswd relayer #{}: {}", state.get_id(), e);

                            if client.auto_reconnect {
                                debug!("Reconnecting to xswd relayer in 5 seconds #{}...", state.get_id());
                                sleep(Duration::from_secs(5)).await;

                                match connect(&client.target).await {
                                    Ok(new_ws) => {
                                        debug!("Reconnected to xswd relayer #{}", state.get_id());
                                        ws = new_ws;
                                        client.connected.store(true, Ordering::SeqCst);

                                        // Loop to try again
                                        continue;
                                    },
                                    Err(e) => {
                                        error!("Failed to reconnect to xswd relayer #{}: {}", state.get_id(), e);
                                    }
                                }
                            }

                            break;
                        }
                    }
                }

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
        if let Err(e) = self.sender.send(InternalMessage::Send(msg.to_string())).await {
            error!("Error while sending message: {}", e);
            return false;
        }

        true
    }

    /// Close the connection to the relayer
    pub async fn close(&self) {
        let task = { self.task_handle.lock().await.take() };

        match task {
            Some(handle) => match self.sender.send(InternalMessage::Close).await {
                Ok(()) => {
                    if let Err(e) = handle.await {
                        error!("Error while waiting for background task to finish: {}", e);
                    } else {
                        debug!("Background task for relayer client {} finished", self.target);
                    }
                },
                Err(e) => {
                    warn!("Couldn't send close message: {}, aborting task", e);
                    handle.abort();
                }
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
        receiver: &mut mpsc::Receiver<InternalMessage>,
        cipher: &mut Cipher
    ) -> Result<(), anyhow::Error>
    where
        W: ShareableTid<'static> + XSWDHandler
    {
        loop {
            select! {
                msg = ws.next() => {
                    let Some(Ok(msg)) = msg else {
                        break;
                    };

                    let bytes: &[u8] = match &msg {
                        Message::Text(bytes) => bytes.as_ref(),
                        Message::Binary(bytes) => &bytes,
                        Message::Close(_) => {
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

                    match msg {
                        InternalMessage::Send(msg) => {
                            let output = cipher.encrypt(msg.as_bytes())?
                                .into_owned();
                            ws.send(Message::Binary(output.into())).await?;
                        },
                        InternalMessage::Close => break,
                    }
                },
                else => break,
            };
        }

        Ok(())
    }
}