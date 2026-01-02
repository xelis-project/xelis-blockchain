use futures::{SinkExt, StreamExt};
use log::{error, debug};
use tokio_tungstenite_wasm::{
    WebSocketStream,
    Message,
    connect,
};
use xelis_common::tokio::{
    select,
    spawn_task,
    sync::mpsc
};

use crate::api::{
    xswd::relayer::{
        cipher::Cipher,
        XSWDRelayerShared
    },
    AppStateShared,
    EncryptionMode,
    XSWDHandler
};

enum InternalMessage {
    Send(String),
    Close,
}

pub struct Client {
    target: String,
    sender: mpsc::Sender<InternalMessage>,
}

impl Client {
    pub async fn new<W>(target: String, relayer: XSWDRelayerShared<W>, encryption_mode: Option<EncryptionMode>, state: AppStateShared) -> Result<Self, anyhow::Error>
    where
        W: Clone + Send + Sync + XSWDHandler + 'static
    {
        // Create a cipher based on the provided encryption mode
        let cipher = Cipher::new(encryption_mode)?;

        let ws = connect(&target).await?;
        let (sender, receiver) = mpsc::channel(64);
        spawn_task(format!("xswd-relayer-{}", state.get_id()), async move {
            if let Err(e) = Self::background_task(ws, &state, &relayer, receiver, cipher).await {
                debug!("Error on xswd relayer #{}: {}", state.get_id(), e);
            }

            relayer.on_close(state).await;
        });

        Ok(Self {
            target,
            sender,
        })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub async fn send_message<V: ToString>(&self, msg: V) {
        if let Err(e) = self.sender.send(InternalMessage::Send(msg.to_string())).await {
            error!("Error while sending message: {}", e);
        }
    }

    pub async fn close(&self) {
        if let Err(e) = self.sender.send(InternalMessage::Close).await {
            error!("Error while sending close message: {}", e);
        }
    }

    async fn background_task<W>(
        mut ws: WebSocketStream,
        state: &AppStateShared,
        relayer: &XSWDRelayerShared<W>,
        mut receiver: mpsc::Receiver<InternalMessage>,
        mut cipher: Cipher
    ) -> Result<(), anyhow::Error>
    where
        W: Clone + Send + Sync + XSWDHandler + 'static
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
                        Ok(None) => continue,
                        Ok(Some(value)) => value,
                        Err(e) => e.to_json()
                    };

                    ws.send(response.to_string().into()).await?;
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