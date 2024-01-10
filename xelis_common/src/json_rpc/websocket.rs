use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc
    },
    collections::HashMap,
    hash::Hash,
    marker::PhantomData
};

use anyhow::Error;
use futures_util::{StreamExt, stream::{SplitSink, SplitStream}, SinkExt};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Value, json};
use tokio::{net::TcpStream, sync::{Mutex, oneshot, broadcast}};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream, connect_async, tungstenite::Message};
use log::error;

use super::{JSON_RPC_VERSION, JsonRPCError, JsonRPCResponse, JsonRPCResult};

// EventReceiver allows to get the event value parsed directly
pub struct EventReceiver<T: DeserializeOwned> {
    inner: broadcast::Receiver<Value>,
    _phantom: PhantomData<T>
}

impl<T: DeserializeOwned> EventReceiver<T> {
    pub fn new(inner: broadcast::Receiver<Value>) -> Self {
        Self {
            inner,
            _phantom: PhantomData
        }
    }

    pub async fn next(&mut self) -> Result<T, Error> {
        let value = self.inner.recv().await?;
        Ok(serde_json::from_value(value)?)
    }
}

// It is around a Arc to be shareable easily
// it has a tokio task running in background to handle all incoming messages
pub type WebSocketJsonRPCClient<E> = Arc<WebSocketJsonRPCClientImpl<E>>;

// A JSON-RPC Client over WebSocket protocol to support events
// It can be used in multi-thread safely because each request/response are linked using the id attribute.
pub struct WebSocketJsonRPCClientImpl<E: Serialize + Hash + Eq + Send + 'static> {
    ws: Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
    count: AtomicUsize,
    requests: Mutex<HashMap<usize, oneshot::Sender<JsonRPCResponse>>>,
    handler_by_id: Mutex<HashMap<usize, broadcast::Sender<Value>>>,
    events_to_id: Mutex<HashMap<E, usize>>,
}

impl<E: Serialize + Hash + Eq + Send + 'static> WebSocketJsonRPCClientImpl<E> {
    pub async fn new(mut target: String) -> Result<WebSocketJsonRPCClient<E>, JsonRPCError> {
        if target.starts_with("https://") {
            target.replace_range(..8, "wss://");
        }
        else if target.starts_with("http://") {
            target.replace_range(..7, "ws://");
        }
        else if !target.starts_with("ws://") && !target.starts_with("wss://") {
            target.insert_str(0, "ws://");
        }

        let (ws, response) = connect_async(target).await?;
        let status = response.status();
        if status.is_server_error() || status.is_client_error() {
            return Err(JsonRPCError::ConnectionError(status.to_string()));
        }
        
        let (write, read) = ws.split();
        let client = Arc::new(WebSocketJsonRPCClientImpl {
            ws: Mutex::new(write),
            count: AtomicUsize::new(0),
            requests: Mutex::new(HashMap::new()),
            handler_by_id: Mutex::new(HashMap::new()),
            events_to_id: Mutex::new(HashMap::new()),
        });

        {
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(e) = client.read(read).await {
                    error!("Error in the WebSocket client ioloop: {:?}", e);
                };
            });
        }

        Ok(client)
    }

    // Generate a new ID for a JSON-RPC request
    fn next_id(&self) -> usize {
        self.count.fetch_add(1, Ordering::SeqCst)
    }

    // Task running in background to handle every messages from the WebSocket server
    // This includes Events propagated and responses to JSON-RPC requests
    async fn read(&self, mut read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>) -> Result<(), JsonRPCError> {
        while let Some(res) = read.next().await {
            let msg = res?;
            match msg {
                Message::Text(text) => {
                    let response: JsonRPCResponse = serde_json::from_str(&text)?;
                    if let Some(id) = response.id {
                        // Check if this ID corresponds to a event subscribed
                        {
                            let mut handlers = self.handler_by_id.lock().await;
                            if let Some(sender) = handlers.get_mut(&id) {
                                // Check that we still have someone who listen it
                                if sender.receiver_count() > 0 {
                                    if let Err(e) = sender.send(response.result.unwrap_or_default()) {
                                        error!("Error sending event to the request: {:?}", e);
                                    }
                                }
                                continue;
                            }
                        }

                        // send the response to the requester
                        let mut requests = self.requests.lock().await;
                        if let Some(sender) = requests.remove(&id) {
                            if let Err(e) = sender.send(response) {
                                error!("Error sending response to the request: {:?}", e);
                            }
                        }
                    }
                },
                Message::Close(_) => {
                    break;
                },
                _ => {}
            }
        }

        Ok(())
    }

    // Call a method without parameters
    pub async fn call<R: DeserializeOwned>(&self, method: &str) -> JsonRPCResult<R> {
        self.send(method, None, &Value::Null).await
    }

    // Call a method with parameters
    pub async fn call_with<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: &P) -> JsonRPCResult<R> {
        self.send(method, None, params).await
    }

    // Verify if we already subscribed to this event or not
    pub async fn has_event(&self, event: &E) -> bool {
        let events = self.events_to_id.lock().await;
        events.contains_key(&event)
    }

    // Subscribe to an event
    pub async fn subscribe_event<T: DeserializeOwned>(&self, event: E) -> JsonRPCResult<EventReceiver<T>> {
        // Returns a Receiver for this event if already registered
        {
            let ids = self.events_to_id.lock().await;
            if let Some(id) = ids.get(&event) {
                let handlers = self.handler_by_id.lock().await;
                if let Some(sender) = handlers.get(id) {
                    return Ok(EventReceiver::new(sender.subscribe()));
                }
            }
        }

        // Generate the ID for this request
        let id = self.next_id();

        // Send it to the server
        self.send::<E, bool>("subscribe", Some(id), &event).await?;
        
        // Create a mapping from the event to the ID used for the request
        {
            let mut ids = self.events_to_id.lock().await;
            ids.insert(event, id);
        }

        // Create a channel to receive the event
        let (sender, receiver) = broadcast::channel(1);
        {
            let mut handlers = self.handler_by_id.lock().await;
            handlers.insert(id, sender);
        }

        Ok(EventReceiver::new(receiver))
    }

    // Unsubscribe from an event
    pub async fn unsubscribe_event(&self, event: &E) -> JsonRPCResult<()> {        
        // Retrieve the id for this event
        let id = {
            let mut ids = self.events_to_id.lock().await;
            ids.remove(event).ok_or(JsonRPCError::EventNotRegistered)?
        };

        // Send the unsubscribe rpc method
        self.send::<E, bool>("unsubscribe", None, event).await?;

        // delete it from events list
        {
            let mut handlers = self.handler_by_id.lock().await;
            handlers.remove(&id);
        }

        Ok(())
    }

    // Send a request to the server and wait for the response
    async fn send<P: Serialize, R: DeserializeOwned>(&self, method: &str, id: Option<usize>, params: &P) -> JsonRPCResult<R> {
        let id = id.unwrap_or_else(|| self.next_id());
        let (sender, receiver) = oneshot::channel();
        {
            let mut requests = self.requests.lock().await;
            requests.insert(id, sender);
        }

        {
            let mut ws = self.ws.lock().await;
            ws.send(Message::Text(serde_json::to_string(
                &json!(
                    {
                        "jsonrpc": JSON_RPC_VERSION,
                        "method": method,
                        "id": id,
                        "params": params
                    }
                )
            )?)).await?;
        }

        let response = receiver.await.or(Err(JsonRPCError::NoResponse))?;
        if let Some(error) = response.error {
            return Err(JsonRPCError::ServerError {
                code: error.code,
                message: error.message,
                data: error.data.map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
            });
        }

        let result = response.result.ok_or(JsonRPCError::NoResponse)?;

        Ok(serde_json::from_value(result)?)
    }
}