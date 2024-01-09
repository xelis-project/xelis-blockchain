use std::{sync::{atomic::{AtomicUsize, Ordering}, Arc}, collections::HashMap, hash::Hash};

use futures_util::{StreamExt, stream::{SplitSink, SplitStream}, SinkExt};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Value, json};
use tokio::{net::TcpStream, sync::{Mutex, oneshot, mpsc}};
use tokio_tungstenite::{WebSocketStream, MaybeTlsStream, connect_async, tungstenite::Message};

use super::{JSON_RPC_VERSION, JsonRPCError, JsonRPCResponse, JsonRPCResult};

pub type WebSocketJsonRPCClient<E> = Arc<WebSocketJsonRPCClientImpl<E>>;

pub struct WebSocketJsonRPCClientImpl<E: Serialize + Hash + Eq + Send + 'static> {
    ws: Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
    count: AtomicUsize,
    requests: Mutex<HashMap<usize, oneshot::Sender<JsonRPCResponse>>>,
    handler_by_id: Mutex<HashMap<usize, mpsc::Sender<Value>>>,
    events_to_id: Mutex<HashMap<E, usize>>,
}

impl<E: Serialize + Hash + Eq + Send + 'static> WebSocketJsonRPCClientImpl<E> {
    pub async fn new(target: String) -> Result<WebSocketJsonRPCClient<E>, JsonRPCError> {
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
                    println!("Error in the WebSocket client ioloop: {:?}", e);
                };
            });
        }

        Ok(client)
    }

    fn next_id(&self) -> usize {
        self.count.fetch_add(1, Ordering::SeqCst)
    }

    async fn read(&self, mut read: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>) -> Result<(), JsonRPCError> {
        while let Some(res) = read.next().await {
            let msg = res?;
            match msg {
                Message::Text(text) => {
                    let response: JsonRPCResponse = serde_json::from_str(&text)?;
                    if let Some(id) = response.id {
                        {
                            let mut events = self.handler_by_id.lock().await;
                            if let Some(sender) = events.get_mut(&id) {
                                if let Err(e) = sender.send(response.result.unwrap_or_default()).await {
                                    println!("Error sending event to the request: {:?}", e);
                                }
                                continue;
                            }
                        }

                        let mut requests = self.requests.lock().await;
                        if let Some(sender) = requests.remove(&id) {
                            if let Err(e) = sender.send(response) {
                                println!("Error sending response to the request: {:?}", e);
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

    // Subscribe to an event
    pub async fn subscribe_event(&self, event: E) -> JsonRPCResult<mpsc::Receiver<Value>> {
        // Generate the ID for this request
        let id = self.next_id();
        // Send it to the server
        self.send::<E, bool>("subscribe", Some(id), &event).await?;

        // Create a channel to receive the event
        let (sender, receiver) = mpsc::channel(1);
        {
            let mut events = self.handler_by_id.lock().await;
            events.insert(id, sender);
        }
        // Create a mapping from the event to the ID used for the request
        {
            let mut events = self.events_to_id.lock().await;
            events.insert(event, id);
        }

        Ok(receiver)
    }

    // Unsubscribe from an event
    pub async fn unsubscribe_event(&self, event: &E) -> JsonRPCResult<()> {
        let id = self.next_id();
        self.send::<E, bool>("unsubscribe", Some(id), event).await?;

        let id = {
            let mut events = self.events_to_id.lock().await;
            events.remove(event).ok_or(JsonRPCError::EventNotRegistered)?
        };

        {
            let mut events = self.handler_by_id.lock().await;
            events.remove(&id);
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