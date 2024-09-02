use std::{
    borrow::Cow,
    collections::HashMap,
    hash::Hash,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc
    },
    time::Duration
};
use anyhow::Error;
use futures_util::{
    StreamExt,
    SinkExt
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Value, json};
use tokio_tungstenite_wasm::{
    WebSocketStream,
    connect,
    Message
};
use log::{debug, error, warn};
use crate::{
    tokio::{
        sync::{broadcast, oneshot, Mutex, mpsc},
        task::JoinHandle,
        time::{sleep, timeout},
        spawn_task,
        select
    },
    api::SubscribeParams,
    utils::sanitize_daemon_address
};

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

    // Get the next event
    // if we lagged behind, we will catch up
    // If you don't want to miss any event, you should create a queue to store them
    // or an unbounded channel
    pub async fn next(&mut self) -> Result<T, Error> {
        let mut res = self.inner.recv().await;
        // If we lagged behind, we need to catch up
        while let Err(e) = res {
            match e {
                broadcast::error::RecvError::Lagged(i) => {
                    error!("EventReceiver lagged {i} behind, catching up...");
                    res = self.inner.recv().await;
                }
                e => return Err(e.into())
            };
        }
 
        let value = res?;
        Ok(serde_json::from_value(value)?)
    }
}

// It is around a Arc to be shareable easily
// it has a tokio task running in background to handle all incoming messages
pub type WebSocketJsonRPCClient<E> = Arc<WebSocketJsonRPCClientImpl<E>>;

enum InternalMessage {
    Send(String),
    Close,
}

// A JSON-RPC Client over WebSocket protocol to support events
// It can be used in multi-thread safely because each request/response are linked using the id attribute.
pub struct WebSocketJsonRPCClientImpl<E: Serialize + Hash + Eq + Send + Sync + Clone + 'static> {
    sender: Mutex<mpsc::Sender<InternalMessage>>,
    // This is the ID for the next request
    count: AtomicUsize,
    // This contains all pending requests
    requests: Mutex<HashMap<usize, oneshot::Sender<JsonRPCResponse>>>,
    // This contains all id sent to register to a event on daemon
    // It stores the sender channel to propagate the event to apps 
    handler_by_id: Mutex<HashMap<usize, broadcast::Sender<Value>>>,
    // This contains all events registered by the app with its usize
    // This allows us to subscribe to same channel if its already subscribed
    events_to_id: Mutex<HashMap<E, usize>>,
    // websocket server address
    target: String,
    // delay auto reconnect duration
    delay_auto_reconnect: Mutex<Option<Duration>>,
    // is the client online
    online: AtomicBool,
    // This channel is called when the connection is lost
    offline_channel: Mutex<Option<broadcast::Sender<()>>>,
    // This channel is called each time we connect
    online_channel: Mutex<Option<broadcast::Sender<()>>>,
    // Background task that keep alive WS connection
    background_task: Mutex<Option<JoinHandle<()>>>,
    // Timeout for a request
    timeout_after: Duration,
}

pub const DEFAULT_AUTO_RECONNECT: Duration = Duration::from_secs(5);

impl<E: Serialize + Hash + Eq + Send + Sync + Clone + std::fmt::Debug + 'static> WebSocketJsonRPCClientImpl<E> {

    // Create a new WebSocketJsonRPCClient with the target address
    pub async fn new(mut target: String) -> Result<WebSocketJsonRPCClient<E>, JsonRPCError> {
        target = sanitize_daemon_address(target.as_str());
        let ws = connect(&target).await?;

        let (sender, receiver) = mpsc::channel(64);
        let client = Arc::new(WebSocketJsonRPCClientImpl {
            sender: Mutex::new(sender),
            count: AtomicUsize::new(0),
            requests: Mutex::new(HashMap::new()),
            handler_by_id: Mutex::new(HashMap::new()),
            events_to_id: Mutex::new(HashMap::new()),
            target,
            delay_auto_reconnect: Mutex::new(Some(DEFAULT_AUTO_RECONNECT)),
            online: AtomicBool::new(true),
            offline_channel: Mutex::new(None),
            online_channel: Mutex::new(None),
            background_task: Mutex::new(None),
            timeout_after: Duration::from_secs(5),
        });

        // Start the background task
        {
            let zelf = client.clone();
            zelf.start_background_task(receiver, ws).await?;
        }

        Ok(client)
    }

    // Get the target address
    pub fn get_target(&self) -> &str {
        &self.target
    }

    // Generate a new ID for a JSON-RPC request
    fn next_id(&self) -> usize {
        self.count.fetch_add(1, Ordering::SeqCst)
    }

    // Notify a channel if we lose/gain the connection
    async fn notify_connection_channel(&self, mutex: &Mutex<Option<broadcast::Sender<()>>>) {
        let mut channel = mutex.lock().await;
        if let Some(sender) = channel.as_ref() {
            // Nobody listen anymore, close the channel
            if sender.receiver_count() == 0 {
                *channel = None;
            } else {
                // Notify receivers
                if let Err(e) = sender.send(()) {
                    error!("Error sending event to the request: {:?}", e);
                }
            }
        }
    }

    // Register to a channel
    async fn register_to_connection_channel(&self, mutex: &Mutex<Option<broadcast::Sender<()>>>) -> broadcast::Receiver<()> {
        let mut channel = mutex.lock().await;
        match channel.as_ref() {
            Some(sender) => sender.subscribe(),
            None => {
                let (sender, receiver) = broadcast::channel(1);
                *channel = Some(sender);
                receiver
            }
        }
    }

    // Call this function to be notified by a channel when we lose the connection
    pub async fn on_connection_lost(&self) -> broadcast::Receiver<()> {
        self.register_to_connection_channel(&self.offline_channel).await
    }

    // Call this function to be notified by a channel when we are connected to the server
    pub async fn on_connection(&self) -> broadcast::Receiver<()> {
        self.register_to_connection_channel(&self.online_channel).await
    }
    
    // Should the client try to reconnect to the server if the connection is lost
    pub async fn should_auto_reconnect(&self) -> bool {
        self.delay_auto_reconnect.lock().await.is_some()
    }

    // Set if the client should try to reconnect to the server if the connection is lost
    pub async fn set_auto_reconnect_delay(&self, duration: Option<Duration>) {
        let mut reconnect = self.delay_auto_reconnect.lock().await;
        *reconnect = duration;
    }

    // Is the client online
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }

    // resubscribe to all events because of a reconnection
    async fn resubscribe_events(self: Arc<Self>) -> Result<(), JsonRPCError> {
        let events = {
            let events = self.events_to_id.lock().await;
            events.clone()
        };

        spawn_task("resubscribe-events", async move {
            for (event, id) in events {
                debug!("Resubscribing to event {:?} with id {}", event, id);

                // Send it to the server
                let res = match self.send::<_, bool>("subscribe", Some(id), &SubscribeParams {
                    notify: Cow::Borrowed(&event),
                }).await {
                    Ok(res) => res,
                    Err(e) => {
                        error!("Error while resubscribing to event with id {}: {:?}", id, e);
                        false
                    }
                };

                if !res {
                    error!("Error while resubscribing to event with id {}", id);
                }
            }
        });
        Ok(())
    }

    // This will stop the task keeping the connection with the node
    pub async fn disconnect(&self) -> Result<(), Error> {
        self.set_auto_reconnect_delay(None).await;
        self.set_online(false).await;
        {

            self.sender.lock().await.send(InternalMessage::Close).await?;
        }
        {
            let task = self.background_task.lock().await.take();
            if let Some(task) = task {
                task.abort();
            }
        }

        // Clear all data
        self.clear_events().await;
        self.clear_requests().await;

        Ok(())
    }

    // Set the online status
    async fn set_online(&self, online: bool) {
        let old = self.online.swap(online, Ordering::SeqCst);
        if old != online {
            if online {
                self.notify_connection_channel(&self.online_channel).await;
            } else {
                self.notify_connection_channel(&self.offline_channel).await;
            }
        }
    }

    // Reconnect by starting again the background task
    pub async fn reconnect(self: &Arc<Self>) -> Result<bool, Error> {
        if self.is_online() {
            warn!("Already connected to the server");
            return Ok(false)
        }

        let ws = connect(&self.target).await?;
        {
            let mut lock = self.background_task.lock().await;
            if let Some(handle) = lock.take() {
                handle.abort();
            }
        }
        {
            let (sender, receiver) = mpsc::channel(64);
            let mut lock = self.sender.lock().await;
            *lock = sender;

            let zelf = Arc::clone(&self);
            zelf.start_background_task(receiver, ws).await?;
        }


        if let Err(e) = Arc::clone(&self).resubscribe_events().await {
            error!("Error while resubscribing to events: {:?}", e);
        }

        Ok(true)
    }

    // Clear all pending requests to notifier the caller that the connection is lost
    async fn clear_requests(&self) {
        let mut requests = self.requests.lock().await;
        requests.clear();
    }

    // Clear all events
    // Because they are all channels, they will returns error to the caller
    async fn clear_events(&self) {
        {
            let mut events = self.events_to_id.lock().await;
            events.clear();
        }
        {
            let mut handlers = self.handler_by_id.lock().await;
            handlers.clear();
        }
    }

    async fn start_background_task(self: Arc<Self>, mut receiver: mpsc::Receiver<InternalMessage>, ws: WebSocketStream) -> Result<(), JsonRPCError> {
        let zelf = Arc::clone(&self);
        let handle = spawn_task("ws-background-task", async move {
            let mut ws = Some(ws);
            while let Some(websocket) = ws.take() {
                zelf.set_online(true).await;

                match zelf.background_task(&mut receiver, websocket).await {
                    Ok(()) => {
                        debug!("Closing background task");
                        {
                            let mut lock = zelf.background_task.lock().await;
                            *lock = None;
                        }

                        // Do a clean up
                        zelf.clear_requests().await;
                        zelf.clear_events().await;

                        return;
                    },
                    Err(e) => {
                        error!("Error in the WebSocket client background task: {:?}", e);
                    }
                }

                // Clear all pending requests
                zelf.clear_requests().await;

                zelf.set_online(false).await;

                // retry to connect until we are online or that it got disabled
                while let Some(auto_reconnect) = { zelf.delay_auto_reconnect.lock().await.as_ref().cloned() } {
                    debug!("Reconnecting to the server in {} seconds...", auto_reconnect.as_secs());
                    sleep(auto_reconnect).await;

                    match connect(&zelf.target).await {
                        Ok(websocket) => {
                            ws = Some(websocket);

                            // Register all events again
                            if let Err(e) = Arc::clone(&zelf).resubscribe_events().await {
                                error!("Error while resubscribing to events due to reconnect: {:?}", e);
                            }

                            break;
                        }
                        Err(e) => {
                            debug!("Error while reconnecting to the server: {:?}", e);
                        }
                    }
                }
            }

            zelf.clear_events().await;
        });

        {
            let mut lock = self.background_task.lock().await;
            if let Some(handle) = lock.take() {
                warn!("Task was still set while starting a new one, aborting it...");
                handle.abort();
            }

            *lock = Some(handle);
        }

        Ok(())        
    }

    // Background task that keep alive WS connection
    async fn background_task(self: &Arc<Self>, receiver: &mut mpsc::Receiver<InternalMessage>, ws: WebSocketStream) -> Result<(), JsonRPCError> {
        let (mut write, mut read) = ws.split();
        loop {
            select! {
                Some(msg) = receiver.recv() => {
                    match msg {
                        InternalMessage::Send(text) => {
                            write.send(Message::Text(text)).await?;
                        },
                        InternalMessage::Close => {
                            write.close().await?;
                            break;
                        }
                    }
                },
                Some(res) = read.next() => {
                    let msg = res?;
                    match msg {
                        Message::Text(text) => {
                            let response: JsonRPCResponse = serde_json::from_str(&text)?;
                            if let Some(id) = response.id {
                                // send the response to the requester if it matches the ID
                                {
                                    let mut requests = self.requests.lock().await;
                                    if let Some(sender) = requests.remove(&id) {
                                        if let Err(e) = sender.send(response) {
                                            debug!("Error sending response to the request: {:?}", e);
                                        }
                                        continue;
                                    }
                                }
        
                                // Check if this ID corresponds to a event subscribed
                                {
                                    let mut handlers = self.handler_by_id.lock().await;
                                    if let Some(sender) = handlers.get_mut(&id) {
                                        // Check that we still have someone who listen it
                                        if let Err(e) = sender.send(response.result.unwrap_or_default()) {
                                            debug!("Error sending event to the request: {:?}", e);
                                        }
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
    // Capacity represents the number of events that can be stored in the channel
    pub async fn subscribe_event<T: DeserializeOwned>(&self, event: E, capacity: usize) -> JsonRPCResult<EventReceiver<T>> {
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
        self.send::<_, bool>("subscribe", Some(id), &SubscribeParams {
            notify: Cow::Borrowed(&event)
        }).await?;

        // Create a mapping from the event to the ID used for the request
        {
            let mut ids = self.events_to_id.lock().await;
            ids.insert(event, id);
        }

        // Create a channel to receive the event
        let (sender, receiver) = broadcast::channel(capacity);
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

    // Send a request to the sender channel that will be sent to the server
    async fn send_message_internal<P: Serialize>(&self, id: Option<usize>, method: &str, params: &P) -> JsonRPCResult<()> {
        let sender = self.sender.lock().await;
        sender.send(InternalMessage::Send(serde_json::to_string(&json!({
            "jsonrpc": JSON_RPC_VERSION,
            "method": method,
            "id": id,
            "params": params
        }))?)).await.map_err(|e| JsonRPCError::SendError(e.to_string()))?;

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

        self.send_message_internal(Some(id), method, params).await?;

        let response = timeout(self.timeout_after, receiver).await
            .or(Err(JsonRPCError::TimedOut))?
            .or(Err(JsonRPCError::NoResponse))?;

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

    // Send a request to the server without waiting for the response
    pub async fn notify_with<P: Serialize>(&self, method: &str, params: &P) -> JsonRPCResult<()> {
        self.send_message_internal(None, method, params).await?;
        Ok(())
    }

    // Send a request to the server without waiting for the response
    pub async fn notify<P: Serialize>(&self, method: &str) -> JsonRPCResult<()> {
        self.notify_with(method, &Value::Null).await
    }
}