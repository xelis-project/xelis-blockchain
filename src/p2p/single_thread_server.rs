use super::server::P2pServer;
use super::connection::Connection;
use super::error::P2pError;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::{TcpListener, SocketAddr, Shutdown};
use std::sync::mpsc::{Sender, Receiver, channel};

enum Message {
    SendBytes(u64, Vec<u8>), // peer id, bytes
    AddConnection(Arc<Connection>),
    RemoveConnection(u64),
    Exit,
}

// SingleThreadServer only use 2 threads: one for incoming new connections
// and one for listening/sending data to all connections already accepted
// useful for low end hardware
pub struct SingleThreadServer {
    peer_id: u64, // unique peer id
    tag: Option<String>, // node tag sent on handshake
    max_peers: usize, // max peers accepted by this server
    bind_address: String, // ip:port address to receive connections
    connections: Mutex<HashMap<u64, Arc<Connection>>>, // all connections accepted
    sender: Mutex<Sender<Message>>, // sender to send messages to the thread #2
    receiver: Mutex<Receiver<Message>> // only used by the thread #2
}

impl SingleThreadServer {

    fn listen_new_connections(&self) {
        println!("Connecting to seed nodes..."); // TODO only if peerlist is empty
        // allocate this buffer only one time, because we are using the same thread
        let mut buffer: [u8; 512] = [0; 512]; // maximum 512 bytes for handshake
        if let Err(e) = self.connect_to_seed_nodes(&mut buffer) {
            println!("Error while connecting to seed nodes: {}", e);
        }

        println!("Starting p2p server...");
        let listener = TcpListener::bind(self.get_bind_address()).unwrap();

        println!("Waiting for connections...");
        for stream in listener.incoming() { // main thread verify all new connections
            println!("New incoming connection");
            match stream {
                Ok(stream) => {
                    if !self.accept_new_connections() { // if we have already reached the limit, we ignore this new connection
                        println!("Max peers reached, rejecting connection");
                        if let Err(e) = stream.shutdown(Shutdown::Both) {
                            println!("Error while closing & ignoring incoming connection: {}", e);
                        }
                        continue;
                    }

                    if let Err(e) = self.handle_new_connection(&mut buffer, stream, false) {
                        println!("Error on new connection: {}", e);
                    }
                }
                Err(e) => {
                    println!("Error while accepting new connection: {}", e);
                }
            }
        }
    }

    // listening connections thread
    fn listen_existing_connections(&self) {
        println!("Starting single thread connection listener...");
        // TODO extend buffer as we have verified this peer
        let mut connections: HashMap<u64, Arc<Connection>> = HashMap::new();
        let mut buf: [u8; 512] = [0; 512]; // allocate this buffer only one time
        loop {
            while let Ok(msg) = self.receiver.lock().unwrap().try_recv() { // read all messages from channel
                match msg {
                    Message::Exit => {
                        return;
                    },
                    Message::AddConnection(connection) => {
                        connections.insert(connection.get_peer_id(), connection);
                    }
                    Message::RemoveConnection(peer_id) => {
                        connections.remove(&peer_id);
                    }
                    Message::SendBytes(peer_id, bytes) => {
                        if let Some(connection) = connections.get(&peer_id) {
                            if let Err(e) = connection.send_bytes(&bytes) {
                                println!("Error on sending bytes: {}", e);
                                connections.remove(&peer_id);
                            }
                        }
                    }
                }
            }

            for connection in connections.values() {
                self.listen_connection(&mut buf, &connection)
            }
        }
    }
}

impl Drop for SingleThreadServer {
    fn drop(&mut self) { // TODO
        let _ = self.sender.lock().unwrap().send(Message::Exit);
    }
}

impl P2pServer for SingleThreadServer {
    fn new(peer_id: u64, tag: Option<String>, max_peers: usize, bind_address: String) -> Self {
        if let Some(tag) = &tag {
            assert!(tag.len() > 0 && tag.len() <= 16);
        }

        // set channel to communicate with listener thread
        let (sender, receiver) = channel();

        SingleThreadServer {
            peer_id,
            tag,
            max_peers,
            bind_address,
            connections: Mutex::new(HashMap::new()),
            sender: Mutex::new(sender),
            receiver: Mutex::new(receiver)
        }
    }

    fn start(&self) {
        use crossbeam::thread;
        thread::scope(|s| {
            s.spawn(|_| {
                self.listen_new_connections();
            });

            s.spawn(|_| {
                self.listen_existing_connections();
            });
        }).unwrap();
    }

    fn stop(self) {
        // TODO close connections & stop threads,
    } 

    fn get_tag(&self) -> &Option<String> {
        &self.tag
    }

    fn get_max_peers(&self) -> usize {
        self.max_peers
    }

    fn get_peer_id(&self) -> u64 {
        self.peer_id
    }

    fn accept_new_connections(&self) -> bool {
        self.get_peer_count() < self.max_peers
    }

    fn get_peer_count(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    fn get_slots_available(&self) -> usize {
        self.max_peers - self.get_peer_count()
    }

    fn is_connected_to(&self, peer_id: &u64) -> Result<bool, P2pError> {
        match self.connections.lock() {
            Ok(connections) => {
                Ok(self.peer_id == *peer_id || connections.contains_key(peer_id))
            },
            Err(e) => Err(P2pError::OnLock(format!("is connected to {}: {}", peer_id, e)))
        }
    }

    fn is_connected_to_addr(&self, peer_addr: &SocketAddr) -> Result<bool, P2pError> {
        for connection in self.get_connections()? {
            if *connection.get_peer_address() == *peer_addr {
                return Ok(true)
            }
        }
        Ok(false)
    }

    fn is_multi_threaded(&self) -> bool {
        false
    }

    fn get_bind_address(&self) -> &String {
        &self.bind_address
    }
 
    fn get_connection(&self, peer_id: &u64) -> Result<Arc<Connection>, P2pError> {
        match self.connections.lock() {
            Ok(ref connections) => {
                match connections.get(peer_id) {
                    Some(connection) => Ok(connection.clone()), // TODO found a better way instead of clone
                    None => Err(P2pError::PeerNotFound(*peer_id))
                }
            }
            Err(e) => {
                Err(P2pError::OnLock(format!("trying to get {}: {}", peer_id, e)))
            }
        }
    }

    // return a 'Receiver' struct if we are in multi thread mode
    // in single mode, we only have one channel
    fn add_connection(&self, connection: Connection) -> Result<(), P2pError> {
        match self.connections.lock() {
            Ok(mut connections) => {
                let peer_id = connection.get_peer_id();
                let arc_connection = Arc::new(connection);
                match connections.insert(peer_id, arc_connection.clone()) {
                    Some(c) => {
                        panic!("Connection {} already exists!", c)
                        //Err(P2pError::PeerIdAlreadyUsed(peer_id)) // should not happen
                    },
                    None => match self.sender.lock() {
                        Ok(ref channel) => {
                            match channel.send(Message::AddConnection(arc_connection)) {
                                Ok(_) => {
                                    println!("add new connection (total {}): {}", connections.len(), self.bind_address);
                                    Ok(())
                                }
                                Err(e) => Err(P2pError::OnChannelMessage(peer_id, format!("{}", e)))
                            }
                        },
                        Err(e) => Err(P2pError::OnLock(format!("trying to add {} to thread: {}", arc_connection, e)))
                    }
                }
            }
            Err(e) => {
                Err(P2pError::OnLock(format!("trying to add {}: {}", connection, e)))
            }
        }
    }

    fn remove_connection(&self, peer_id: &u64) -> Result<(), P2pError> {
        match self.connections.lock().unwrap().remove(peer_id) {
            Some(connection) => {
                if !connection.is_closed() {
                    if let Err(e) = connection.close() {
                        return Err(P2pError::OnConnectionClose(format!("trying to remove {}: {}", peer_id, e)));
                    }
                }
                println!("{} disconnected", connection);

                match self.sender.lock() {
                    Ok(channel) => {
                        if let Err(e) = channel.send(Message::RemoveConnection(*peer_id)) {
                            Err(P2pError::OnChannelMessage(*peer_id, format!("{}", e)))
                        } else {
                            Ok(())
                        }
                    }
                    Err(e) => {
                        Err(P2pError::OnLock(format!("trying to remove {}: {}", peer_id, e)))
                    }
                }
            },
            None => Err(P2pError::PeerNotFound(*peer_id)),
        }
    }

    fn get_connections(&self) -> Result<Vec<Arc<Connection>>, P2pError> {
        match self.connections.lock() {
            Ok(connections) => {
                Ok(connections.values().map(|arc| { arc.clone() }).collect()) // TODO Found a better way instead of cloning
            },
            Err(e) => Err(P2pError::OnLock(format!("trying to get connections: {}", e)))
        }
    }

    // notify the thread that own the target peer through channel
    fn send_to_peer(&self, peer_id: u64, bytes: Vec<u8>) -> Result<(), P2pError> {
        match self.sender.lock() {
            Ok(chan) => {
                if let Err(e) = chan.send(Message::SendBytes(peer_id, bytes)) {
                    Err(P2pError::OnChannelMessage(peer_id, format!("'SendBytes': {}", e)))
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                Err(P2pError::OnLock(format!("send_to_peer: {}", e))) 
            }
        }
    }
}