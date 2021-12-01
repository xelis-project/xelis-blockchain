use std::net::TcpStream;
use std::io::Write;

pub struct Connection {
    id: usize, // TODO use a UUID
    stream: TcpStream
}

impl Connection {
    pub fn new(id: usize, stream: TcpStream) -> Self {
        Connection {
            id,
            stream
        }
    }

    pub fn send_bytes(&mut self, buf: &[u8]) {
        if let Err(e) = self.stream.write(buf) {
            panic!("Error while sending bytes to connection {}: {}", self.id, e);
        }
    }

    pub fn isAlive(&self) -> bool {
        false
    }
}

