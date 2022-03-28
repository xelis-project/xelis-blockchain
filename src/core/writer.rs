use crate::crypto::hash::Hash;

pub struct Writer {
    bytes: Vec<u8>
}

impl Writer {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new()
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
    }

    pub fn write_hash(&mut self, hash: &Hash) {
        self.bytes.extend(hash.as_bytes())
    }

    pub fn write_bool(&mut self, value: &bool) {
        self.bytes.push(if *value { 1 } else { 0 });
    }
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u16(&mut self, value: &u16) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: &u32) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u64(&mut self, value: &u64) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_string(&mut self, value: &String) {
        self.bytes.push(value.len() as u8);
        self.bytes.extend(value.as_bytes());
    }

    pub fn write_optional_string(&mut self, opt: &Option<String>) {
        match opt {
            Some(v) => {
                self.write_string(v);
            },
            None => {
                self.bytes.push(0);
            }
        };
    }

    pub fn total_write(&self) -> usize {
        self.bytes.len()
    }

    pub fn bytes(self) -> Vec<u8> {
        self.bytes
    }
}