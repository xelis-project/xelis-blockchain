use crate::crypto::Hash;

pub struct Writer<'a> {
    bytes: &'a mut Vec<u8>,
    len: usize,
}

impl<'a> Writer<'a> {
    pub fn new(bytes: &'a mut Vec<u8>) -> Self {
        Self {
            len: bytes.len(),
            bytes
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
    }

    pub fn write_hash(&mut self, hash: &Hash) {
        self.bytes.extend(hash.as_bytes())
    }

    pub fn write_bool(&mut self, value: bool) {
        self.bytes.push(if value { 1 } else { 0 });
    }
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: &u32) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u64(&mut self, value: &u64) {
        self.bytes.extend(value.to_be_bytes());
    }

    pub fn write_u128(&mut self, value: &u128) {
        self.bytes.extend(value.to_be_bytes());
    }

    // max 255 bytes
    pub fn write_string(&mut self, value: &str) {
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

    pub fn write_optional_non_zero_u8(&mut self, opt: Option<u8>) {
        self.bytes.push(opt.unwrap_or(0));
    }

    pub fn write_optional_non_zero_u16(&mut self, opt: Option<u16>) {
        self.write_u16(opt.unwrap_or(0));
    }

    pub fn write_optional_non_zero_u64(&mut self, opt: Option<u64>) {
        self.write_u64(&opt.unwrap_or(0));
    }

    pub fn total_write(&self) -> usize {
        self.bytes.len() - self.len
    }

    pub fn as_mut_bytes(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
