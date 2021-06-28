pub struct Address {
    network: u8,
    public_key: [u8; 32]
}

impl Address {
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(self.network);
        bytes.extend(&self.public_key);

        bytes
    }
}