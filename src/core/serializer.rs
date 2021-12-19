pub trait Serializer {
    fn to_bytes(&self) -> Vec<u8>;

    fn size(&self) -> usize {
        self.to_bytes().len()
    }

    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>>;
}