#[derive(Debug, Clone, Copy)]
pub struct Flags(u8);

impl Flags {
    // No flag enabled
    pub const NONE: u8 = 0;
    // allow to be shared with others peers
    pub const SHARED: u8 = 1 << 0;
    // support the compression mode
    pub const COMPRESSION: u8 = 1 << 2;

    #[inline]
    pub fn new(bits: u8) -> Self {
        Self(bits)
    }

    #[inline]
    pub fn contains(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    #[inline]
    pub fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }

    #[inline]
    pub fn remove(&mut self, flag: u8) {
        self.0 &= !flag;
    }

    #[inline]
    pub fn bits(&self) -> u8 {
        self.0
    }
}