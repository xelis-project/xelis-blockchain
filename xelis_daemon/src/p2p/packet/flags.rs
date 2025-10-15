#[derive(Debug, Clone, Copy)]
pub struct Flags(u8);

impl Flags {
    // No flag enabled
    pub const NONE: u8 = 0;
    // allow to be shared with others peers
    pub const SHARED: u8 = 1 << 0;
    // support the compression mode
    pub const COMPRESSION: u8 = 1 << 1;
    // disable fast sync mode (only full sync)
    pub const DISABLE_FAST_SYNC: u8 = 1 << 2;

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

#[cfg(test)]
mod tests {
    use super::Flags;

    #[test]
    fn test_flags() {
        let mut flags = Flags::new(Flags::NONE);
        assert!(!flags.contains(Flags::SHARED));
        assert!(!flags.contains(Flags::COMPRESSION));
        assert!(!flags.contains(Flags::DISABLE_FAST_SYNC));

        flags.insert(Flags::SHARED);
        assert!(flags.contains(Flags::SHARED));
        assert!(!flags.contains(Flags::COMPRESSION));
        assert!(!flags.contains(Flags::DISABLE_FAST_SYNC));

        flags.insert(Flags::COMPRESSION);
        assert!(flags.contains(Flags::SHARED));
        assert!(flags.contains(Flags::COMPRESSION));
        assert!(!flags.contains(Flags::DISABLE_FAST_SYNC));

        flags.remove(Flags::SHARED);
        assert!(!flags.contains(Flags::SHARED));
        assert!(flags.contains(Flags::COMPRESSION));
        assert!(!flags.contains(Flags::DISABLE_FAST_SYNC));

        flags.insert(Flags::DISABLE_FAST_SYNC);
        assert!(!flags.contains(Flags::SHARED));
        assert!(flags.contains(Flags::COMPRESSION));
        assert!(flags.contains(Flags::DISABLE_FAST_SYNC));

        flags.remove(Flags::COMPRESSION);
        assert!(!flags.contains(Flags::SHARED));
        assert!(!flags.contains(Flags::COMPRESSION));
        assert!(flags.contains(Flags::DISABLE_FAST_SYNC));

        flags.remove(Flags::DISABLE_FAST_SYNC);
        assert!(!flags.contains(Flags::SHARED));
        assert!(!flags.contains(Flags::COMPRESSION));
        assert!(!flags.contains(Flags::DISABLE_FAST_SYNC));

        assert_eq!(flags.bits(), Flags::NONE);
    }
}