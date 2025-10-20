#[derive(Copy, Clone, Debug)]
pub enum Direction {
    Forward,
    Reverse,
}

#[cfg(feature = "rocksdb")]
impl Into<rocksdb::Direction> for Direction {
    fn into(self) -> rocksdb::Direction {
        match self {
            Direction::Forward => rocksdb::Direction::Forward,
            Direction::Reverse => rocksdb::Direction::Reverse,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum IteratorMode<'a> {
    Start,
    End,
    // Allow for range start operations
    From(&'a [u8], Direction),
    // Strict prefix to all keys
    WithPrefix(&'a [u8], Direction),
    Range {
        lower_bound: &'a [u8],
        // NOTE: upper bound is NEVER included
        upper_bound: &'a [u8],
        direction: Direction,
    }
}
