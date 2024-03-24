// A simple module to define the time types used in the project

use std::time::{SystemTime, UNIX_EPOCH, Duration};

// Millis timestamps used to determine it using its type
pub type TimestampMillis = u64;

// Seconds timestamps used to determine it using its type
pub type TimestampSeconds = u64;

#[inline]
pub fn get_current_time() -> Duration {
    let start = SystemTime::now();
    let time = start.duration_since(UNIX_EPOCH).expect("Incorrect time returned from get_current_time");
    time
}

// return timestamp in seconds
pub fn get_current_time_in_seconds() -> TimestampSeconds {
    get_current_time().as_secs()
}

// return timestamp in milliseconds
// We cast it to u64 as we have plenty of time before it overflows
// See more: https://github.com/xelis-project/xelis-blockchain/issues/18
pub fn get_current_time_in_millis() -> TimestampMillis {
    get_current_time().as_millis() as TimestampMillis
}
