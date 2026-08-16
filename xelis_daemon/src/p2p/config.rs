use std::time::Duration;

use humantime::Duration as HumanDuration;
use serde::{Deserialize, Serialize};

use crate::config::{
    CHAIN_SYNC_TIMEOUT_SECS,
    PEER_SEND_BYTES_TIMEOUT,
    PEER_TIMEOUT_BOOTSTRAP_STEP,
    PEER_TIMEOUT_INIT_CONNECTION,
    PEER_TIMEOUT_REQUEST_OBJECT,
};

fn default_handshake_timeout() -> HumanDuration {
    Duration::from_millis(PEER_TIMEOUT_INIT_CONNECTION).into()
}

fn default_send_timeout() -> HumanDuration {
    Duration::from_millis(PEER_SEND_BYTES_TIMEOUT).into()
}

fn default_request_timeout() -> HumanDuration {
    Duration::from_millis(PEER_TIMEOUT_REQUEST_OBJECT).into()
}

fn default_bootstrap_timeout() -> HumanDuration {
    Duration::from_millis(PEER_TIMEOUT_BOOTSTRAP_STEP).into()
}

fn default_chain_sync_timeout() -> HumanDuration {
    Duration::from_secs(CHAIN_SYNC_TIMEOUT_SECS).into()
}

#[derive(Debug, Clone, Copy, clap::Args, Serialize, Deserialize)]
pub struct P2pTimeouts {
    /// Timeout for the P2P key exchange and handshake.
    #[clap(name = "p2p-handshake-timeout", long, default_value_t = default_handshake_timeout())]
    #[serde(with = "humantime_serde", default = "default_handshake_timeout")]
    pub handshake: HumanDuration,
    /// Timeout for writing a P2P packet to a peer.
    #[clap(name = "p2p-send-timeout", long, default_value_t = default_send_timeout())]
    #[serde(with = "humantime_serde", default = "default_send_timeout")]
    pub send: HumanDuration,
    /// Timeout for an individual object request.
    #[clap(name = "p2p-request-timeout", long, default_value_t = default_request_timeout())]
    #[serde(with = "humantime_serde", default = "default_request_timeout")]
    pub request_object: HumanDuration,
    /// Timeout for an individual bootstrap request.
    #[clap(name = "p2p-bootstrap-timeout", long, default_value_t = default_bootstrap_timeout())]
    #[serde(with = "humantime_serde", default = "default_bootstrap_timeout")]
    pub bootstrap: HumanDuration,
    /// Timeout for an individual chain-sync request.
    #[clap(name = "p2p-chain-sync-timeout", long, default_value_t = default_chain_sync_timeout())]
    #[serde(with = "humantime_serde", default = "default_chain_sync_timeout")]
    pub chain_sync: HumanDuration,
}

impl Default for P2pTimeouts {
    fn default() -> Self {
        Self {
            handshake: default_handshake_timeout(),
            send: default_send_timeout(),
            request_object: default_request_timeout(),
            bootstrap: default_bootstrap_timeout(),
            chain_sync: default_chain_sync_timeout(),
        }
    }
}

mod humantime_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &HumanDuration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HumanDuration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse::<HumanDuration>().map_err(serde::de::Error::custom)
    }
}
