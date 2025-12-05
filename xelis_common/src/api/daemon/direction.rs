use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

use crate::time::TimestampMillis;

// Direction is used for cache to knows from which context it got added
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    // We don't update it because it's In, we won't send back
    In,
    // Out can be updated with In to be transformed to Both
    // Because of desync, we may receive the object while sending it
    Out,
    // Cannot be updated
    Both
}

impl Direction {
    pub fn update(&mut self, direction: Direction) -> bool {
        match self {
            Self::Out => match direction {
                Self::In => {
                    *self = Self::Both;
                    true
                },
                _ => false
            },
            Self::In => match direction {
                Self::Out => {
                    *self = Self::Both;
                    true
                },
                _ => false
            },
            _ => false
        }
    }
}

// Direction is used for cache to knows from which context it got added
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimedDirection {
    // We don't update it because it's In, we won't send back
    In {
        received_at: TimestampMillis
    },
    // Out can be updated with In to be transformed to Both
    // Because of desync, we may receive the object while sending it
    Out {
        sent_at: TimestampMillis
    },
    // Cannot be updated
    Both {
        received_at: TimestampMillis,
        sent_at: TimestampMillis,
    }
}

impl TimedDirection {
    pub fn is_both(&self) -> bool {
        matches!(self, Self::Both { .. })
    }

    pub fn is_in(&self) -> bool {
        matches!(self, Self::In { .. })
    }

    pub fn is_out(&self) -> bool {
        matches!(self, Self::Out { .. })
    }

    pub fn contains_out(&self) -> bool {
        matches!(self, Self::Out { .. } | Self::Both { .. })
    }

    pub fn contains_in(&self) -> bool {
        matches!(self, Self::In { .. } | Self::Both { .. })
    }

    pub fn update(&mut self, direction: TimedDirection) -> bool {
        match *self {
            Self::Out { sent_at } => match direction {
                Self::In { received_at } => {
                    *self = Self::Both {
                        received_at,
                        sent_at,
                    };
                    true
                },
                _ => false
            },
            Self::In { received_at } => match direction {
                Self::Out { sent_at } => {
                    *self = Self::Both {
                        received_at,
                        sent_at
                    };
                    true
                },
                _ => false
            },
            _ => false
        }
    }
}