use crate::{block::BlockVersion, versioned::VersionedState};

use super::*;

mod persistent;
mod previous_value;
mod read_only;
mod memory;
mod mutability;

mod legacy;
