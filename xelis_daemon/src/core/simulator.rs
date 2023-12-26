use std::{str::FromStr, fmt::{Display, Formatter}};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Simulator {
    // Mine only one block every BLOCK_TIME
    Blockchain,
    // Mine random 1-5 blocks every BLOCK_TIME to enable BlockDAG
    BlockDag
}

impl FromStr for Simulator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "blockchain" | "0" => Self::Blockchain,
            "blockdag" | "1" => Self::BlockDag,
            _ => return Err("Invalid simulator type".into())
        })
    }
}

impl Display for Simulator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match &self {
            Self::Blockchain => "blockchain",
            Self::BlockDag => "blockdag"
        };
        write!(f, "{}", str)
    }
}