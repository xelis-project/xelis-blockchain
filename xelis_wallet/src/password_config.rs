use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use xelis_common::serializer::*;

use crate::{config::PASSWORD_HASH_SIZE, error::WalletError};

/// Constants for password hashing configuration.
/// These constants define the default parameters for the Argon2id password hashing algorithm used in the wallet.

/// The memory cost in KiB for the legacy password hashing configuration.
pub const LEGACY_PASSWORD_MEMORY_COST_KIB: u32 = 15 * 1000;

/// The default memory cost in KiB for the password hashing configuration.
pub const DEFAULT_PASSWORD_MEMORY_COST_KIB: u32 = 128 * 1024;
/// The default parallelism (number of threads) for the password hashing configuration.
pub const DEFAULT_PASSWORD_PARALLELISM: u32 = 4;
/// The default number of iterations for the password hashing configuration.
pub const DEFAULT_PASSWORD_ITERATIONS: u32 = 16;

/// Represents the configuration for password hashing in the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PasswordConfig {
    Argon2id {
        memory_cost_kib: u32,
        parallelism: u32,
        iterations: u32,
    },
}

impl Serializer for PasswordConfig {
    fn write(&self, writer: &mut Writer) {
        match self {
            Self::Argon2id { memory_cost_kib, parallelism, iterations } => {
                writer.write_u8(0);
                writer.write_u32(*memory_cost_kib);
                writer.write_u32(*parallelism);
                writer.write_u32(*iterations);
            }
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        match reader.read_u8()? {
            0 => Ok(Self::Argon2id {
                memory_cost_kib: reader.read_u32()?,
                parallelism: reader.read_u32()?,
                iterations: reader.read_u32()?,
            }),
            _ => Err(ReaderError::InvalidValue),
        }
    }
}


impl PasswordConfig {
    pub fn hash_password(&self, password: &str, salt: &[u8]) -> Result<[u8; PASSWORD_HASH_SIZE], WalletError> {
        let mut output = [0; PASSWORD_HASH_SIZE];
        match self {
            Self::Argon2id { memory_cost_kib, parallelism, iterations } => {
                let params = Params::new(*memory_cost_kib, *iterations, *parallelism, Some(PASSWORD_HASH_SIZE))
                    .map_err(|e| WalletError::AlgorithmHashingError(e.to_string()))?;

                let algorithm = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

                algorithm.hash_password_into(password.as_bytes(), salt, &mut output)
                    .map_err(|e| WalletError::AlgorithmHashingError(e.to_string()))?;
            }
        }

        Ok(output)
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self::Argon2id {
            memory_cost_kib: DEFAULT_PASSWORD_MEMORY_COST_KIB,
            parallelism: DEFAULT_PASSWORD_PARALLELISM,
            iterations: DEFAULT_PASSWORD_ITERATIONS,
        }
    }
}

impl PasswordConfig {
    /// Returns a legacy default password configuration for backward compatibility.
    pub fn legacy_default() -> Self {
        Self::Argon2id {
            memory_cost_kib: LEGACY_PASSWORD_MEMORY_COST_KIB,
            parallelism: 1,
            iterations: 16,
        }
    }
}
