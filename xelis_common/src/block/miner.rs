use std::{borrow::Cow, str::FromStr};
use log::debug;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::{
    crypto::{
        elgamal::RISTRETTO_COMPRESSED_SIZE,
        hash,
        Hash,
        Hashable,
        PublicKey,
    },
    serializer::{Reader, ReaderError, Serializer, Writer},
    time::TimestampMillis,
};
use xelis_hash::{
    Error as XelisHashError,
    v1,
    v2,
};

use super::{BlockHeader, BLOCK_WORK_SIZE, EXTRA_NONCE_SIZE};

pub enum WorkVariant {
    Uninitialized,
    V1(v1::ScratchPad, [u8; BLOCK_WORK_SIZE]),
    V2(v2::ScratchPad, [u8; BLOCK_WORK_SIZE]),
}

impl WorkVariant {
    pub fn get_algorithm(&self) -> Option<Algorithm> {
        Some(match self {
            WorkVariant::Uninitialized => return None,
            WorkVariant::V1(_, _) => Algorithm::V1,
            WorkVariant::V2(_, _) => Algorithm::V2
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[repr(u8)]
pub enum Algorithm {
    V1 = 0,
    V2 = 1
}

impl FromStr for Algorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "v1" => Ok(Algorithm::V1),
            "v2" => Ok(Algorithm::V2),
            _ => Err("invalid algorithm")
        }
    }
}

// This structure is used by xelis-miner which allow to compute a valid block POW hash
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinerWork<'a> {
    header_work_hash: Hash, // include merkle tree of tips, txs, and height (immutable)
    timestamp: TimestampMillis, // miners can update timestamp to keep it up-to-date
    nonce: u64,
    miner: Option<Cow<'a, PublicKey>>,
    // Extra nonce so miner can write anything
    // Can also be used to spread more the work job and increase its work capacity
    extra_nonce: [u8; EXTRA_NONCE_SIZE]
}

// Worker is used to store the current work and its variant
// Based on the variant, the worker can compute the POW hash
// It is used by the miner to efficiently switch context in case of algorithm change
pub struct Worker<'a> {
    work: Option<MinerWork<'a>>,
    variant: WorkVariant
}

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("worker is not initialized")]
    Uninitialized,
    #[error("missing miner work")]
    MissingWork,
    #[error(transparent)]
    HashError(#[from] XelisHashError)
}

impl<'a> Worker<'a> {
    // Create a new worker
    pub fn new() -> Self {
        Self {
            work: None,
            variant: WorkVariant::Uninitialized
        }
    }

    // Take the current work
    pub fn take_work(&mut self) -> Option<MinerWork<'a>> {
        self.work.take()
    }

    // Switch the current context to a new work
    pub fn set_work(&mut self, work: MinerWork<'a>, kind: Algorithm) -> Result<(), WorkerError> {
        // Check if the algorithm changed or if it must be initialized
        if self.variant.get_algorithm() != Some(kind) {
            match kind {
                Algorithm::V1 => {
                    let scratch_pad = v1::ScratchPad::default();
                    let mut slice = [0u8; BLOCK_WORK_SIZE];
                    slice.copy_from_slice(&work.to_bytes());
    
                    self.variant = WorkVariant::V1(scratch_pad, slice);
                },
                Algorithm::V2 => {
                    let scratch_pad = v2::ScratchPad::default();
                    let mut slice = [0u8; BLOCK_WORK_SIZE];
                    slice.copy_from_slice(&work.to_bytes());
                    self.variant = WorkVariant::V2(scratch_pad, slice);
                }
            }
        } else {
            match &mut self.variant {
                WorkVariant::Uninitialized => unreachable!(),
                WorkVariant::V1(_, input) => input.copy_from_slice(&work.to_bytes()),
                WorkVariant::V2(_, input) => input.copy_from_slice(&work.to_bytes()),
            };
        }
        self.work = Some(work);

        Ok(())
    }

    // Increase the nonce of the current work
    pub fn increase_nonce(&mut self) -> Result<(), WorkerError> {
        match self.work.as_mut() {
            Some(work) => {
                work.increase_nonce();
                match &mut self.variant {
                    WorkVariant::Uninitialized => return Err(WorkerError::Uninitialized),
                    WorkVariant::V1(_, input) => input[40..48].copy_from_slice(&work.nonce().to_be_bytes()),
                    WorkVariant::V2(_, input) => input[40..48].copy_from_slice(&work.nonce().to_be_bytes())
                }
            },
            None => return Err(WorkerError::MissingWork)
        };

        Ok(())
    }

    // Set the timestamp of the current work
    pub fn set_timestamp(&mut self, timestamp: TimestampMillis) -> Result<(), WorkerError> {
        match self.work.as_mut() {
            Some(work) => {
                work.set_timestamp(timestamp);
                match &mut self.variant {
                    WorkVariant::Uninitialized => return Err(WorkerError::Uninitialized),
                    WorkVariant::V1(_, input) => input[32..40].copy_from_slice(&work.timestamp().to_be_bytes()),
                    WorkVariant::V2(_, input) => input[32..40].copy_from_slice(&work.timestamp().to_be_bytes()),
                }
            },
            None => return Err(WorkerError::MissingWork),
        };

        Ok(())
    }

    // Compute the POW hash based on the current work
    pub fn get_pow_hash(&mut self) -> Result<Hash, WorkerError> {
        let hash = match &mut self.variant {
            WorkVariant::Uninitialized => return Err(WorkerError::Uninitialized),
            WorkVariant::V1(scratch_pad, work) => {
                // Compute the POW hash
                let mut input = v1::AlignedInput::default();
                let slice = input.as_mut_slice()?;
                slice[0..BLOCK_WORK_SIZE].copy_from_slice(work.as_ref());
                v1::xelis_hash(slice, scratch_pad).map(|bytes| Hash::new(bytes))?
            },
            WorkVariant::V2(scratch_pad, work) => {
                v2::xelis_hash(work, scratch_pad).map(|bytes| Hash::new(bytes))?
            }
        };

        Ok(hash)
    }

    // Compute the block hash based on the current work
    // This is used to get the expected block hash
    pub fn get_block_hash(&self) -> Result<Hash, WorkerError> {
        let hash = match &self.variant {
            WorkVariant::Uninitialized => return Err(WorkerError::Uninitialized),
            WorkVariant::V1(_, input) => hash(input),
            WorkVariant::V2(_, input) => hash(input),
        };

        Ok(hash)
    }
}

impl<'a> MinerWork<'a> {
    pub fn new(header_work_hash: Hash, timestamp: TimestampMillis) -> Self {
        Self {
            header_work_hash,
            timestamp,
            nonce: 0,
            miner: None,
            extra_nonce: [0u8; EXTRA_NONCE_SIZE]
        }
    }

    pub fn from_block(header: BlockHeader) -> Self {
        Self {
            header_work_hash: header.get_work_hash(),
            timestamp: header.get_timestamp(),
            nonce: 0,
            miner: Some(Cow::Owned(header.miner)),
            extra_nonce: header.extra_nonce
        }
    }

    #[inline(always)]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    #[inline(always)]
    pub fn timestamp(&self) -> TimestampMillis {
        self.timestamp
    }

    #[inline(always)]
    pub fn get_header_work_hash(&self) -> &Hash {
        &self.header_work_hash
    }

    #[inline(always)]
    pub fn get_miner(&self) -> Option<&PublicKey> {
        self.miner.as_ref().map(|m| m.as_ref())
    }

    pub fn get_extra_nonce(&mut self) -> &mut [u8; EXTRA_NONCE_SIZE] {
        &mut self.extra_nonce
    }

    #[inline(always)]
    pub fn set_timestamp(&mut self, timestamp: TimestampMillis) {
        self.timestamp = timestamp;
    }

    #[inline(always)]
    pub fn increase_nonce(&mut self) {
        self.nonce += 1;
    }

    #[inline(always)]
    pub fn set_miner(&mut self, miner: Cow<'a, PublicKey>) {
        self.miner = Some(miner);
    }

    #[inline(always)]
    pub fn set_thread_id(&mut self, id: u8) {
        self.extra_nonce[EXTRA_NONCE_SIZE - 1] = id;
    }

    #[inline(always)]
    pub fn set_thread_id_u16(&mut self, id: u16) {
        self.extra_nonce[EXTRA_NONCE_SIZE - 2..].copy_from_slice(id.to_be_bytes().as_ref());
    }

    #[inline(always)]
    pub fn take(self) -> (Hash, TimestampMillis, u64, Option<Cow<'a, PublicKey>>, [u8; EXTRA_NONCE_SIZE]) {
        (self.header_work_hash, self.timestamp, self.nonce, self.miner, self.extra_nonce)
    }
}

impl<'a> Serializer for MinerWork<'a> {
    fn write(&self, writer: &mut Writer) {
        writer.write_hash(&self.header_work_hash); // 32
        writer.write_u64(&self.timestamp); // 32 + 8 = 40
        writer.write_u64(&self.nonce); // 40 + 8 = 48
        writer.write_bytes(&self.extra_nonce); // 48 + 32 = 80

        // 80 + 32 = 112
        if let Some(miner) = &self.miner {
            miner.write(writer);
        } else {
            // We set a 32 bytes empty public key as we don't have any miner
            writer.write_bytes(&[0u8; RISTRETTO_COMPRESSED_SIZE]);
        }

        debug_assert!(writer.total_write() == BLOCK_WORK_SIZE, "invalid block work size, expected {}, got {}", BLOCK_WORK_SIZE, writer.total_write());
    }

    fn read(reader: &mut Reader) -> Result<MinerWork<'a>, ReaderError> {
        if reader.total_size() != BLOCK_WORK_SIZE {
            debug!("invalid block work size, expected {}, got {}", BLOCK_WORK_SIZE, reader.total_size());
            return Err(ReaderError::InvalidSize)
        }

        let header_work_hash = reader.read_hash()?;
        let timestamp = reader.read_u64()?;
        let nonce = reader.read_u64()?;
        let extra_nonce = reader.read_bytes_32()?;
        let miner = Some(Cow::Owned(PublicKey::read(reader)?));

        Ok(MinerWork {
            header_work_hash,
            timestamp,
            nonce,
            extra_nonce,
            miner
        })
    }

    fn size(&self) -> usize {
        BLOCK_WORK_SIZE
    }
}

// no need to override hash() as its already serialized in good format
// This is used to get the expected block hash
impl Hashable for MinerWork<'_> {}

#[cfg(test)]
mod tests {
    use crate::crypto::KeyPair;

    use super::*;

    #[test]
    fn test_worker() {
        let header_work_hash = Hash::new([255u8; 32]);
        let timestamp = 1234567890;
        let nonce = 0;
        let miner = KeyPair::new().get_public_key().compress();
        let extra_nonce = [0u8; EXTRA_NONCE_SIZE];

        let work = MinerWork {
            header_work_hash,
            timestamp,
            nonce,
            miner: Some(Cow::Owned(miner)),
            extra_nonce
        };
        let work_hex = work.to_hex();

        let mut input = v1::AlignedInput::default();
        let slice = input.as_mut_slice().unwrap();
        slice[0..BLOCK_WORK_SIZE].copy_from_slice(&work.to_bytes());
        let expected_hash = v1::xelis_hash(slice, &mut v1::ScratchPad::default()).map(|bytes| Hash::new(bytes)).unwrap();
        let block_hash = work.hash();

        let mut worker = Worker::new();
        worker.set_work(work.clone(), Algorithm::V1).unwrap();

        let worker_hash = worker.get_pow_hash().unwrap();
        let next_worker_hash = worker.get_pow_hash().unwrap();
        let worker_block_hash = work.hash();

        assert_eq!(expected_hash, worker_hash);
        assert_eq!(block_hash, worker_block_hash);

        // Lets do another hash
        assert_eq!(expected_hash, next_worker_hash);

        assert_eq!(work_hex, worker.take_work().unwrap().to_hex());

    }
}