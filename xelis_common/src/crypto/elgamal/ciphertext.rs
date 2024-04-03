use std::ops::{Add, AddAssign, Sub, SubAssign};

use curve25519_dalek::{traits::Identity, RistrettoPoint, Scalar};
use serde::{Deserialize, Deserializer, Serialize};
use super::{pedersen::{DecryptHandle, PedersenCommitment}, CompressedCiphertext, CompressedCommitment, CompressedHandle};

// Represents a twisted ElGamal Ciphertext
// One part is a Pedersen commitment to be bulletproofs compatible
// The other part is a handle to be used for decryption
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    commitment: PedersenCommitment,
    handle: DecryptHandle,
}

impl Ciphertext {
    // Create a new Ciphertext
    pub fn new(commitment: PedersenCommitment, handle: DecryptHandle) -> Self {
        Self { commitment, handle }
    }
    
    // Create a ciphertext with a zero value
    pub fn zero() -> Self {
        Self {
            commitment: PedersenCommitment::from_point(RistrettoPoint::identity()),
            handle: DecryptHandle::from_point(RistrettoPoint::identity()),
        }
    }

    // Get the commitment
    pub fn commitment(&self) -> &PedersenCommitment {
        &self.commitment
    }

    // Get the handle
    pub fn handle(&self) -> &DecryptHandle {
        &self.handle
    }

    // Compress the Ciphertext
    pub fn compress(&self) -> CompressedCiphertext {
        CompressedCiphertext::new(
            CompressedCommitment::new(self.commitment.as_point().compress()),
            CompressedHandle::new(self.handle.as_point().compress())
        )
    }
}

// ADD TRAITS

impl Add<u64> for Ciphertext {
    type Output = Self;

    fn add(self, rhs: u64) -> Self {
        Self {
            commitment: self.commitment + Scalar::from(rhs),
            handle: self.handle,
        }
    }
}

impl Add for Ciphertext {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            commitment: self.commitment + rhs.commitment,
            handle: self.handle + rhs.handle,
        }
    }
}

impl Add<&Ciphertext> for Ciphertext {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self {
            commitment: self.commitment + &rhs.commitment,
            handle: self.handle + &rhs.handle,
        }
    }
}

impl Add<Scalar> for Ciphertext {
    type Output = Self;
    fn add(self, rhs: Scalar) -> Self {
        Self {
            commitment: self.commitment + rhs,
            handle: self.handle,
        }
    }
}

impl Add<&Scalar> for Ciphertext {
    type Output = Self;
    fn add(self, rhs: &Scalar) -> Self {
        Self {
            commitment: self.commitment + rhs,
            handle: self.handle,
        }
    }
}

// ADD ASSIGN TRAITS

impl AddAssign<u64> for Ciphertext {
    fn add_assign(&mut self, rhs: u64) {
        self.commitment += Scalar::from(rhs);
    }
}

impl AddAssign for Ciphertext {
    fn add_assign(&mut self, rhs: Self) {
        self.commitment += rhs.commitment;
        self.handle += rhs.handle;
    }
}

impl AddAssign<&Ciphertext> for Ciphertext {
    fn add_assign(&mut self, rhs: &Self) {
        self.commitment += &rhs.commitment;
        self.handle += &rhs.handle;
    }
}

impl AddAssign<Scalar> for Ciphertext {
    fn add_assign(&mut self, rhs: Scalar) {
        self.commitment += rhs;
    }
}

impl AddAssign<&Scalar> for Ciphertext {
    fn add_assign(&mut self, rhs: &Scalar) {
        self.commitment += rhs;
    }
}

// SUB TRAITS

impl Sub<u64> for Ciphertext {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self {
        Self {
            commitment: self.commitment - Scalar::from(rhs),
            handle: self.handle,
        }
    }
}

impl Sub for Ciphertext {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            commitment: self.commitment - rhs.commitment,
            handle: self.handle - rhs.handle,
        }
    }
}

impl Sub<&Ciphertext> for Ciphertext {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self {
            commitment: self.commitment - &rhs.commitment,
            handle: self.handle - &rhs.handle,
        }
    }
}

impl Sub<Scalar> for Ciphertext {
    type Output = Self;
    fn sub(self, rhs: Scalar) -> Self {
        Self {
            commitment: self.commitment - rhs,
            handle: self.handle,
        }
    }
}

impl Sub<&Scalar> for Ciphertext {
    type Output = Self;
    fn sub(self, rhs: &Scalar) -> Self {
        Self {
            commitment: self.commitment - rhs,
            handle: self.handle,
        }
    }
}

// SUB ASSIGN TRAITS

impl SubAssign<u64> for Ciphertext {
    fn sub_assign(&mut self, rhs: u64) {
        self.commitment -= Scalar::from(rhs);
    }
}

impl SubAssign for Ciphertext {
    fn sub_assign(&mut self, rhs: Self) {
        self.commitment -= rhs.commitment;
        self.handle -= rhs.handle;
    }
}

impl SubAssign<&Ciphertext> for Ciphertext {
    fn sub_assign(&mut self, rhs: &Self) {
        self.commitment -= &rhs.commitment;
        self.handle -= &rhs.handle;
    }
}

impl SubAssign<Scalar> for Ciphertext {
    fn sub_assign(&mut self, rhs: Scalar) {
        self.commitment -= rhs;
    }
}

impl SubAssign<&Scalar> for Ciphertext {
    fn sub_assign(&mut self, rhs: &Scalar) {
        self.commitment -= rhs;
    }
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        self.compress().serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Ciphertext, D::Error>
    where
        D: Deserializer<'a>,
    {
        let compressed = CompressedCiphertext::deserialize(deserializer)?;
        compressed.decompress().map_err(serde::de::Error::custom)
    }
}