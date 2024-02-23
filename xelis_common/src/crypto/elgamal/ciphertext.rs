use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto}, scalar::Scalar};
use core::ops::{Add, Neg, Mul, Sub};
use std::{ops::{AddAssign, SubAssign}, fmt::{Formatter, Display}};

use crate::serializer::{Serializer, Writer, ReaderError, Reader};

// Each ciphertext has a size of 64 bytes in compressed form.
// Homomorphic properties can be used to add, subtract, and multiply ciphertexts.
#[derive(Clone)]
pub struct Ciphertext {
    left: RistrettoPoint,
    right: RistrettoPoint,
}

impl Ciphertext {
    pub fn new(left: RistrettoPoint, right: RistrettoPoint) -> Self {
        Self {
            left,
            right,
        }
    }

    pub fn points(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.left, self.right)
    }
}

impl Serializer for Ciphertext {
    fn write(&self, writer: &mut Writer) {
        writer.write_bytes(self.left.compress().as_bytes());
        writer.write_bytes(self.right.compress().as_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, ReaderError> {
        let left_bytes = reader.read_bytes_32()?;
        let right_bytes = reader.read_bytes_32()?;

        Ok(Self {
            left: CompressedRistretto::from_slice(&left_bytes).decompress().ok_or(ReaderError::InvalidValue)?,
            right: CompressedRistretto::from_slice(&right_bytes).decompress().ok_or(ReaderError::InvalidValue)?,
        })
    }

    fn size(&self) -> usize {
        32 + 32
    }
}

impl Add for Ciphertext {
    type Output = Self;

    fn add(mut self, other: Self) -> Self::Output {
        self.left += other.left;
        self.right += other.right;
        self
    }
}

impl Add<&Ciphertext> for Ciphertext {
    type Output = Self;

    fn add(mut self, other: &Self) -> Self::Output {
        self.left += other.left;
        self.right += other.right;
        self
    }
}

impl Add<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: &Ciphertext) -> Self::Output {
        Ciphertext::new(self.left + other.left, self.right + other.right)
    }
}

impl Add<Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, mut other: Ciphertext) -> Self::Output {
        other.left += self.left;
        other.right += self.right;
        other
    }
}

impl AddAssign<Ciphertext> for Ciphertext {
    fn add_assign(&mut self, rhs: Ciphertext) {
        self.left += rhs.left;
        self.right += rhs.right;
    }
}

impl AddAssign<&Ciphertext> for Ciphertext {
    fn add_assign(&mut self, rhs: &Ciphertext) {
        self.left += rhs.left;
        self.right += rhs.right;
    }
}

impl SubAssign<Ciphertext> for Ciphertext {
    fn sub_assign(&mut self, rhs: Ciphertext) {
        self.left -= rhs.left;
        self.right -= rhs.right;
    }
}

impl SubAssign<&Ciphertext> for Ciphertext {
    fn sub_assign(&mut self, rhs: &Ciphertext) {
        self.left -= rhs.left;
        self.right -= rhs.right;
    }
}

impl Add<RistrettoPoint> for Ciphertext {
    type Output = Self;

    fn add(mut self, other: RistrettoPoint) -> Self::Output {
        self.right += other;
        self
    }
}

impl Add<&RistrettoPoint> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: &RistrettoPoint) -> Self::Output {
        Ciphertext::new(self.left, self.right + other)
    }
}

impl Add<&RistrettoPoint> for Ciphertext {
    type Output = Self;

    fn add(mut self, other: &RistrettoPoint) -> Self::Output {
        self.right += other;
        self
    }
}

impl Add<RistrettoPoint> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: RistrettoPoint) -> Self::Output {
        Ciphertext::new(self.left, self.right + other)
    }
}

impl Sub for Ciphertext {
    type Output = Self;

    fn sub(mut self, other: Self) -> Self::Output {
        self.left -= other.left;
        self.right -= other.right;
        self
    }
}

impl Sub<&Ciphertext> for Ciphertext {
    type Output = Self;

    fn sub(mut self, other: &Self) -> Self::Output {
        self.left -= other.left;
        self.right -= other.right;
        self
    }
}

impl Sub<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: &Ciphertext) -> Self::Output {
        Ciphertext::new(self.left - other.left, self.right - other.right)
    }
}

impl Sub<RistrettoPoint> for Ciphertext {
    type Output = Self;

    fn sub(mut self, other: RistrettoPoint) -> Self::Output {
        self.right -= other;
        self
    }
}

impl Sub<&RistrettoPoint> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: &RistrettoPoint) -> Self::Output {
        Ciphertext::new(self.left, self.right - other)
    }
}

impl Sub<&RistrettoPoint> for Ciphertext {
    type Output = Self;

    fn sub(mut self, other: &RistrettoPoint) -> Self::Output {
        self.right -= other;
        self
    }
}

impl Sub<RistrettoPoint> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: RistrettoPoint) -> Self::Output {
        Ciphertext::new(self.left, self.right - other)
    }
}

impl Neg for Ciphertext {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.left = -self.left;
        self.right = -self.right;
        self
    }
}

impl Neg for &Ciphertext {
    type Output = Ciphertext;

    fn neg(self) -> Self::Output {
        Ciphertext::new(-self.left, -self.right)
    }
}

impl Mul<Scalar> for Ciphertext {
    type Output = Self;

    fn mul(mut self, other: Scalar) -> Self::Output {
        self.left *= other;
        self.right *= other;
        self
    }
}

impl Mul<Scalar> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: Scalar) -> Self::Output {
        Ciphertext::new(self.left * other, self.right * other)
    }
}

impl Mul<&Scalar> for Ciphertext {
    type Output = Self;

    fn mul(mut self, other: &Scalar) -> Self::Output {
        self.left *= other;
        self.right *= other;
        self
    }
}

impl Mul<&Scalar> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: &Scalar) -> Self::Output {
        Ciphertext::new(self.left * other, self.right * other)
    }
}

impl serde::Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::Deserializer<'de> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Ok(Self::from_bytes(&bytes).map_err(serde::de::Error::custom)?)
    }
}

impl Display for Ciphertext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ciphertext({})", self.to_hex())
    }
}