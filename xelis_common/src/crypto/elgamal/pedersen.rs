use std::ops::{Add, AddAssign, Sub, SubAssign};

use curve25519_dalek::{traits::MultiscalarMul, RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use super::{key::PublicKey, CompressedCommitment, CompressedHandle, G, H};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenOpening(Scalar);

impl PedersenOpening {
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self(scalar)
    }

    pub fn generate_new() -> Self {
        PedersenOpening(Scalar::random(&mut OsRng))
    }

    pub fn as_scalar(&self) -> Scalar {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCommitment(RistrettoPoint);

impl PedersenCommitment {
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self(point)
    }

    pub fn new<T: Into<Scalar>>(amount: T) -> (PedersenCommitment, PedersenOpening) {
        let opening = PedersenOpening::generate_new();
        let commitment = Self::new_with_opening(amount, &opening);

        (commitment, opening)
    }

    pub fn new_with_opening<T: Into<Scalar>>(amount: T, opening: &PedersenOpening) -> Self {
        let x: Scalar = amount.into();
        let r = opening.as_scalar();

        Self(RistrettoPoint::multiscalar_mul(&[x, r], &[G, *H]))
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    // Compress the PedersenCommitment
    pub fn compress(&self) -> CompressedCommitment {
        CompressedCommitment::new(self.0.compress())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptHandle(RistrettoPoint);

impl DecryptHandle {
    // Create a new DecryptHandle using a point
    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p)
    }

    // Create a new DecryptHandle using a public key and a PedersenOpening
    pub fn new(public: &PublicKey, opening: &PedersenOpening) -> Self {
        Self(public.as_point() * opening.as_scalar())
    }

    // Get the point
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    // Compress the DecryptHandle
    pub fn compress(&self) -> CompressedHandle {
        CompressedHandle::new(self.0.compress())
    }
}

// ADD TRAITS

impl Add for PedersenCommitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Add<&PedersenCommitment> for PedersenCommitment {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Add<Scalar> for PedersenCommitment {
    type Output = Self;

    fn add(self, rhs: Scalar) -> Self {
        Self(self.0 + (rhs * G))
    }
}

impl Add<&Scalar> for PedersenCommitment {
    type Output = Self;

    fn add(self, rhs: &Scalar) -> Self {
        Self(self.0 + (rhs * G))
    }
}

impl Add for DecryptHandle {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Add<&DecryptHandle> for DecryptHandle {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

// ADD ASSIGN TRAITS

impl AddAssign for PedersenCommitment {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&PedersenCommitment> for PedersenCommitment {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }
}

impl AddAssign<Scalar> for PedersenCommitment {
    fn add_assign(&mut self, rhs: Scalar) {
        self.0 += rhs * G;
    }
}

impl AddAssign<&Scalar> for PedersenCommitment {
    fn add_assign(&mut self, rhs: &Scalar) {
        self.0 += rhs * G;
    }
}

impl AddAssign for DecryptHandle {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&DecryptHandle> for DecryptHandle {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }
}

// SUB TRAITS

impl Sub for PedersenCommitment {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Sub<&PedersenCommitment> for PedersenCommitment {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Sub<Scalar> for PedersenCommitment {
    type Output = Self;

    fn sub(self, rhs: Scalar) -> Self {
        Self(self.0 - rhs * G)
    }
}

impl Sub<&Scalar> for PedersenCommitment {
    type Output = Self;

    fn sub(self, rhs: &Scalar) -> Self {
        Self(self.0 - rhs * G)
    }
}

impl Sub for DecryptHandle {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl Sub<&DecryptHandle> for DecryptHandle {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

// SUB ASSIGN TRAITS

impl SubAssign for PedersenCommitment {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl SubAssign<&PedersenCommitment> for PedersenCommitment {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
    }
}

impl SubAssign<Scalar> for PedersenCommitment {
    fn sub_assign(&mut self, rhs: Scalar) {
        self.0 -= rhs * G;
    }
}

impl SubAssign<&Scalar> for PedersenCommitment {
    fn sub_assign(&mut self, rhs: &Scalar) {
        self.0 -= rhs * G;
    }
}

impl SubAssign for DecryptHandle {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl SubAssign<&DecryptHandle> for DecryptHandle {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
    }
}