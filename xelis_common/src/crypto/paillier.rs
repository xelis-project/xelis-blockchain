use rug::{Integer, rand::RandState};
use thiserror::Error;

// p & q are two large primes and must have 2048 bits
pub const PRIME_BITS_SIZE: usize = 2048;
// Size is 4 * 2048 / 8 = 1024 bytes
// 4 because p * q = 4096 bits (N)
// and the ciphertext is the size of N^2
pub const SIZE: usize = PRIME_BITS_SIZE * 4 / 8;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid ciphertext for this Public Key")]
    InvalidCiphertext,
    #[error("Invalid operation")]
    InvalidOperation,
    #[error("Invalid plaintext")]
    InvalidPlaintext,
    #[error("Invalid decrypted value")]
    InvalidDecryptedValue
}

pub struct PrivateKey {
    p: Integer,
    q: Integer
}

impl PrivateKey {
    pub fn new(p: Integer, q: Integer) -> Self {
        if p.significant_bits() != PRIME_BITS_SIZE as u32 || q.significant_bits() != PRIME_BITS_SIZE as u32 {
            panic!("Invalid prime size p: {}, q: {}", p.significant_bits(), q.significant_bits())
        }

        Self {
            p,
            q
        }
    }

    // n = p * q
    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::new((&self.p * &self.q).into())
    }

    pub fn expand(self) -> ExpandedPrivateKey {
        let n: Integer = (&self.p * &self.q).into();

        // lambda = (p-1) * (q-1)
        let p_minus: Integer = &self.p - Integer::from(1);
        let q_minus: Integer = &self.q - Integer::from(1);
        let lambda: Integer = p_minus * q_minus;

        // boost performance, use invert_ref instead of extended GCD
        let mu: Integer = lambda.invert_ref(&n).unwrap().into();

        ExpandedPrivateKey {
            key: self.get_public_key(),
            _inner: self,
            lambda,
            mu,
        }
    }
}

// Expanded private key
pub struct ExpandedPrivateKey {
    _inner: PrivateKey,
    key: PublicKey,
    lambda: Integer,
    mu: Integer,
}

impl ExpandedPrivateKey {
    pub fn decrypt(&self, ciphertext: Ciphertext) -> Result<u64, CryptoError> {
        if !ciphertext.is_valid(&self.key) {
            return Err(CryptoError::InvalidCiphertext)
        }

        // c^lambda mod n^2
        let c_lambda: Integer = ciphertext.value.pow_mod_ref(&self.lambda, &self.key.nn)
            .ok_or(CryptoError::InvalidOperation)?
            .into();

        // L(x) = (x - 1) / n
        let plaintext = (&c_lambda - Integer::from(1)) / &self.key.n;
        // m = L(c^lambda mod n^2) * mu mod n
        let result = plaintext * &self.mu % &self.key.n;
        Ok(result.to_u64().ok_or(CryptoError::InvalidDecryptedValue)?)
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.key
    }
}

// Only necessary value is N, others are precomputed
pub struct PublicKey {
    // the modulus (used for encryption)
    n: Integer,
    // n + 1
    g: Integer,
    // n^2
    nn: Integer,
}

impl PublicKey {
    pub fn new(n: Integer) -> PublicKey {
        Self {
            g: &n + Integer::from(1),
            nn:  n.square_ref().into(),
            n,
        }
    }

    pub fn encrypt(&self, value: u64) -> Result<Ciphertext, CryptoError> {
        let plaintext = Integer::from(value);
        if plaintext >= self.n {
            return Err(CryptoError::InvalidPlaintext)
        }

        // Create a random number generator
        let mut rng = RandState::new();
        // Generate a random number between 0 and n
        let mut r: Integer = self.n.random_below_ref(&mut rng).into();
        // We want a positive value only
        if r.is_zero() {
            r += 1;
        }

        // c = g^value * r^n (mod n^2)
        let c1: Integer = self.g.pow_mod_ref(&plaintext, &self.nn)
            .ok_or(CryptoError::InvalidOperation)?
            .into();
        let c2: Integer = r.pow_mod_ref(&self.n, &self.nn)
            .ok_or(CryptoError::InvalidOperation)?
            .into();

        let mul: Integer = c1 * c2;
        Ok(Ciphertext::new(mul % &self.nn))
    }

    // C1 * C2 mod n^2
    pub fn add(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, CryptoError> {
        if (!c1.is_valid(self)) || (!c2.is_valid(self)) {
            return Err(CryptoError::InvalidCiphertext)
        }

        let mul: Integer = (&c1.value * &c2.value).into();
        Ok(Ciphertext::new(mul % &self.nn))
    }

    // C1 * g^value mod N^2
    pub fn add_plaintext(&self, c1: &Ciphertext, value: u64) -> Result<Ciphertext, CryptoError> {
        if !c1.is_valid(self) {
            return Err(CryptoError::InvalidCiphertext)
        }

        let plaintext = Integer::from(value);
        let c2: Integer = self.g.pow_mod_ref(&plaintext, &self.nn)
            .ok_or(CryptoError::InvalidOperation)?
            .into();

        let mul: Integer = (&c1.value * c2).into();
        Ok(Ciphertext::new(mul % &self.nn))
    }

    pub fn sub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, CryptoError> {
        if !c1.is_valid(self) || !c2.is_valid(self) {
            return Err(CryptoError::InvalidCiphertext)
        }

        // Instead of searching bezout coefficients and GCD we can just invert the value
        let negative_c2: Integer = c2.value.invert_ref(&self.nn)
            .ok_or(CryptoError::InvalidOperation)?
            .into();

        Ok(Ciphertext::new(&c1.value * negative_c2 % &self.nn))
    }

    pub fn mul_plaintext(&self, c1: &Ciphertext, value: u64) -> Result<Ciphertext, CryptoError> {
        if !c1.is_valid(self) {
            return Err(CryptoError::InvalidCiphertext)
        }

        let plaintext = Integer::from(value);
        let mul = c1.value.pow_mod_ref(&plaintext, &self.nn)
            .ok_or(CryptoError::InvalidOperation)?
            .into();

        Ok(Ciphertext::new(mul))
    }

    pub fn div_plaintext(&self, c1: &Ciphertext, value: u64) -> Result<Ciphertext, CryptoError> {
        if !c1.is_valid(self) {
            return Err(CryptoError::InvalidCiphertext)
        }

        let plaintext = Integer::from(value);
        let inverse = plaintext.invert(&self.nn).map_err(|_| CryptoError::InvalidOperation)?;

        let mul = c1.value.pow_mod_ref(&inverse, &self.nn)
        .ok_or(CryptoError::InvalidOperation)?
        .into();

        Ok(Ciphertext::new(mul))
    }
}

// Represents an encrypted value
pub struct Ciphertext {
    value: Integer,
}

impl Ciphertext {
    pub fn new(value: Integer) -> Ciphertext {
        Self {
            value,
        }
    }

    // 0 < C < n^2
    pub fn is_valid(&self, key: &PublicKey) -> bool {
        key.nn > self.value && self.value > Integer::from(0)
    }
}

mod tests {
    use std::str::FromStr;
    use super::*;

    fn _generate_private_key() -> ExpandedPrivateKey {
        let p = Integer::from_str("26946565058508556335703057678479193452304038415320320612739026385225298610008864186185248157667939692602914497266158802716790474833947772826137352516209983737629258254217925182069688200921824682629208537057830159202300700254744398401385317004557290421622059016544387100633064484394429299712612387988787656113893086893594807335060378763142902668584121938589954668585758578121584153647867617579207136469100271575899315110489594116527521092010000583127405316221856395802750870474485516597674185947739156275281462539159055254987599109169478119201211066791295912114221003467197211019730323321923834862781706821839382425319").unwrap();
        let q = Integer::from_str("30285103848165032371432135057580005479137385975250075866315362110663210942596615960809988401619020086330330323690859032150264976037456961162655919684888298622597867407709454379915077961482177205641007860316172930122789053649106796228331050588480104621044323245329249654789956970860084725229793041508008076837900555099704375472732833392770407190572998528495204954650991713220053319696501576522725356507569592271456467055934422479932228786490254699513808991388789871837682571567374631101622153747215563532592329904419750104317088696095242472742008866975771374389004813336895149595148338528131027712001071213942813066383").unwrap();

        PrivateKey::new(p, q).expand()
    }

    #[test]
    fn test_generate_private_key() {
        _generate_private_key();
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = _generate_private_key();
        let value = 10u64;
        let ciphertext = key.get_public_key().encrypt(value).unwrap();
        let decrypted = key.decrypt(ciphertext).unwrap();
        assert_eq!(value, decrypted);
    }

    #[test]
    fn test_homomorphic_add() {
        let key = _generate_private_key();
        let left = 2500u64;
        let right = 500u64;
        
        let c1 = key.get_public_key().encrypt(left).unwrap();
        let c2 = key.get_public_key().encrypt(right).unwrap();

        let sum = key.get_public_key().add(&c1, &c2).unwrap();
        let decrypted = key.decrypt(sum).unwrap();
        assert_eq!(left + right, decrypted);
    }

    #[test]
    fn test_homomorphic_add_plaintext() {
        let key = _generate_private_key();
        let left = 2500u64;
        let right = 500u64;
        
        let c1 = key.get_public_key().encrypt(left).unwrap();

        let sum = key.get_public_key().add_plaintext(&c1, right).unwrap();
        let decrypted = key.decrypt(sum).unwrap();
        assert_eq!(left + right, decrypted);
    }

    #[test]
    fn test_homomorphic_sub() {
        let key = _generate_private_key();
        let left = 2500u64;
        let right = 500u64;
        
        let c1 = key.get_public_key().encrypt(left).unwrap();
        let c2 = key.get_public_key().encrypt(right).unwrap();

        let sum = key.get_public_key().sub(&c1, &c2).unwrap();
        let decrypted = key.decrypt(sum).unwrap();
        assert_eq!(left - right, decrypted);
    }

    #[test]
    fn test_homomorphic_mul() {
        let key = _generate_private_key();
        let left = 2500u64;
        let right = 17u64;
        
        let c1 = key.get_public_key().encrypt(left).unwrap();

        let sum = key.get_public_key().mul_plaintext(&c1, right).unwrap();
        let decrypted = key.decrypt(sum).unwrap();
        assert_eq!(left * right, decrypted);
    }

    #[test]
    fn test_homomorphic_div() {
        let key = _generate_private_key();
        let left = 2500u64;
        let right = 10u64;
        
        let c1 = key.get_public_key().encrypt(left).unwrap();

        let sum = key.get_public_key().div_plaintext(&c1, right).unwrap();
        let decrypted = key.decrypt(sum).unwrap();
        assert_eq!(left / right, decrypted);
    }
}