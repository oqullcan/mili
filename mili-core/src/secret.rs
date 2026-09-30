//! Secret key material.
//!
//! Two rules govern everything in this module. Secret bytes are zeroized when
//! the value is dropped, and secret values cannot be rendered. [`Debug`] prints
//! a redaction marker, and no type here implements [`Display`] or any
//! serialization trait, so printing a key with `{}` does not compile.
//!
//! `SecretBytes` is the shared representation and is crate-private. Public
//! key types are distinct newtypes over it, so a signing key cannot be passed
//! where an encryption key is expected: the types do not convert into each
//! other and there is no function that accepts both.
//!
//! Not implementing `Display` is deliberate. Returning
//! `Err(fmt::Error)` from `Display` would make `format!("{key}")` panic in the
//! caller's code, which is worse than refusing at compile time.
//!
//! # Copying
//!
//! `Clone` is not implemented. A copy the caller cannot reach is a liability,
//! and no phase of mili has yet needed one.
//!
//! # Comparison
//!
//! Equality uses [`subtle::ConstantTimeEq`] and does not short-circuit.
//!
//! [`Display`]: std::fmt::Display
//! [`Debug`]: std::fmt::Debug

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::Error;

/// Length in bytes of a mili symmetric key.
pub const SYMMETRIC_KEY_SIZE: usize = 32;

/// Fixed-length secret bytes, zeroized on drop.
pub(crate) struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// Wraps a byte array.
    pub(crate) fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Borrows the underlying bytes.
    ///
    /// Crate-private. The caller must not let the reference outlive a use that
    /// could duplicate the value.
    pub(crate) fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

/// A 256-bit symmetric key.
///
/// This is the only key type that is not tied to a public-key algorithm. Keys
/// for X-Wing sealing and for composite signing are separate types added in
/// later phases, and neither converts into this one.
///
/// The value is zeroized on drop, `Debug` is redacted, `Display` is not
/// implemented and equality is constant time. There is no `Clone` and no
/// serialization trait.
///
/// # Examples
///
/// ```
/// use mili_core::SymmetricKey;
///
/// # fn main() -> Result<(), mili_core::Error> {
/// let key = SymmetricKey::generate()?;
/// assert_eq!(format!("{key:?}"), "SymmetricKey([REDACTED])");
/// # Ok(())
/// # }
/// ```
pub struct SymmetricKey(SecretBytes<SYMMETRIC_KEY_SIZE>);

impl SymmetricKey {
    /// Draws a new key from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Failed`] if the operating system randomness source is
    /// unavailable. mili does not fall back to any other source.
    pub fn generate() -> Result<Self, Error> {
        let bytes = crate::rng::array::<SYMMETRIC_KEY_SIZE>()?;
        Ok(Self(SecretBytes::from_bytes(bytes)))
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SymmetricKey").field(&self.0).finish()
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SymmetricKey {}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SymmetricKey, SYMMETRIC_KEY_SIZE};
    use zeroize::Zeroize;

    #[test]
    fn documented_length() {
        assert_eq!(SYMMETRIC_KEY_SIZE, 32);
    }

    #[test]
    fn debug_is_redacted() {
        let key = SymmetricKey::generate().expect("OS randomness is available");
        assert_eq!(format!("{key:?}"), "SymmetricKey([REDACTED])");
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let secret = SecretBytes::from_bytes([0xAAu8; 32]);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }

    #[test]
    fn secret_bytes_debug_contains_no_digits() {
        // A key drawn from bytes 0x00..=0x1F renders as two hexadecimal digits
        // per byte. The expected debug output has no digits, so any match would
        // mean a leak.
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let secret = SecretBytes::from_bytes(bytes);
        let rendered = format!("{secret:?}");
        assert!(
            !rendered.contains(|c: char| c.is_ascii_digit()),
            "{rendered}"
        );
    }

    #[test]
    fn zeroize_clears_the_value() {
        let mut secret = SecretBytes::from_bytes([0xFFu8; 32]);
        assert_eq!(secret.as_bytes(), &[0xFFu8; 32]);
        secret.zeroize();
        assert_eq!(secret.as_bytes(), &[0x00u8; 32]);
    }

    #[test]
    fn equality_is_exact() {
        let mut different = [0x00u8; 32];
        different[1] = 0x01;

        assert_eq!(
            SecretBytes::from_bytes([0x01u8; 32]),
            SecretBytes::from_bytes([0x01u8; 32])
        );
        assert_ne!(
            SecretBytes::from_bytes([0x01u8; 32]),
            SecretBytes::from_bytes(different)
        );
    }

    #[test]
    fn generated_keys_differ() {
        let a = SymmetricKey::generate().expect("OS randomness is available");
        let b = SymmetricKey::generate().expect("OS randomness is available");
        assert_ne!(a, b);
    }
}
