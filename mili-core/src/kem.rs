//! The hybrid key encapsulation mechanism and the key types built on it.
//!
//! X-Wing, which combines X25519 with ML-KEM-768 and combines the two shared
//! secrets with SHA3-256. The specification is
//! `draft-connolly-cfrg-xwing-kem`; it is an IETF internet-draft, not an RFC.
//! See `SPEC.md` section 9.
//!
//! Two types, and they are the only key types that can be used here:
//!
//! - [`SealingKey`] is the 32 byte seed. It is zeroized on drop, it has no
//!   `Display`, no `Clone` and no serialization trait, and the only way its bytes
//!   leave the type is an explicit call.
//! - [`EncapsulationKey`] is the 1216 byte public key. It is not secret.
//!
//! The two do not convert into each other and no function takes both, so a
//! sealing key cannot be passed where an encryption key is expected and an
//! encryption key cannot be passed where a signing key is expected.
//!
//! # Encapsulation randomness
//!
//! [`EncapsulationKey::encapsulate`] draws its ephemeral key from the operating
//! system CSPRNG inside the `x-wing` crate. mili exposes no way to supply a
//! generator, so there is no caller-reachable path to weaker or predictable
//! randomness.

use x_wing::{Decapsulate, Decapsulator, KeyExport};

use crate::secret::SecretBytes;
use crate::Error;

/// Length in bytes of an X-Wing decapsulation key seed.
pub const SEALING_KEY_SIZE: usize = 32;

/// Length in bytes of an X-Wing encapsulation key.
pub const ENCAPSULATION_KEY_SIZE: usize = 1216;

/// Length in bytes of an X-Wing KEM ciphertext.
pub(crate) const KEM_CIPHERTEXT_SIZE: usize = 1120;

/// Length in bytes of an X-Wing shared secret.
pub(crate) const SHARED_SECRET_SIZE: usize = 32;

/// An X-Wing decapsulation key.
///
/// Zeroized on drop. `Debug` is redacted, `Display` is not implemented, and
/// there is no `Clone`.
pub struct SealingKey(SecretBytes<SEALING_KEY_SIZE>);

impl SealingKey {
    /// Draws a new seed from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the operating system randomness source is
    /// unavailable.
    pub fn generate() -> Result<Self, Error> {
        let bytes = crate::rng::array::<SEALING_KEY_SIZE>()?;
        Ok(Self(SecretBytes::from_bytes(bytes)))
    }

    /// Wraps an existing 32 byte X-Wing seed.
    pub fn from_bytes(bytes: [u8; SEALING_KEY_SIZE]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// Borrows the seed.
    ///
    /// The only way key bytes leave this type. Crate-private until a phase needs
    /// it for a key file or the FFI boundary.
    #[allow(dead_code)]
    pub(crate) fn expose(&self) -> &[u8; SEALING_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Derives the matching public key.
    ///
    /// Expands the seed with SHAKE-256 into an ML-KEM-768 key pair and an
    /// X25519 key pair, as X-Wing specifies. Expensive relative to the other key
    /// operations: a caller sealing repeatedly should keep the
    /// [`EncapsulationKey`] rather than recompute it for every file.
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        EncapsulationKey(
            x_wing::DecapsulationKey::from(*self.0.as_bytes())
                .encapsulation_key()
                .clone(),
        )
    }

    /// Recovers the recipient's shared secret from a KEM ciphertext.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if `ciphertext` is not exactly
    /// [`KEM_CIPHERTEXT_SIZE`] bytes. A correctly sized ciphertext never fails
    /// here: X-Wing uses implicit rejection, so a ciphertext that was not
    /// produced for this key yields a shared secret the sender did not produce,
    /// and the AEAD step rejects it. That is deliberate, because a decapsulation
    /// failure signal would be an oracle.
    pub(crate) fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<SecretBytes<SHARED_SECRET_SIZE>, Error> {
        if ciphertext.len() != KEM_CIPHERTEXT_SIZE {
            return Err(Error::Failed);
        }
        let shared = x_wing::DecapsulationKey::from(*self.0.as_bytes())
            .decapsulate_slice(ciphertext)
            .map_err(|_| Error::Failed)?;
        let mut bytes = [0u8; SHARED_SECRET_SIZE];
        bytes.copy_from_slice(shared.as_slice());
        Ok(SecretBytes::from_bytes(bytes))
    }
}

/// An X-Wing encapsulation key.
///
/// Public data, so it is stored in its parsed form and re-serialising it is a
/// copy of public bytes. `Display` is not implemented and there is no `Clone`.
pub struct EncapsulationKey(x_wing::EncapsulationKey);

impl EncapsulationKey {
    /// Parses the 1216 byte encoding of an X-Wing public key.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the length is wrong or the embedded ML-KEM-768
    /// encapsulation key is not a valid ML-KEM-768 key. The two cases are not
    /// distinguished: both mean the input is not a usable public key, and
    /// saying which check failed tells a caller more about the key it supplied
    /// than it needs to know.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        x_wing::EncapsulationKey::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::Failed)
    }

    /// Copies the 1216 byte encoding out.
    ///
    /// These are public bytes. `Display` is still not implemented, so that a key
    /// cannot end up in a log line by accident.
    pub fn to_bytes(&self) -> [u8; ENCAPSULATION_KEY_SIZE] {
        let mut bytes = [0u8; ENCAPSULATION_KEY_SIZE];
        bytes.copy_from_slice(self.0.to_bytes().as_slice());
        bytes
    }

    /// Encapsulates to this key using the operating system CSPRNG.
    ///
    /// Crate-private. Callers go through [`crate::seal::seal`], which derives the
    /// AEAD key and builds the file, so a shared secret cannot be used for a
    /// purpose mili did not intend.
    pub(crate) fn encapsulate(&self) -> (Vec<u8>, SecretBytes<SHARED_SECRET_SIZE>) {
        let (ciphertext, shared) = x_wing::Encapsulate::encapsulate(&self.0);
        let mut shared_bytes = [0u8; SHARED_SECRET_SIZE];
        shared_bytes.copy_from_slice(shared.as_slice());
        (
            ciphertext.as_slice().to_vec(),
            SecretBytes::from_bytes(shared_bytes),
        )
    }
}

impl core::fmt::Debug for SealingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealingKey([REDACTED])")
    }
}

impl core::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncapsulationKey([REDACTED])")
    }
}

// Tests that reach into ML-KEM-768 or X25519 arithmetic are excluded under miri.
// They exercise third-party integer arithmetic that miri proves nothing useful
// about, and each call costs orders of magnitude more under miri than natively.
// mili's own bounds checks, which are the part worth proving, are not gated.
#[cfg(test)]
mod tests {
    #[cfg(not(miri))]
    use super::EncapsulationKey;
    use super::{SealingKey, ENCAPSULATION_KEY_SIZE, SEALING_KEY_SIZE};
    use crate::Error;
    #[cfg(not(miri))]
    use serde::Deserialize;

    #[cfg(not(miri))]
    const XWING_JSON: &str = include_str!("../../tests/vectors/xwing_draft11.json");

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct XWingFile {
        sizes: Sizes,
        vectors: Vec<XWingVector>,
    }

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct Sizes {
        seed: usize,
        pk: usize,
        eseed: usize,
        ct: usize,
        ss: usize,
    }

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct XWingVector {
        seed: String,
        sk: String,
        pk: String,
        eseed: String,
        ct: String,
        ss: String,
    }

    #[cfg(not(miri))]
    fn hex_decode(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "hex string has odd length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("vector file hex is valid"))
            .collect()
    }

    #[cfg(not(miri))]
    fn seed32(text: &str) -> [u8; SEALING_KEY_SIZE] {
        let bytes = hex_decode(text);
        assert_eq!(bytes.len(), SEALING_KEY_SIZE);
        let mut fixed = [0u8; SEALING_KEY_SIZE];
        fixed.copy_from_slice(&bytes);
        fixed
    }

    #[cfg(not(miri))]
    fn vector_file() -> XWingFile {
        let file: XWingFile = serde_json::from_str(XWING_JSON).expect("x-wing file parses");
        assert!(!file.vectors.is_empty(), "the x-wing file is empty");
        file
    }

    #[test]
    fn documented_sizes_match_the_specification() {
        assert_eq!(SEALING_KEY_SIZE, 32);
        assert_eq!(ENCAPSULATION_KEY_SIZE, 1216);
    }

    #[test]
    #[cfg(not(miri))]
    fn vector_file_declares_the_expected_sizes() {
        let file = vector_file();
        assert_eq!(file.sizes.seed, 32);
        assert_eq!(file.sizes.pk, 1216);
        assert_eq!(file.sizes.eseed, 64);
        assert_eq!(file.sizes.ct, 1120);
        assert_eq!(file.sizes.ss, 32);
    }

    #[test]
    #[cfg(not(miri))]
    fn xwing_keygen_matches_the_draft() {
        let file = vector_file();
        for (index, vector) in file.vectors.iter().enumerate() {
            let key = SealingKey::from_bytes(seed32(&vector.seed));
            assert_eq!(
                key.encapsulation_key().to_bytes().as_slice(),
                hex_decode(&vector.pk),
                "vector {index}: encapsulation key mismatch"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn xwing_decapsulation_matches_the_draft() {
        let file = vector_file();
        for (index, vector) in file.vectors.iter().enumerate() {
            assert_eq!(
                vector.seed, vector.sk,
                "vector {index}: the draft's seed and sk differ"
            );
            let key = SealingKey::from_bytes(seed32(&vector.sk));
            let shared = key
                .decapsulate(&hex_decode(&vector.ct))
                .expect("a 1120 byte ciphertext decapsulates");
            assert_eq!(
                shared.as_bytes().as_slice(),
                hex_decode(&vector.ss),
                "vector {index}: decapsulated shared secret mismatch"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn xwing_encapsulation_matches_the_draft() {
        use ml_kem::array::ArrayN;

        let file = vector_file();

        for (index, vector) in file.vectors.iter().enumerate() {
            let key = SealingKey::from_bytes(seed32(&vector.seed));
            let public = key.encapsulation_key();

            let mut randomness = ArrayN::<u8, 64>::default();
            randomness
                .as_mut_slice()
                .copy_from_slice(&hex_decode(&vector.eseed));

            // `encapsulate_deterministic` is hidden from the upstream docs and
            // is only correct with uniform randomness. mili calls it here with
            // published test vectors and nowhere else.
            let (ciphertext, shared) = public.0.encapsulate_deterministic(&randomness);

            assert_eq!(
                ciphertext.as_slice(),
                hex_decode(&vector.ct),
                "vector {index}: encapsulated ciphertext mismatch"
            );
            assert_eq!(
                shared.as_slice(),
                hex_decode(&vector.ss),
                "vector {index}: sender shared secret mismatch"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_key_decapsulates_to_a_different_secret() {
        let file = vector_file();
        let vector = &file.vectors[0];

        let right = SealingKey::from_bytes(seed32(&vector.seed));
        let wrong = SealingKey::from_bytes([0xABu8; SEALING_KEY_SIZE]);
        let ciphertext = hex_decode(&vector.ct);

        let expected = right.decapsulate(&ciphertext).expect("valid length");
        let actual = wrong.decapsulate(&ciphertext).expect("valid length");

        assert_ne!(
            expected.as_bytes(),
            actual.as_bytes(),
            "implicit rejection must yield a different shared secret"
        );
    }

    #[test]
    fn a_ciphertext_of_the_wrong_length_is_rejected() {
        let key = SealingKey::from_bytes([0u8; SEALING_KEY_SIZE]);
        assert!(matches!(key.decapsulate(&[]), Err(Error::Failed)));
        assert!(matches!(key.decapsulate(&[0u8; 1119]), Err(Error::Failed)));
        assert!(matches!(key.decapsulate(&[0u8; 1121]), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn key_generation_produces_distinct_keys() {
        let a = SealingKey::generate().expect("OS randomness is available");
        let b = SealingKey::generate().expect("OS randomness is available");
        assert_ne!(
            a.encapsulation_key().to_bytes(),
            b.encapsulation_key().to_bytes()
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn encapsulation_key_parsing_rejects_bad_lengths() {
        let key = SealingKey::generate().expect("OS randomness is available");
        let bytes = key.encapsulation_key().to_bytes();

        assert!(EncapsulationKey::from_bytes(&bytes[..1215]).is_err());
        assert!(EncapsulationKey::from_bytes(&[]).is_err());

        let mut too_long = bytes.to_vec();
        too_long.push(0);
        assert!(EncapsulationKey::from_bytes(&too_long).is_err());
    }

    #[test]
    #[cfg(not(miri))]
    fn encapsulation_key_parsing_rejects_an_invalid_mlkem_key() {
        let key = SealingKey::generate().expect("OS randomness is available");
        let mut bytes = key.encapsulation_key().to_bytes().to_vec();

        // ML-KEM-768 packs two 12 bit little endian coefficients per three bytes:
        // b0 = d0 low 8 bits, b1 = d0 high 4 bits with d1 low 4 bits, b2 = d1
        // high 8 bits. Byte 2 therefore holds the top of coefficient 1, and
        // setting it to 0xFF drives that coefficient to 4080, above the modulus
        // 3329. FIPS 203 requires an encapsulation key whose coefficients are not
        // reduced modulo q to be rejected, and X-Wing inherits that requirement.
        bytes[2] = 0xFF;

        assert!(matches!(
            EncapsulationKey::from_bytes(&bytes),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn encapsulation_key_round_trips_through_bytes() {
        let key = SealingKey::generate().expect("OS randomness is available");
        let bytes = key.encapsulation_key().to_bytes();
        let restored = EncapsulationKey::from_bytes(&bytes).expect("valid key");
        assert_eq!(restored.to_bytes(), bytes);
    }

    #[test]
    #[cfg(not(miri))]
    fn debug_is_redacted() {
        let key = SealingKey::from_bytes([0u8; SEALING_KEY_SIZE]);
        assert_eq!(format!("{key:?}"), "SealingKey([REDACTED])");
        let public = key.encapsulation_key();
        assert_eq!(format!("{public:?}"), "EncapsulationKey([REDACTED])");
    }

    #[test]
    #[cfg(not(miri))]
    fn encapsulation_agrees_with_decapsulation() {
        let key = SealingKey::generate().expect("OS randomness is available");
        let public = key.encapsulation_key();
        let (ciphertext, sender) = public.encapsulate();
        let recipient = key.decapsulate(&ciphertext).expect("valid length");
        assert_eq!(sender.as_bytes(), recipient.as_bytes());
    }
}
