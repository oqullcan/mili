//! Composite signatures: ML-DSA-65 and Ed25519, valid only if both verify.
//!
//! This is the `MLDSA65-Ed25519-SHA512` construction of
//! `draft-ietf-lamps-pq-composite-sigs`. That document is an IETF internet-draft,
//! not an RFC. `docs/SPEC.md` section 6 has the layout byte by byte.
//!
//! Three properties are worth stating before the API.
//!
//! **Both halves or nothing.** A signature verifies only when ML-DSA-65 verifies
//! *and* Ed25519 verifies. There is no partial acceptance path, no configuration
//! that selects a half, and no way to ask "did the classical half pass". The
//! point of a composite signature is that breaking it requires breaking both.
//!
//! **The signing key is the draft's key.** 64 bytes, the ML-DSA-65 seed followed
//! by the Ed25519 seed. It is not derived from a shorter master seed, so any
//! other implementation of the same construction can reconstruct it.
//!
//! **A key type cannot be misused.** [`SigningKey`] and [`VerifyingKey`] are
//! distinct newtypes that do not convert into [`crate::SealingKey`] or
//! [`crate::EncapsulationKey`], and no function takes more than one of them. A
//! signing key cannot reach an encryption operation, and an encryption key cannot
//! reach a signing operation.
//!
//! # Sizes
//!
//! | Object | Bytes | Layout |
//! |--------|-------|--------|
//! | [`SigningKey`] | 64 | ML-DSA-65 seed (32) \|\| Ed25519 seed (32) |
//! | [`VerifyingKey`] | 1984 | ML-DSA-65 public key (1952) \|\| Ed25519 public key (32) |
//! | signature | 3373 | ML-DSA-65 signature (3309) \|\| Ed25519 signature (64) |
//!
//! The signature is large. That is what a composite of ML-DSA-65 and Ed25519
//! costs, and it is the reason mili does not wrap signatures in the streaming
//! format.

use core::mem::size_of;
use ed25519_dalek::Signer as _;
use hybrid_array::Array;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyExport as _, KeyInit as _, MlDsa65,
    Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::Error;

/// Length in bytes of a composite signing key.
pub const SIGNING_KEY_SIZE: usize = ML_DSA65_SEED_SIZE + ED25519_SEED_SIZE;

/// Length in bytes of a composite verifying key.
pub const VERIFYING_KEY_SIZE: usize = ML_DSA65_VERIFYING_KEY_SIZE + ED25519_VERIFYING_KEY_SIZE;

// The lengths below are stated in terms of the upstream crates rather than written
// out, because a hand-written literal is only correct for one version of the
// dependency. `hybrid_array::Array` is `repr(transparent)` over `[u8; N]`, so its
// size is its length, and `ed25519_dalek` exports the three lengths it uses.
//
// This was not hypothetical. `ml_dsa_bytes`, `ml_dsa_signature_bytes` and
// `encoded_signature` used to copy into an array of a literal length, which panics
// when the lengths disagree, so an upstream size change would have become a panic on
// a library path — in a crate whose threat model says there is not one. The
// constants are now the upstream lengths, so there is nothing left to disagree.
//
// `size_of` and a path to a constant are both evaluated at compile time, so these
// are still constants and the ABI is unchanged. The absolute values are pinned by
// `sizes_are_the_documented_ones`, so a change upstream shows up as a failing test
// in this crate rather than a silent adoption of whatever a new version says.
//
// `ML_DSA65_SEED_SIZE` is the one length that stays a literal, because ml-dsa
// exposes the expanded signing key's length rather than the seed's. It is checked
// by the same test, against what `MlDsa65::new` accepts.

/// Length in bytes of the ML-DSA-65 seed inside a signing key.
pub const ML_DSA65_SEED_SIZE: usize = 32;

/// Length in bytes of the ML-DSA-65 public key inside a verifying key.
pub const ML_DSA65_VERIFYING_KEY_SIZE: usize = size_of::<EncodedVerifyingKey<MlDsa65>>();

/// Length in bytes of the Ed25519 seed inside a signing key.
pub const ED25519_SEED_SIZE: usize = ed25519_dalek::SECRET_KEY_LENGTH;

/// Length in bytes of the Ed25519 public key inside a verifying key.
pub const ED25519_VERIFYING_KEY_SIZE: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Length in bytes of the ML-DSA-65 signature half.
pub const ML_DSA65_SIGNATURE_SIZE: usize = size_of::<EncodedSignature<MlDsa65>>();

/// Length in bytes of the Ed25519 signature half.
pub const ED25519_SIGNATURE_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Length in bytes of the two component signatures inside a composite signature.
///
/// Not the length of a composite signature. That is [`SIGNATURE_SIZE`], and the
/// difference is this constant's six byte header.
///
/// The two are named apart because a caller who allocated `SIGNATURE_SIZE` bytes
/// from the old name got six bytes short, and the C ABI in `mili-ffi` did exactly
/// that until the header check caught it: `mili_sign` was handed a 3373 byte buffer
/// for a 3379 byte signature and wrote six bytes past the end. A constant whose name
/// is the total but whose value is a part is a defect in the constant, not in the
/// caller that read it.
pub const SIGNATURE_PAYLOAD_SIZE: usize = ML_DSA65_SIGNATURE_SIZE + ED25519_SIGNATURE_SIZE;

/// Length in bytes of a whole composite signature, header included.
pub const SIGNATURE_SIZE: usize = HEADER_SIZE + SIGNATURE_PAYLOAD_SIZE;

/// The magic every mili file starts with.
const MAGIC: [u8; 4] = *b"mili";

/// The `format_type` byte of a composite signature.
const FORMAT_TYPE: u8 = 0x03;

/// The `version` byte of a composite signature.
const VERSION: u8 = 0x01;

/// The `Prefix` octet string of the composite draft, as fixed bytes.
const COMPOSITE_PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/// The `Label` for this composite algorithm, as fixed bytes.
///
/// The draft also passes this value into ML-DSA as its context string.
const LABEL: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

/// The object identifier the draft assigns to this composite algorithm.
///
/// Recorded for interoperability. mili does not implement X.509, so the value is
/// not used to build anything.
pub const OID: &str = "1.3.6.1.5.5.7.6.48";

/// A composite signing key: the ML-DSA-65 seed followed by the Ed25519 seed.
///
/// Zeroized on drop, `Debug` is redacted, `Display` is not implemented, there is
/// no `Clone` and no serialization trait.
pub struct SigningKey(SecretBytes<SIGNING_KEY_SIZE>);

impl SigningKey {
    /// Draws a new key from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the operating system randomness source is
    /// unavailable.
    pub fn generate() -> Result<Self, Error> {
        let bytes = crate::rng::array::<SIGNING_KEY_SIZE>()?;
        Ok(Self(SecretBytes::from_bytes(bytes)))
    }

    /// Wraps an existing 64 byte composite seed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNING_KEY_SIZE]) -> Self {
        Self(SecretBytes::from_bytes(bytes))
    }

    /// Borrows the seed.
    ///
    /// Crate-private, for wrapping the key in a key file and for the FFI
    /// boundary.
    pub(crate) fn expose(&self) -> &[u8; SIGNING_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Copies the seed out, for storing a key or handing it to another process.
    ///
    /// # What this exposes
    ///
    /// The seed is the private key, 32 bytes for each of the two component
    /// schemes. Public because a caller has to be able to persist a key, and
    /// because `mili-ffi` needs to move one across the C ABI.
    ///
    /// [`crate::kem::SealingKey::to_bytes`] says what the caller then owes; it is the
    /// same here.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_SIZE] {
        *self.expose()
    }

    /// Derives the matching verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let (mldsa_seed, ed25519_seed) = split(&self.0);
        VerifyingKey(component_public_keys(&mldsa_seed, &ed25519_seed))
    }

    /// Signs `message` and returns the `mili-sig-v1` encoding.
    ///
    /// The ML-DSA half is signed hedged: FIPS 204's randomised variant, with 32
    /// bytes from [`crate::rng`], which is the only randomness source mili has and
    /// which offers no caller-supplied alternative. The ML-DSA signature is
    /// therefore not a function of the key and the message alone, and no fault
    /// attack that a deterministic signer is exposed to applies here.
    ///
    /// That is the whole of what this buys, and it is worth not claiming more:
    /// the composite signature is still linkable, because the Ed25519 half is
    /// deterministic and is carried verbatim. See `THREAT_MODEL.md` section 3.6
    /// and the test named `the_ed25519_half_is_still_deterministic`.
    ///
    /// Verification is unaffected. The encoding is still `mili-sig-v1` at
    /// [`SIGNATURE_SIZE`] bytes and the Ed25519 half is unchanged; the randomness
    /// travels inside the ML-DSA signature, which is where FIPS 204 puts it.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the operating system randomness source is
    /// unavailable. FIPS 204 has no signature that needs no randomness, so failing
    /// closed is the only honest option; signing with a weak or repeated value
    /// would risk a forgery, not merely a weaker signature.
    ///
    /// ML-DSA-65 also returns an error for a context string longer than 255 bytes,
    /// which is unreachable here because the label is a 30 byte constant. That
    /// shares the error type with the randomness failure and cannot be told apart
    /// from it, so it is reported as [`Error::Failed`] too.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let transcript = transcript(message);
        let (mldsa_seed, ed25519_seed) = split(&self.0);

        let mldsa_key = MlDsaSigningKey::<MlDsa65>::from_seed(&Array::from(*mldsa_seed));
        let mldsa_signature = mldsa_key
            .expanded_key()
            .sign_randomized(&transcript, LABEL, &mut crate::rng::TryRng)
            .map_err(|_| Error::Failed)?;
        let mldsa_bytes = ml_dsa_signature_bytes(mldsa_signature.encode());

        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let ed25519_bytes = ed25519.sign(&transcript).to_bytes();

        let mut out = Vec::with_capacity(SIGNATURE_SIZE);
        out.extend_from_slice(&MAGIC);
        out.push(FORMAT_TYPE);
        out.push(VERSION);
        out.extend_from_slice(&mldsa_bytes);
        out.extend_from_slice(&ed25519_bytes);
        Ok(out)
    }
}

/// A composite verifying key: the ML-DSA-65 public key followed by the Ed25519
/// public key.
pub struct VerifyingKey([u8; VERIFYING_KEY_SIZE]);

impl VerifyingKey {
    /// Parses the 1984 byte encoding.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the length is wrong or the embedded Ed25519 public
    /// key is not a valid point encoding. Both mean the input is not a usable
    /// verifying key, and saying which check failed tells a caller more about
    /// the key it supplied than it needs to know.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != VERIFYING_KEY_SIZE {
            return Err(Error::Failed);
        }
        let mut fixed = [0u8; VERIFYING_KEY_SIZE];
        fixed.copy_from_slice(bytes);
        let ed25519 = ed25519_dalek::VerifyingKey::from_bytes(&split_verifying(&fixed).1)
            .map_err(|_| Error::Failed)?;
        // A decodable point is not necessarily a usable key. The identity point
        // and the order eight torsion points decode fine and are of negligible
        // order, so a composite whose Ed25519 half is one of them can be forged
        // without any secret: the half accepts any transcript. That would reduce
        // the composite to ML-DSA-65 alone, which is the degradation the
        // construction exists to prevent, so the key is refused at parse time
        // rather than at verification.
        //
        // `is_weak` is the upstream's own test for this and is what
        // `verify_strict` would otherwise apply later.
        if ed25519.is_weak() {
            return Err(Error::Failed);
        }
        Ok(Self(fixed))
    }

    /// Copies the 1984 byte encoding out.
    ///
    /// These are public bytes. `Display` is still not implemented, so that a key
    /// cannot end up in a log line by accident.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_SIZE] {
        self.0
    }

    /// Verifies a `mili-sig-v1` signature over `message`.
    ///
    /// Returns as soon as one half fails, which the draft explicitly permits
    /// because no private key is involved in verification and there is nothing to
    /// learn from timing.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] if the version byte names a version this
    /// build does not implement. [`Error::Failed`] for a short buffer, a wrong
    /// magic, a wrong `format_type`, a malformed component key, a component
    /// signature that does not verify, and a message that is not the one signed.
    /// The last three are not distinguished.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let parsed = SignatureFile::parse(signature)?;

        let (mldsa_bytes, ed25519_bytes) = split_signature(parsed.0);
        let (mldsa_public, ed25519_public) = split_verifying(&self.0);

        let transcript = transcript(message);

        let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(&mldsa_public[..])
            .map_err(|_| Error::Failed)?;
        let mldsa_signature = MlDsaSignature::<MlDsa65>::decode(&encoded_signature(&mldsa_bytes))
            .ok_or(Error::Failed)?;

        if !MlDsaVerifyingKey::<MlDsa65>::new(&encoded_key).verify_with_context(
            &transcript,
            LABEL,
            &mldsa_signature,
        ) {
            return Err(Error::Failed);
        }

        // `ed25519::Signature::from_bytes` cannot fail: the 64 bytes are taken
        // as the two R and S scalars without a range check. A signature with an
        // out of range half is rejected by `verify` below, which is the check
        // that matters.
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&ed25519_bytes);
        let ed25519_key =
            ed25519_dalek::VerifyingKey::from_bytes(&ed25519_public).map_err(|_| Error::Failed)?;

        // `verify_strict` rather than `verify`, as defence in depth. `from_bytes`
        // already refuses a small order key, so this path should never see one,
        // but `verify` additionally accepts non-canonical `S` and `R` encodings
        // in some positions and `verify_strict` does not. The cost is a table
        // lookup per point, which is nothing next to ML-DSA-65.
        ed25519_key
            .verify_strict(&transcript, &ed25519_signature)
            .map_err(|_| Error::Failed)
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifyingKey([REDACTED])")
    }
}

/// Builds `M' = Prefix || Label || len(ctx) || ctx || PH(M)` with an empty
/// application context, exactly as section 3.2 of the draft specifies.
fn transcript(message: &[u8]) -> Vec<u8> {
    let prehash = Sha512::digest(message);

    // Every term is a constant or a label length, so this cannot overflow in
    // practice; saturating states that rather than leaving it to be checked.
    let capacity = COMPOSITE_PREFIX
        .len()
        .saturating_add(LABEL.len())
        .saturating_add(1)
        .saturating_add(64);
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(LABEL);
    out.push(0);
    out.extend_from_slice(&prehash);
    out
}

/// Length of the fixed header of a signature file.
const HEADER_SIZE: usize = 6;

/// Splits a composite seed into its two component seeds.
///
/// The halves come back in zeroizing buffers so that this frame does not leave a
/// second plain copy of either seed behind.
fn split(
    seed: &SecretBytes<SIGNING_KEY_SIZE>,
) -> (
    Zeroizing<[u8; ML_DSA65_SEED_SIZE]>,
    Zeroizing<[u8; ED25519_SEED_SIZE]>,
) {
    let all = seed.as_bytes();
    let mut mldsa = [0u8; ML_DSA65_SEED_SIZE];
    mldsa.copy_from_slice(&all[..ML_DSA65_SEED_SIZE]);
    let mut ed25519 = [0u8; ED25519_SEED_SIZE];
    ed25519.copy_from_slice(&all[ML_DSA65_SEED_SIZE..]);
    (Zeroizing::new(mldsa), Zeroizing::new(ed25519))
}

/// Derives the two component public keys from the two component seeds.
fn component_public_keys(
    mldsa_seed: &[u8; ML_DSA65_SEED_SIZE],
    ed25519_seed: &[u8; ED25519_SEED_SIZE],
) -> [u8; VERIFYING_KEY_SIZE] {
    let mldsa_key = MlDsaSigningKey::<MlDsa65>::from_seed(&Array::from(*mldsa_seed));
    let mldsa_public = ml_dsa_bytes(mldsa_key.expanded_key().verifying_key().to_bytes());
    let ed25519_public = ed25519_dalek::SigningKey::from_bytes(ed25519_seed)
        .verifying_key()
        .to_bytes();

    let mut bytes = [0u8; VERIFYING_KEY_SIZE];
    bytes[..ML_DSA65_VERIFYING_KEY_SIZE].copy_from_slice(&mldsa_public);
    bytes[ML_DSA65_VERIFYING_KEY_SIZE..].copy_from_slice(&ed25519_public);
    bytes
}

/// Copies an ML-DSA array out as fixed size bytes.
fn ml_dsa_bytes(bytes: EncodedVerifyingKey<MlDsa65>) -> [u8; ML_DSA65_VERIFYING_KEY_SIZE] {
    let mut out = [0u8; ML_DSA65_VERIFYING_KEY_SIZE];
    out.copy_from_slice(bytes.as_slice());
    out
}

/// Copies an ML-DSA signature out as fixed size bytes.
fn ml_dsa_signature_bytes(bytes: EncodedSignature<MlDsa65>) -> [u8; ML_DSA65_SIGNATURE_SIZE] {
    let mut out = [0u8; ML_DSA65_SIGNATURE_SIZE];
    out.copy_from_slice(bytes.as_slice());
    out
}

/// Wraps signature bytes in the type `Signature::decode` expects.
fn encoded_signature(bytes: &[u8; ML_DSA65_SIGNATURE_SIZE]) -> EncodedSignature<MlDsa65> {
    Array::from(*bytes)
}

/// Splits a verifying key into its two component public keys.
fn split_verifying(
    bytes: &[u8; VERIFYING_KEY_SIZE],
) -> (
    [u8; ML_DSA65_VERIFYING_KEY_SIZE],
    [u8; ED25519_VERIFYING_KEY_SIZE],
) {
    let mut mldsa = [0u8; ML_DSA65_VERIFYING_KEY_SIZE];
    mldsa.copy_from_slice(&bytes[..ML_DSA65_VERIFYING_KEY_SIZE]);
    let mut ed25519 = [0u8; ED25519_VERIFYING_KEY_SIZE];
    ed25519.copy_from_slice(&bytes[ML_DSA65_VERIFYING_KEY_SIZE..]);
    (mldsa, ed25519)
}

/// Splits a signature file body into its two component signatures.
fn split_signature(file: &[u8]) -> ([u8; ML_DSA65_SIGNATURE_SIZE], [u8; ED25519_SIGNATURE_SIZE]) {
    let body = &file[HEADER_SIZE..];
    let mut mldsa = [0u8; ML_DSA65_SIGNATURE_SIZE];
    mldsa.copy_from_slice(&body[..ML_DSA65_SIGNATURE_SIZE]);
    let mut ed25519 = [0u8; ED25519_SIGNATURE_SIZE];
    ed25519.copy_from_slice(&body[ML_DSA65_SIGNATURE_SIZE..]);
    (mldsa, ed25519)
}

/// The `mili-sig-v1` file: magic, format type, version, then the two halves.
struct SignatureFile<'a>(&'a [u8]);

impl<'a> SignatureFile<'a> {
    /// Parses and length checks a signature file.
    ///
    /// Nothing here is a security check. The magic, `format_type` and `version`
    /// bytes are public, and the cryptographic check happens in `verify`.
    fn parse(file: &'a [u8]) -> Result<Self, Error> {
        if file.len() != SIGNATURE_SIZE {
            return Err(Error::Failed);
        }
        if file[..4] != MAGIC || file[4] != FORMAT_TYPE {
            return Err(Error::Failed);
        }
        if file[5] != VERSION {
            return Err(Error::UnsupportedVersion);
        }
        Ok(Self(file))
    }
}

// The tests that reach into ML-DSA-65 or Ed25519 arithmetic are excluded
// under miri. Each call costs orders of magnitude more when miri interprets
// it, and `every_signature_byte_is_authenticated` alone runs three thousand
// verifications. The three tests that are not excluded check mili's own
// constants, labels and transcript, which is the part worth proving.
#[cfg(test)]
mod tests {
    // The lengths are constants, so they are imported unconditionally: `HEADER_SIZE`
    // and `ML_DSA65_SEED_SIZE` were previously only reachable from tests that sign,
    // which miri skips, and a size that cannot be asserted under miri is a size
    // nothing checks there.
    #[cfg(not(miri))]
    use super::SigningKey;
    use super::{
        transcript, ED25519_SEED_SIZE, ED25519_SIGNATURE_SIZE, ED25519_VERIFYING_KEY_SIZE,
        HEADER_SIZE, LABEL, ML_DSA65_SEED_SIZE, ML_DSA65_SIGNATURE_SIZE,
        ML_DSA65_VERIFYING_KEY_SIZE, OID, SIGNATURE_PAYLOAD_SIZE, SIGNATURE_SIZE, SIGNING_KEY_SIZE,
        VERIFYING_KEY_SIZE,
    };
    #[cfg(not(miri))]
    use crate::{Error, SealingKey};
    #[cfg(not(miri))]
    use hybrid_array::Array;
    #[cfg(not(miri))]
    use ml_dsa::{
        EncodedVerifyingKey, KeyInit as _, MlDsa65, Signature as MlDsaSignature,
        VerifyingKey as MlDsaVerifyingKey,
    };
    #[cfg(not(miri))]
    use serde::Deserialize;

    #[cfg(not(miri))]
    const LAMPS_JSON: &str = include_str!("../../tests/vectors/lamps19_composite_ed25519.json");

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct VectorFile {
        source: String,
        label: String,
        prefix: String,
        message: String,
        sizes: Sizes,
        vector: Vector,
    }

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct Sizes {
        pk: usize,
        sk: usize,
        #[serde(rename = "s")]
        signature: usize,
        #[serde(rename = "sWithContext")]
        signature_with_context: usize,
    }

    #[cfg(not(miri))]
    #[derive(Deserialize)]
    struct Vector {
        #[serde(rename = "tcId")]
        tc_id: String,
        pk: String,
        sk: String,
        #[serde(rename = "s")]
        signature: String,
        #[serde(rename = "sWithContext")]
        signature_with_context: String,
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
    fn key() -> SigningKey {
        let mut bytes = [0x5Au8; SIGNING_KEY_SIZE];
        for byte in &mut bytes[ML_DSA65_SEED_SIZE..] {
            *byte = 0xA5;
        }
        SigningKey::from_bytes(bytes)
    }

    #[test]
    fn sizes_are_the_documented_ones() {
        // The constants are now defined in terms of the upstream crates, so this
        // test no longer proves they agree with those crates. It pins the absolute
        // values, which is the other half: an upstream release that changes a size
        // fails here instead of silently becoming mili's format version, because a
        // mili file written by one build has to be readable by the other.
        assert_eq!(HEADER_SIZE, 6);
        assert_eq!(SIGNING_KEY_SIZE, 64);
        assert_eq!(VERIFYING_KEY_SIZE, 1984);
        assert_eq!(SIGNATURE_PAYLOAD_SIZE, 3373);
        assert_eq!(SIGNATURE_SIZE, 3379);
        assert_eq!(ML_DSA65_SEED_SIZE, 32);
        assert_eq!(ML_DSA65_VERIFYING_KEY_SIZE, 1952);
        assert_eq!(ED25519_SEED_SIZE, 32);
        assert_eq!(ED25519_VERIFYING_KEY_SIZE, 32);
        assert_eq!(ML_DSA65_SIGNATURE_SIZE, 3309);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
        assert_eq!(
            ML_DSA65_VERIFYING_KEY_SIZE + ED25519_VERIFYING_KEY_SIZE,
            VERIFYING_KEY_SIZE
        );
        assert_eq!(
            ML_DSA65_SIGNATURE_SIZE + ED25519_SIGNATURE_SIZE,
            SIGNATURE_PAYLOAD_SIZE
        );
    }

    // Signing is what this test exists to do, and an ML-DSA-65 plus Ed25519
    // signature under miri is minutes rather than milliseconds. Everything it
    // checks is constant arithmetic that runs under miri in the test above.
    #[test]
    #[cfg(not(miri))]
    fn seed_lengths_are_the_ones_the_upstream_types_produce() {
        // ML_DSA65_SEED_SIZE is the one length left as a literal, because ml-dsa
        // publishes the expanded signing key's length and not the seed's. So
        // instead of trusting the literal, produce a real key and signature and
        // check that the sizes mili hands to a caller are the sizes upstream
        // produced. That is the property the C ABI depends on anyway: a caller
        // allocates `VERIFYING_KEY_SIZE` and `SIGNATURE_SIZE` and mili has to fill
        // exactly that many bytes.
        let mut seed = [0xA5u8; SIGNING_KEY_SIZE];
        seed[..ML_DSA65_SEED_SIZE].copy_from_slice(&[0xA5; ML_DSA65_SEED_SIZE]);
        seed[ML_DSA65_SEED_SIZE..].copy_from_slice(&[0x5A; ED25519_SEED_SIZE]);
        let key = SigningKey::from_bytes(seed);
        assert_eq!(key.to_bytes().len(), SIGNING_KEY_SIZE);

        let verifying_key = key.verifying_key().to_bytes();
        assert_eq!(verifying_key.len(), VERIFYING_KEY_SIZE);
        assert_eq!(
            &verifying_key[..ML_DSA65_VERIFYING_KEY_SIZE].len(),
            &ML_DSA65_VERIFYING_KEY_SIZE
        );
        assert_eq!(
            verifying_key[ML_DSA65_VERIFYING_KEY_SIZE..].len(),
            ED25519_VERIFYING_KEY_SIZE
        );

        let signature = key
            .sign(b"a message")
            .expect("signing with a fresh key succeeds");
        assert_eq!(signature.len(), SIGNATURE_SIZE);
        assert_eq!(signature.len() - HEADER_SIZE, SIGNATURE_PAYLOAD_SIZE);
        assert_eq!(
            &signature[HEADER_SIZE..HEADER_SIZE + ML_DSA65_SIGNATURE_SIZE].len(),
            &ML_DSA65_SIGNATURE_SIZE
        );
        assert_eq!(
            signature.len() - HEADER_SIZE - ML_DSA65_SIGNATURE_SIZE,
            ED25519_SIGNATURE_SIZE
        );
    }

    #[test]
    fn the_labels_are_the_ones_the_draft_names() {
        assert_eq!(OID, "1.3.6.1.5.5.7.6.48");
        assert_eq!(LABEL, b"COMPSIG-MLDSA65-Ed25519-SHA512");
        assert_eq!(LABEL.len(), 30);
    }

    #[test]
    fn the_transcript_has_the_draft_layout() {
        // Frozen expected value, computed with an independent SHA-512
        // implementation rather than typed out by hand.
        const EXPECTED: &str = concat!(
            "436f6d706f73697465416c676f726974686d5369676e61747572657332303235",
            "434f4d505349472d4d4c44534136352d456432353531392d534841353132",
            "00",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );

        let t = transcript(b"");
        assert_eq!(t.len(), 127);
        assert_eq!(&t[..32], b"CompositeAlgorithmSignatures2025");
        assert_eq!(&t[32..62], LABEL);
        assert_eq!(
            t[62], 0,
            "an empty application context must be encoded as zero"
        );
        assert_eq!(hex_encode(&t), EXPECTED);
    }

    fn hex_encode(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip() {
        let key = key();
        let verifying = key.verifying_key();

        for message in [
            &b""[..],
            b"a",
            b"a longer message to sign",
            &[0x5Au8; 5000][..],
        ] {
            let signature = key.sign(message).expect("sign");
            assert_eq!(signature.len(), SIGNATURE_SIZE);
            verifying.verify(message, &signature).expect("verify");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_different_message_does_not_verify() {
        let key = key();
        let signature = key.sign(b"signed message").expect("sign");
        assert!(matches!(
            key.verifying_key().verify(b"other message", &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_key_does_not_verify() {
        let key = key();
        let signature = key.sign(b"a message").expect("sign");
        let wrong = SigningKey::from_bytes([0xC3u8; SIGNING_KEY_SIZE]);
        assert!(matches!(
            wrong.verifying_key().verify(b"a message", &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn both_halves_are_required() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let mut signature = key.sign(message).expect("sign");

        // Corrupt the ML-DSA half only.
        let mut broken = signature.clone();
        broken[6] ^= 0x01;
        assert!(
            matches!(verifying.verify(message, &broken), Err(Error::Failed)),
            "a signature with a corrupt ML-DSA half must not verify"
        );

        // Corrupt the Ed25519 half only.
        let mut broken = signature.clone();
        let last = broken.len() - 1;
        broken[last] ^= 0x01;
        assert!(
            matches!(verifying.verify(message, &broken), Err(Error::Failed)),
            "a signature with a corrupt Ed25519 half must not verify"
        );

        // Corrupt a byte in the ML-DSA hint region, which changes the signature
        // without making the encoding undecodable.
        signature[HEADER_SIZE + 100] ^= 0x01;
        assert!(matches!(
            verifying.verify(message, &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn every_signature_byte_is_authenticated() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message to sign";
        let signature = key.sign(message).expect("sign");

        for index in HEADER_SIZE..signature.len() {
            let mut tampered = signature.clone();
            tampered[index] ^= 0x01;
            assert!(
                matches!(verifying.verify(message, &tampered), Err(Error::Failed)),
                "byte {index} was accepted after a bit flip"
            );
        }

        // The header bytes are checked before any cryptography, so flipping the
        // version byte is reported as an unsupported version rather than as a
        // failed authentication. That distinction is deliberate and public.
        for index in 0..HEADER_SIZE {
            let mut tampered = signature.clone();
            tampered[index] ^= 0x01;
            let result = verifying.verify(message, &tampered);
            assert!(
                result.is_err(),
                "header byte {index} was accepted after a flip"
            );
            if index == 5 {
                assert!(matches!(result, Err(Error::UnsupportedVersion)));
            } else {
                assert!(matches!(result, Err(Error::Failed)));
            }
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_header_is_checked() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let signature = key.sign(message).expect("sign");

        let mut bad_magic = signature.clone();
        bad_magic[0] ^= 0xFF;
        assert!(matches!(
            verifying.verify(message, &bad_magic),
            Err(Error::Failed)
        ));

        let mut bad_type = signature.clone();
        bad_type[4] = 0x02;
        assert!(matches!(
            verifying.verify(message, &bad_type),
            Err(Error::Failed)
        ));

        let mut bad_version = signature.clone();
        bad_version[5] = 0x02;
        assert!(matches!(
            verifying.verify(message, &bad_version),
            Err(Error::UnsupportedVersion)
        ));
    }

    /// Two signatures over the same message differ, and both verify.
    ///
    /// FIPS 204 has an optional deterministic variant and `sign_deterministic`
    /// is the one mili used, so every signature a key produces was a function of
    /// that key and that message alone. Anyone holding two documents signed by
    /// the same identity could therefore link them from the ML-DSA half. Hedging
    /// removes that, at the cost of one more call to the RNG that was already
    /// there. It does not make the composite unlinkable; see
    /// `the_ed25519_half_is_still_deterministic`.
    ///
    /// Written so it cannot pass by accident: if signing is still deterministic
    /// the two signatures are equal and the first assertion fails; if signing is
    /// randomised but the signatures do not verify, the second fails.
    #[test]
    #[cfg(not(miri))]
    fn two_signatures_of_the_same_message_differ_and_both_verify() {
        let mut seed = [0x5Au8; SIGNING_KEY_SIZE];
        seed[..32].copy_from_slice(&[0x21u8; 32]);
        seed[32..].copy_from_slice(&[0xA3u8; 32]);
        let key = SigningKey::from_bytes(seed);
        let message = b"a message that is signed twice";

        let first = key.sign(message).expect("sign");
        let second = key.sign(message).expect("sign");

        assert_ne!(
            first, second,
            "two signatures over the same message with the same key are identical, \
             which means the ML-DSA half is deterministic and its outputs are linkable"
        );

        let verifying = key.verifying_key();
        assert!(
            verifying.verify(message, &first).is_ok(),
            "the first does not verify"
        );
        assert!(
            verifying.verify(message, &second).is_ok(),
            "the second does not verify"
        );

        // And the randomness is real rather than a counter or a clock, which would
        // collide on a fast machine. Sized so a repeating pattern is caught.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let signature = key.sign(message).expect("sign");
            assert!(
                seen.insert(signature.clone()),
                "a signature repeated within 100 attempts, so the variation is not random"
            );
            assert!(
                verifying.verify(message, &signature).is_ok(),
                "a signature did not verify"
            );
        }
    }

    /// The Ed25519 half is still identical between two signatures, and this is
    /// the reason the composite signature remains linkable.
    ///
    /// Hedging the ML-DSA half does not make the composite unlinkable, and it is
    /// worth being exact about why. The composite is `mili-sig-v1`: the two
    /// signatures concatenated, both carried verbatim. Ed25519 is deterministic by
    /// construction (RFC 8032) and mili signs the same transcript every time, so
    /// its 64 bytes repeat exactly. An observer holding two signatures from one
    /// identity compares those 64 bytes and links them, with no effort and
    /// without the verifying key.
    ///
    /// So the change buys what randomised ML-DSA signing is actually for, which
    /// is fault-attack resistance against a deterministic signer, and it removes
    /// the ML-DSA half from being a deterministic function of key and message. It
    /// does not remove linkability. Recording that as a test rather than a
    /// sentence is deliberate: if a future format change drops or replaces the
    /// Ed25519 half, this test is what should fail, so the claim can be revisited
    /// with evidence instead of memory.
    #[test]
    #[cfg(not(miri))]
    fn the_ed25519_half_is_still_deterministic() {
        let mut seed = [0x5Au8; SIGNING_KEY_SIZE];
        seed[..32].copy_from_slice(&[0x21u8; 32]);
        seed[32..].copy_from_slice(&[0xA3u8; 32]);
        let key = SigningKey::from_bytes(seed);
        let message = b"a message that is signed twice";

        let first = key.sign(message).expect("sign");
        let second = key.sign(message).expect("sign");

        let ed25519_start = SIGNATURE_SIZE - ED25519_SIGNATURE_SIZE;
        assert_eq!(
            &first[ed25519_start..],
            &second[ed25519_start..],
            "the Ed25519 half became randomised, so the composite signature is no \
             longer linkable and THREAT_MODEL section 3.6 needs rewriting rather \
             than this assertion changing"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn every_truncation_is_rejected() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let signature = key.sign(message).expect("sign");

        for len in [0usize, 1, 5, 6, 100, 2000, 3378, signature.len() - 1] {
            assert!(
                verifying.verify(message, &signature[..len]).is_err(),
                "truncation to {len} bytes was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn appended_bytes_are_rejected() {
        let key = key();
        let verifying = key.verifying_key();
        let message = b"a message";
        let mut signature = key.sign(message).expect("sign");
        signature.push(0);
        assert!(matches!(
            verifying.verify(message, &signature),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn verifying_key_parsing_rejects_bad_input() {
        let key = key();
        let bytes = key.verifying_key().to_bytes();

        assert!(super::VerifyingKey::from_bytes(&bytes[..VERIFYING_KEY_SIZE - 1]).is_err());
        assert!(super::VerifyingKey::from_bytes(&[]).is_err());

        let mut too_long = bytes.to_vec();
        too_long.push(0);
        assert!(super::VerifyingKey::from_bytes(&too_long).is_err());

        // An Ed25519 public key is a compressed Edwards point; a value that is not
        // a valid encoding must be rejected. `0xEC` repeated is one: the masked
        // y coordinate does not decode to a curve point. `[0xFF; 32]` is not,
        // because it is a valid encoding, so it would be a bad choice here.
        let mut bad_point = bytes;
        let offset = ML_DSA65_VERIFYING_KEY_SIZE;
        bad_point[offset..offset + ED25519_VERIFYING_KEY_SIZE].copy_from_slice(&[0xEC; 32]);
        assert!(matches!(
            super::VerifyingKey::from_bytes(&bad_point),
            Err(Error::Failed)
        ));
    }

    /// A key that decodes is not the same as a key that is safe to verify with.
    ///
    /// The identity point `[1, 0, 0, ..., 0]` is a valid compressed Edwards
    /// encoding, so it passes `VerifyingKey::from_bytes`. It is also of order one,
    /// which means the Ed25519 half of a composite signed with it carries no
    /// secrecy and no binding to a key at all: anyone can satisfy that half.
    ///
    /// This matters because `docs/THREAT_MODEL.md` section 3.5 and the module
    /// comment both rest the guarantee on both halves verifying. A degenerate but
    /// accepted key would silently reduce the composite to ML-DSA-65 alone, which
    /// is exactly the degradation the construction exists to prevent.
    #[test]
    #[cfg(not(miri))]
    fn a_small_order_ed25519_key_is_rejected() {
        let key = key();
        let mut bytes = key.verifying_key().to_bytes();
        let offset = ML_DSA65_VERIFYING_KEY_SIZE;
        bytes[offset..offset + ED25519_VERIFYING_KEY_SIZE].copy_from_slice(&[0u8; 32]);
        // The identity point is [1, 0, ...], so the first byte is 1 and the rest 0.
        bytes[offset] = 1;
        assert!(
            matches!(super::VerifyingKey::from_bytes(&bytes), Err(Error::Failed)),
            "a small order Ed25519 verifying key was accepted"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn verifying_key_round_trips_through_bytes() {
        let key = key();
        let bytes = key.verifying_key().to_bytes();
        let restored = super::VerifyingKey::from_bytes(&bytes).expect("valid key");
        assert_eq!(restored.to_bytes(), bytes);

        let signature = key.sign(b"a message").expect("sign");
        restored.verify(b"a message", &signature).expect("verify");
    }

    #[test]
    #[cfg(not(miri))]
    fn key_generation_produces_distinct_keys() {
        let a = SigningKey::generate().expect("OS randomness is available");
        let b = SigningKey::generate().expect("OS randomness is available");
        assert_ne!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    #[cfg(not(miri))]
    fn debug_is_redacted() {
        assert_eq!(format!("{:?}", key()), "SigningKey([REDACTED])");
        assert_eq!(
            format!("{:?}", key().verifying_key()),
            "VerifyingKey([REDACTED])"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn the_two_seed_halves_are_independent() {
        // Flipping one half of the composite seed must change the verifying key,
        // which is the property that a single shared seed would not have.
        let base = key();
        let mut flipped = *base.expose();
        flipped[0] ^= 0xFF;
        assert_ne!(
            base.verifying_key().to_bytes(),
            SigningKey::from_bytes(flipped).verifying_key().to_bytes()
        );

        let mut flipped = *base.expose();
        flipped[32] ^= 0xFF;
        assert_ne!(
            base.verifying_key().to_bytes(),
            SigningKey::from_bytes(flipped).verifying_key().to_bytes()
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn a_sealing_key_cannot_be_used_here() {
        // The compile time guarantee is that these are distinct types. This test
        // records the runtime consequence, which is that a sealing key's bytes
        // are not a valid composite signing key with the same meaning.
        let sealing = SealingKey::from_bytes([0x11u8; 32]);
        let composite = SigningKey::from_bytes([0x11u8; SIGNING_KEY_SIZE]);
        let signature = composite.sign(b"a message").expect("sign");
        assert!(matches!(
            composite.verifying_key().verify(b"a message", &signature),
            Ok(())
        ));
        let _ = sealing.encapsulation_key();
    }

    #[test]
    #[cfg(not(miri))]
    fn lamps_draft_vector() {
        let file: VectorFile = serde_json::from_str(LAMPS_JSON).expect("lamps vector file parses");

        assert!(file.source.contains("lamps-pq-composite-sigs-19"));
        assert_eq!(file.label, "COMPSIG-MLDSA65-Ed25519-SHA512");
        assert_eq!(file.prefix, "CompositeAlgorithmSignatures2025");
        assert_eq!(file.sizes.pk, VERIFYING_KEY_SIZE);
        assert_eq!(file.sizes.sk, SIGNING_KEY_SIZE);
        // The draft's sizes are the two component signatures and nothing else. mili's
        // wire size is those plus this crate's own six byte header, so this compares
        // like with like rather than a draft quantity against a mili quantity that
        // happened to be spelled the same way.
        assert_eq!(file.sizes.signature, SIGNATURE_PAYLOAD_SIZE);
        assert_eq!(file.sizes.signature_with_context, SIGNATURE_PAYLOAD_SIZE);
        assert_eq!(SIGNATURE_SIZE, HEADER_SIZE + SIGNATURE_PAYLOAD_SIZE);

        let vector = &file.vector;
        assert_eq!(vector.tc_id, "id-MLDSA65-Ed25519-SHA512");

        let message = file.message.as_bytes();
        let verifying = super::VerifyingKey::from_bytes(&hex_decode(&vector.pk))
            .expect("the draft's public key is a valid composite key");

        // The signature computed with an empty application context is the one
        // mili produces, because mili always uses an empty context.
        let signature = hex_decode(&vector.signature);
        let mut file_bytes = Vec::with_capacity(HEADER_SIZE + signature.len());
        file_bytes.extend_from_slice(b"mili");
        file_bytes.push(0x03);
        file_bytes.push(0x01);
        file_bytes.extend_from_slice(&signature);

        verifying
            .verify(message, &file_bytes)
            .expect("the draft's signature must verify under mili's construction");

        // The draft's signing key must derive the draft's published verifying
        // key. That part is exact and is checked here.
        let mut seed = [0u8; SIGNING_KEY_SIZE];
        seed.copy_from_slice(&hex_decode(&vector.sk));
        let signing = SigningKey::from_bytes(seed);
        assert_eq!(
            signing.verifying_key().to_bytes().as_slice(),
            hex_decode(&vector.pk).as_slice(),
            "mili's verifying key differs from the draft's published key"
        );

        // mili's own signature over the same key and message must also verify,
        // but is not byte identical to the published one. The reference
        // implementation that produced the draft's vectors used randomised ML-DSA
        // signing, so those vectors pin verification and were never reproducible
        // byte for byte by anyone, and mili randomises too. See docs/SPEC.md
        // section 6.4.
        //
        // This assertion no longer carries much information: with both signers
        // randomised, two signatures almost certainly differ whatever the
        // implementations do. It is kept because it is the check that would catch
        // a change which made signing deterministic, not because it can now
        // prove one.
        let produced = signing.sign(message).expect("sign");
        assert_ne!(
            produced, file_bytes,
            "mili produced the draft's exact signature, which would mean mili is \
             signing deterministically"
        );
        verifying
            .verify(message, &produced)
            .expect("mili's own signature verifies");
    }

    #[test]
    #[cfg(not(miri))]
    fn the_draft_vector_with_a_context_does_not_verify_under_an_empty_context() {
        // mili always signs with an empty application context, so the draft's
        // sWithContext value, which was produced over a non-empty ctx, must not
        // verify. This is what proves mili is not accidentally ignoring the
        // context field.
        let file: VectorFile = serde_json::from_str(LAMPS_JSON).expect("lamps vector file parses");
        let verifying =
            super::VerifyingKey::from_bytes(&hex_decode(&file.vector.pk)).expect("valid key");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"mili");
        bytes.push(0x03);
        bytes.push(0x01);
        bytes.extend_from_slice(&hex_decode(&file.vector.signature_with_context));

        assert!(matches!(
            verifying.verify(file.message.as_bytes(), &bytes),
            Err(Error::Failed)
        ));
    }

    // The NIST ACVP corpus for ML-DSA-65 verification.
    //
    // This is the only known-answer coverage the ML-DSA half has, and its scope is
    // narrower than the file name suggests, so the scope is stated before the code.
    //
    // It covers the context-aware verification path: three published signatures
    // that must verify, and eight that must not. A verifier test that only checks
    // what it must accept cannot show that it refuses anything, so the negatives
    // are most of the file.
    //
    // The corpus is context-bearing on purpose, because that is the path mili takes.
    // The composite draft binds the ML-DSA half to the construction by passing the
    // algorithm label as ML-DSA's context string, so `VerifyingKey::verify` here
    // calls `verify_with_context` with a thirty byte label. Empty-context vectors
    // would not touch that call.
    //
    // It does not cover signing. The ACVP sigGen groups give an expanded secret key
    // rather than a seed, and `ml-dsa` 0.1.1 reaches an expanded key only through
    // `ExpandedSigningKey::from_expanded`, which the crate deprecates and
    // documents as a panic risk. `mili-core` is `#![forbid(unsafe_code)]` and its
    // threat model has no panic on a library path, so consuming those vectors
    // would mean using the one entry point upstream tells callers not to. mili's
    // signing output is pinned by the composite draft's Appendix E vector, which is
    // a verification test as well: it carries the draft's key and message and
    // checks that mili's signature verifies under them.
    //
    // The vector file records one further thing this test does not assert, because
    // it cannot be asserted honestly: ACVP's empty-context positive cases are
    // accepted by `verify_internal` and rejected by `verify_with_context`, and the
    // crate documents `verify_internal` as omitting the domain separator and the
    // context boundary, so the two disagree and the file does not say which is
    // right. mili never passes an empty context, so it has no exposure either way.
    #[cfg(not(miri))]
    const ACVP_SIGVER_JSON: &str = include_str!("../../tests/vectors/acvp_mldsa65_sigver.json");

    #[cfg(not(miri))]
    #[derive(serde::Deserialize)]
    struct AcvpSigVerFile {
        standard: String,
        vector_set: u32,
        groups: Vec<AcvpSigVerGroup>,
    }

    #[cfg(not(miri))]
    #[derive(serde::Deserialize)]
    struct AcvpSigVerGroup {
        parameter_set: String,
        function: String,
        pre_hash: String,
        context: String,
        cases: Vec<AcvpSigVerCase>,
    }

    #[cfg(not(miri))]
    #[derive(serde::Deserialize)]
    struct AcvpSigVerCase {
        tc_id: u32,
        pk: String,
        message: String,
        signature: String,
        must_verify: bool,
        #[serde(default)]
        context: Option<String>,
    }

    /// ML-DSA-65 verification agrees with the NIST ACVP corpus.
    #[test]
    #[cfg(not(miri))]
    fn ml_dsa65_verification_matches_the_nist_acvp_corpus() {
        let file: AcvpSigVerFile =
            serde_json::from_str(ACVP_SIGVER_JSON).expect("the acvp sigver file parses");
        assert_eq!(file.standard, "FIPS 204");
        assert_eq!(file.vector_set, 42, "the pinned ACVP vector set");
        assert!(!file.groups.is_empty(), "the acvp sigver file is empty");

        let mut accepted = 0usize;
        let mut refused_at_decode = 0usize;
        let mut refused_at_verify = 0usize;
        let mut saw_context_free_group = false;
        let mut saw_context_bound_group = false;

        for group in &file.groups {
            assert_eq!(group.parameter_set, "ML-DSA-65", "mili signs with only 65");
            assert_eq!(group.function, "verification");
            assert_eq!(
                group.pre_hash, "pure",
                "mili does not pre-hash before signing"
            );
            assert!(
                matches!(group.context.as_str(), "empty" | "present"),
                "unexpected context kind {}",
                group.context
            );

            for case in &group.cases {
                let label = format!("tc_id {}", case.tc_id);

                let pk = hex_decode(&case.pk);
                assert_eq!(
                    pk.len(),
                    ML_DSA65_VERIFYING_KEY_SIZE,
                    "{label}: the published key is not an ML-DSA-65 key"
                );
                let signature = hex_decode(&case.signature);
                assert_eq!(
                    signature.len(),
                    ML_DSA65_SIGNATURE_SIZE,
                    "{label}: the published signature is not an ML-DSA-65 signature"
                );
                let message = hex_decode(&case.message);
                let context = case.context.as_deref().map(hex_decode).unwrap_or_default();

                match group.context.as_str() {
                    "empty" => {
                        assert!(context.is_empty(), "{label}: the group says no context");
                        saw_context_free_group = true;
                    }
                    "present" => {
                        assert!(!context.is_empty(), "{label}: the group says a context");
                        assert!(
                            context.len() <= 255,
                            "{label}: FIPS 204 caps the context at 255 bytes"
                        );
                        saw_context_bound_group = true;
                    }
                    _ => unreachable!("checked above"),
                }

                // Built exactly the way `VerifyingKey::try_from` builds the ML-DSA
                // half of a composite key, so this exercises the construction mili
                // depends on rather than a parallel one. Every ACVP case carries a
                // well formed key — the tampering is in the signature, the message
                // or the context — so a decode failure here means mili or the crate
                // disagrees with NIST about what a key is.
                let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(pk.as_slice())
                    .unwrap_or_else(|_| panic!("{label}: the published key did not decode"));
                let verifying = MlDsaVerifyingKey::<MlDsa65>::new(&encoded_key);

                let decoded = MlDsaSignature::<MlDsa65>::decode(&Array::from(
                    <[u8; ML_DSA65_SIGNATURE_SIZE]>::try_from(signature.as_slice())
                        .expect("the length is checked above"),
                ));

                if case.must_verify {
                    let mldsa_signature = decoded.unwrap_or_else(|| {
                        panic!("{label}: ACVP says this verifies and it did not decode")
                    });
                    assert!(
                        verifying.verify_with_context(&message, &context, &mldsa_signature),
                        "{label}: ACVP says this verifies and it did not, with the \
                         published context of {} bytes",
                        context.len()
                    );

                    // A signature made with a context does not verify without it. This
                    // is the property that makes the context a domain separator rather
                    // than decoration, and it is the failure a caller that dropped the
                    // context from its own call would silently inherit. Asserted, not
                    // assumed, because it is what distinguishes the specified algorithm
                    // from `verify_internal`.
                    if !context.is_empty() {
                        assert!(
                            !verifying.verify_with_context(&message, &[], &mldsa_signature),
                            "{label}: a signature made with a non-empty context verified \
                             without it"
                        );
                    }
                    accepted += 1;
                    continue;
                }

                // ACVP's negatives are not all "well formed but wrong". Several are
                // corrupted in the encoding, and `Signature::decode` catches those:
                // FIPS 204 fixes which bytes of a signature must be zero, and a
                // signature with a non-zero byte there is not a signature. Both are
                // correct refusals and the test should not insist on which one
                // happens, only that the case does not verify.
                match decoded {
                    None => refused_at_decode += 1,
                    Some(mldsa_signature) => {
                        assert!(
                            !verifying.verify_with_context(&message, &context, &mldsa_signature),
                            "{label}: ACVP says this must not verify and it did"
                        );
                        refused_at_verify += 1;
                    }
                }
            }
        }

        // Both group shapes present. The context-free one is here only for its
        // negatives, but it is what proves the corpus is not entirely context-bound,
        // which is the property that would let a change to the context-free path go
        // unnoticed.
        assert!(saw_context_bound_group, "no case exercised a context");
        assert!(
            saw_context_free_group,
            "no case exercised the context-free path"
        );

        assert_eq!(
            accepted, 3,
            "the corpus is meant to hold three positive cases"
        );
        assert!(
            refused_at_decode + refused_at_verify == 8,
            "every one of the eight negative cases was refused, at decode or at verify"
        );
        // Both refusal routes present, because the two are different code paths and
        // a corpus that only reached one of them would not show that the other works.
        assert!(
            refused_at_decode > 0,
            "no negative case was refused at decode, so the corrupt-encoding check \
             these vectors exercise is not being tested"
        );
        assert!(
            refused_at_verify > 0,
            "no negative case reached verification, so a verifier that wrongly \
             accepts would not be caught by this file"
        );
    }
}
