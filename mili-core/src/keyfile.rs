//! Password-wrapped key files: the `mili-key-v1` format.
//!
//! A key file holds exactly one key, wrapped under a password. `docs/SPEC.md`
//! section 7 has the layout byte by byte.
//!
//! # The key derivation
//!
//! Argon2id at the profile of `docs/SPEC.md` section 7.1: 64 MiB of memory, 3
//! passes, 4 lanes, a 128 bit salt, a 256 bit output. That is the second
//! recommended option of RFC 9106 section 4, with the lane count left at 4.
//! Argon2's `p_cost` is its lane count, not a count of operating system threads,
//! so a profile with four lanes is single threaded and reproduces the same key
//! on every platform.
//!
//! The password is not stored and cannot be checked. A wrong password produces
//! a wrapping key that decrypts to nothing that authenticates.
//!
//! # What a key file does not tell you
//!
//! A key file carries a payload type but no key identifier. The only way to tell
//! which key a file holds is to open it. `mili-backup-v1` carries identifiers
//! for this reason; see `crate::backup`.
//!
//! # Parameter checks
//!
//! The cost parameters are written into the file, and `open` refuses any file
//! that asks for less than the documented floor. Without that check an attacker
//! who can rewrite a key file could weaken the parameters and then guess the
//! password offline. There is also a ceiling, so that a hostile file cannot make
//! mili allocate before it has authenticated anything. Both are checked before
//! Argon2 runs, so rejecting a file costs nothing.
//!
//! # The working memory
//!
//! Argon2's allocating entry point does not wipe the memory it uses. mili
//! allocates the blocks itself, hands them to the `with_memory` entry point, and
//! wipes them when they are dropped. The allocation is fallible, so a caller
//! whose system cannot provide 64 MiB gets an error rather than an abort.

// `Algorithm`, `Argon2`, `Params`, `Version`, `Block` and `Zeroizing` are used
// only by the real `derive_kek` and the `WorkingMemory` it allocates, both of
// which are `#[cfg(not(miri))]`. Under miri they are unused and CI compiles
// with `--deny warnings`, so they are gated with the code that needs them.
// `Zeroize` is not gated: it is also the trait behind `payload.zeroize()` on a
// parsed payload, which runs under miri.
#[cfg(not(miri))]
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::Zeroize;
#[cfg(not(miri))]
use zeroize::Zeroizing;

use crate::aead::{AeadKey, AeadNonce, TAG_SIZE};
use crate::error::Error;
use crate::format;
use crate::kdf::{self, Domain};
use crate::kem::SealingKey;
use crate::secret::{SecretBytes, SymmetricKey, SYMMETRIC_KEY_SIZE};
use crate::signature::{SigningKey, SIGNING_KEY_SIZE};

/// The `format_type` byte of a key file.
pub const FORMAT_TYPE: u8 = 0x10;

/// The `kdf_id` byte. mili writes one value and accepts no other.
pub const KDF_ARGON2ID: u8 = 0x01;

/// The `params_id` byte, naming the profile of [`PROFILE`].
pub const PROFILE_ID: u8 = 0x01;

/// `m_cost` in kibibytes: 64 MiB.
pub const M_COST: u32 = 65_536;

/// `t_cost`: passes over memory.
pub const T_COST: u32 = 3;

/// `p_cost`: Argon2 lane count, not operating system threads.
pub const P_COST: u32 = 4;

/// Length in bytes of the Argon2 salt.
pub const ARGON2_SALT_SIZE: usize = 16;

/// Smallest `m_cost` mili will accept on open, in kibibytes: 32 MiB.
pub const M_COST_FLOOR: u32 = 32_768;

/// Largest `m_cost` mili will accept on open, in kibibytes: 1 GiB.
///
/// A property of mili, not of Argon2, which has no upper bound worth speaking of.
///
/// A file claiming more than this is rejected before anything is allocated, so a
/// hostile file cannot cost the reader its memory.
pub const M_COST_CEILING: u32 = 1_048_576;

/// Smallest `t_cost` mili will accept on open.
pub const T_COST_FLOOR: u32 = 2;

/// Largest `t_cost` mili will accept on open.
///
/// This bound is not about strength. `t_cost` multiplies the work of a
/// derivation, and the value comes from the file being opened, so a large one is
/// a denial of service on whoever opens the file. Eight passes is already well
/// past the point where a password stops being the weak link.
pub const T_COST_CEILING: u32 = 8;

/// Smallest `p_cost` mili will accept on open.
pub const P_COST_FLOOR: u32 = 1;

/// Largest `p_cost` mili will accept on open.
///
/// Argon2 requires at least four lanes when it runs in parallel mode, and
/// `mili` allocates its working memory as one contiguous block array, so the
/// lane count is bounded by what that allocation can serve rather than by the
/// machine's core count.
pub const P_COST_CEILING: u32 = 16;

/// The payload type of a sealing key.
pub const PAYLOAD_SEALING: u8 = 0x01;

/// The payload type of a composite signing key.
pub const PAYLOAD_SIGNING: u8 = 0x02;

/// The payload type of a symmetric key.
pub const PAYLOAD_SYMMETRIC: u8 = 0x03;

/// Offset of the `kdf_id` field.
pub(crate) const KDF_ID_OFFSET: usize = 6;

/// Offset of the `params_id` field.
pub(crate) const PARAMS_ID_OFFSET: usize = 7;

/// Offset of the `m_cost` field.
pub(crate) const M_COST_OFFSET: usize = 8;

/// Offset of the `t_cost` field.
pub(crate) const T_COST_OFFSET: usize = 12;

/// Offset of the `p_cost` field.
pub(crate) const P_COST_OFFSET: usize = 16;

/// Offset of the Argon2 salt.
///
/// This is not `SALT_END`: the sealed box and the stream carry a 32 byte salt
/// starting at offset 6, and a key file carries kdf_id, params_id and three cost
/// parameters there instead. The two layouts share the first six bytes and
/// nothing after them.
pub(crate) const ARGON2_SALT_OFFSET: usize = P_COST_OFFSET + 4;

/// Offset of the `payload_type` field.
pub(crate) const PAYLOAD_TYPE_OFFSET: usize = ARGON2_SALT_OFFSET + ARGON2_SALT_SIZE;

/// Offset of the `payload_len` field.
pub(crate) const PAYLOAD_LEN_OFFSET: usize = PAYLOAD_TYPE_OFFSET + 1;

/// Length of the authenticated header: everything before the payload.
pub(crate) const HEADER_SIZE: usize = PAYLOAD_LEN_OFFSET + 4;

/// The one profile mili writes, as a named constant so the documentation and the
/// code cannot disagree.
pub const PROFILE: Argon2Profile = Argon2Profile {
    m_cost: M_COST,
    t_cost: T_COST,
    p_cost: P_COST,
    salt_size: ARGON2_SALT_SIZE,
};

/// The Argon2id parameters mili writes and the bounds it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Profile {
    /// Memory cost in kibibytes.
    pub m_cost: u32,
    /// Number of passes over memory.
    pub t_cost: u32,
    /// Argon2 lane count.
    pub p_cost: u32,
    /// Argon2 salt length in bytes.
    pub salt_size: usize,
}

/// A key file, as a byte string.
///
/// Holds one key wrapped under a password. The key never appears in the clear in
/// the type: opening produces a typed key, and there is no accessor that returns
/// the raw payload.
pub struct KeyFile(Vec<u8>);

impl KeyFile {
    /// Wraps a sealing key under `password`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the operating system randomness source is
    /// unavailable, if the 64 MiB working allocation fails, or if Argon2 rejects
    /// the inputs. A password shorter than one byte is rejected, because Argon2
    /// accepts an empty one and an empty password is not a thing a caller means.
    pub fn from_sealing_key(key: &SealingKey, password: &[u8]) -> Result<Self, Error> {
        Self::wrap(PAYLOAD_SEALING, key.expose(), password)
    }

    /// Wraps a composite signing key under `password`.
    ///
    /// # Errors
    ///
    /// As [`KeyFile::from_sealing_key`].
    pub fn from_signing_key(key: &SigningKey, password: &[u8]) -> Result<Self, Error> {
        Self::wrap(PAYLOAD_SIGNING, key.expose(), password)
    }

    /// Wraps a symmetric key under `password`.
    ///
    /// # Errors
    ///
    /// As [`KeyFile::from_sealing_key`].
    pub fn from_symmetric_key(key: &SymmetricKey, password: &[u8]) -> Result<Self, Error> {
        Self::wrap(PAYLOAD_SYMMETRIC, key.expose(), password)
    }

    /// Wraps raw payload bytes under `password`, at the fixed profile.
    fn wrap(payload_type: u8, payload: &[u8], password: &[u8]) -> Result<Self, Error> {
        check_password(password)?;
        let file = seal_payload(
            payload_type,
            payload,
            password,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )?;
        Ok(Self(file))
    }

    /// Unwraps this file and returns the payload type and the payload.
    ///
    /// Crate-private. The public entry points are the three typed openers, and
    /// this one hands back raw payload bytes for any type, which is exactly the
    /// raw access the typed openers exist to withhold.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] if the version byte names a version this
    /// build does not implement. [`Error::Failed`] for a short file, a wrong
    /// magic, a wrong `format_type`, a `kdf_id` or `params_id` other than the one
    /// mili writes, cost parameters outside the accepted range, an empty
    /// password, an allocation failure, and a payload that does not
    /// authenticate. A wrong password and a corrupted file are the same error.
    pub(crate) fn open_payload(&self, password: &[u8]) -> Result<(u8, SecretBytes<64>), Error> {
        check_password(password)?;
        let header = Header::parse(&self.0)?;
        check_params(header.m_cost, header.t_cost, header.p_cost)?;

        let wrap_key = wrap_key_for(
            password,
            &header.salt,
            header.m_cost,
            header.t_cost,
            header.p_cost,
        )?;
        let aead = AeadKey::from_secret(&wrap_key)?;

        let mut payload = self.0[HEADER_SIZE..].to_vec();
        aead.open_in_place(AeadNonce::ZERO, &self.0[..HEADER_SIZE], &mut payload)?;
        if payload.len() != header.payload_len {
            return Err(Error::Failed);
        }

        let mut fixed = [0u8; 64];
        if payload.len() > fixed.len() {
            return Err(Error::Failed);
        }
        fixed[..payload.len()].copy_from_slice(&payload);
        payload.zeroize();
        Ok((header.payload_type, SecretBytes::from_bytes(fixed)))
    }

    /// Reports which kind of key this file holds, without a password.
    ///
    /// Returns [`PAYLOAD_SEALING`], [`PAYLOAD_SIGNING`] or [`PAYLOAD_SYMMETRIC`].
    /// This authenticates nothing: any bytes have a payload type at a fixed offset,
    /// so the answer is a property of the header rather than of the contents. It is
    /// for a caller deciding which of its keys to try, and for the C ABI, which has
    /// no other way to ask.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the bytes are too short to hold a key file at all.
    /// Everything else about the file, including whether it authenticates, is
    /// decided on open.
    pub fn payload_type(&self) -> Result<u8, Error> {
        Header::parse(&self.0).map(|header| header.payload_type)
    }

    /// Unwraps this file, which must hold a sealing key.
    ///
    /// # Errors
    ///
    /// As `open_payload`, plus [`Error::Failed`] if the payload type
    /// is not [`PAYLOAD_SEALING`] or the length is not
    /// [`crate::SEALING_KEY_SIZE`].
    pub fn open_sealing_key(&self, password: &[u8]) -> Result<SealingKey, Error> {
        let (payload_type, payload) = self.open_payload(password)?;
        if payload_type != PAYLOAD_SEALING {
            return Err(Error::Failed);
        }
        let mut seed = [0u8; crate::SEALING_KEY_SIZE];
        seed.copy_from_slice(&payload.as_bytes()[..crate::SEALING_KEY_SIZE]);
        Ok(SealingKey::from_bytes(seed))
    }

    /// Unwraps this file, which must hold a composite signing key.
    ///
    /// # Errors
    ///
    /// As `open_payload`, plus [`Error::Failed`] if the payload type
    /// is not [`PAYLOAD_SIGNING`] or the length is not [`SIGNING_KEY_SIZE`].
    pub fn open_signing_key(&self, password: &[u8]) -> Result<SigningKey, Error> {
        let (payload_type, payload) = self.open_payload(password)?;
        if payload_type != PAYLOAD_SIGNING {
            return Err(Error::Failed);
        }
        let mut seed = [0u8; SIGNING_KEY_SIZE];
        seed.copy_from_slice(&payload.as_bytes()[..SIGNING_KEY_SIZE]);
        Ok(SigningKey::from_bytes(seed))
    }

    /// Unwraps this file, which must hold a symmetric key.
    ///
    /// # Errors
    ///
    /// As `open_payload`, plus [`Error::Failed`] if the payload type
    /// is not [`PAYLOAD_SYMMETRIC`] or the length is not [`SYMMETRIC_KEY_SIZE`].
    pub fn open_symmetric_key(&self, password: &[u8]) -> Result<SymmetricKey, Error> {
        let (payload_type, payload) = self.open_payload(password)?;
        if payload_type != PAYLOAD_SYMMETRIC {
            return Err(Error::Failed);
        }
        let mut seed = [0u8; SYMMETRIC_KEY_SIZE];
        seed.copy_from_slice(&payload.as_bytes()[..SYMMETRIC_KEY_SIZE]);
        Ok(SymmetricKey::from_bytes(seed))
    }

    /// Re-wraps this file under a fresh salt, with the same payload.
    ///
    /// This is key file rotation: the key is unchanged, so every file encrypted
    /// under it stays readable, but the file on disk is new and the old one can
    /// be destroyed. The cost parameters are read from this file, so a rotation
    /// does not silently move the file to a different profile.
    ///
    /// Rotating the key itself is a different thing: generate a new key and wrap
    /// it, then re-encrypt the data that was sealed to the old public key. There
    /// is no operation here that changes the key.
    ///
    /// # Errors
    ///
    /// As [`KeyFile::from_sealing_key`], and [`Error::Failed`] if the current
    /// file does not open, which for a wrong password is indistinguishable from
    /// a corrupted file.
    pub fn rotate(&self, password: &[u8]) -> Result<Self, Error> {
        let header = Header::parse(&self.0)?;
        check_params(header.m_cost, header.t_cost, header.p_cost)?;
        let (payload_type, payload) = self.open_payload(password)?;

        let file = seal_payload(
            payload_type,
            &payload.as_bytes()[..header.payload_len],
            password,
            header.m_cost,
            header.t_cost,
            header.p_cost,
        )?;
        Ok(Self(file))
    }

    /// Borrows the key file bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Takes the key file bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Wraps a key file's bytes back into a `KeyFile`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the bytes are too short to be a key file. The rest
    /// of the header is checked on open, not here, so that constructing a
    /// `KeyFile` from bytes a caller is holding cannot fail for a reason that
    /// only `open` can judge.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE + TAG_SIZE {
            return Err(Error::Failed);
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl core::fmt::Debug for KeyFile {
    /// Redacted. A key file is ciphertext, but its header says which payload type
    /// it holds, and printing that is a small leak for no benefit.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyFile([REDACTED])")
    }
}

/// Builds a key file around `payload` and encrypts it in place.
///
/// `out` is built as header then plaintext, then encrypted in place, so the
/// associated data is the header and the tag lands after the ciphertext.
fn seal_payload(
    payload_type: u8,
    payload: &[u8],
    password: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, Error> {
    let salt = crate::rng::array::<ARGON2_SALT_SIZE>()?;
    let header = build_header(payload_type, payload.len(), &salt, m_cost, t_cost, p_cost);
    let wrap_key = wrap_key_for(password, &salt, m_cost, t_cost, p_cost)?;
    let aead = AeadKey::from_secret(&wrap_key)?;

    // Only the payload goes into the cipher's buffer. The header is the
    // associated data, and it has to stay in the clear so that a reader can find
    // the salt and the cost parameters before it can decrypt anything.
    let mut ciphertext = payload.to_vec();
    aead.seal_extend(AeadNonce::ZERO, &header, &mut ciphertext)?;

    let mut file = header;
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

/// Builds the 41 byte header of a key file.
///
/// The layout is `docs/SPEC.md` section 7:
///
/// ```text
/// ofs  len  field
/// 0    4    magic "mili"
/// 4    1    format_type 0x10
/// 5    1    version 0x01
/// 6    1    kdf_id 0x01
/// 7    1    params_id 0x01
/// 8    4    m_cost, kibibytes
/// 12   4    t_cost
/// 16   4    p_cost
/// 20   16   argon2_salt
/// 36   1    payload_type
/// 37   4    payload_len
/// ```
fn build_header(
    payload_type: u8,
    payload_len: usize,
    salt: &[u8; ARGON2_SALT_SIZE],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_SIZE);
    format::write_fields(&mut header, FORMAT_TYPE);
    header.push(KDF_ARGON2ID);
    header.push(PROFILE_ID);
    header.extend_from_slice(&m_cost.to_be_bytes());
    header.extend_from_slice(&t_cost.to_be_bytes());
    header.extend_from_slice(&p_cost.to_be_bytes());
    header.extend_from_slice(salt);
    header.push(payload_type);
    header.extend_from_slice(&(payload_len as u32).to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_SIZE);
    header
}

const _: () = {
    // The layout is load bearing. If any of these move, every key file written by
    // an earlier build becomes unreadable, so they are asserted at compile time.
    assert!(KDF_ID_OFFSET == 6);
    assert!(PARAMS_ID_OFFSET == 7);
    assert!(M_COST_OFFSET == 8);
    assert!(T_COST_OFFSET == 12);
    assert!(P_COST_OFFSET == 16);
    assert!(ARGON2_SALT_OFFSET == 20);
    assert!(PAYLOAD_TYPE_OFFSET == 36);
    assert!(PAYLOAD_LEN_OFFSET == 37);
    assert!(HEADER_SIZE == 41);
};

/// Length in bytes of a key identifier.
pub const KEY_ID_SIZE: usize = 16;

/// Computes the identifier of a key, as `docs/SPEC.md` section 11 defines it.
///
/// The identifier is the first 16 bytes of an HKDF-SHA256 expansion of the
/// key's public bytes under the `mili-v1:keyid` label, with no salt.
///
/// A symmetric key has no public half, so its own bytes are used. That is sound:
/// HKDF-SHA256's output is a pseudorandom function of a 256 bit uniform input, so
/// publishing a 16 byte tag of it reveals nothing that a 2^256 search does not
/// already require, and it cannot be inverted to recover the key.
pub(crate) fn key_id_of(
    mldsa_or_xwing_public: Option<&[u8]>,
    symmetric: Option<&[u8]>,
) -> Result<[u8; KEY_ID_SIZE], Error> {
    let input = match (mldsa_or_xwing_public, symmetric) {
        (Some(public), None) => public,
        (None, Some(key)) => key,
        _ => return Err(Error::Internal),
    };
    let derived = kdf::derive::<KEY_ID_SIZE>(Domain::KeyId, input, &[])?;
    let mut id = [0u8; KEY_ID_SIZE];
    id.copy_from_slice(derived.as_bytes());
    Ok(id)
}

/// The parsed, still unauthenticated header of a key file.
struct Header {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; ARGON2_SALT_SIZE],
    payload_type: u8,
    payload_len: usize,
}

impl Header {
    /// Parses and length checks a key file header.
    ///
    /// Nothing here is a security check except the version byte, which is public
    /// in the sense that reporting it leaks nothing. Authentication happens in
    /// `open_payload`.
    fn parse(file: &[u8]) -> Result<Self, Error> {
        let body = format::parse_fields(file, FORMAT_TYPE, HEADER_SIZE + TAG_SIZE)?;
        if file[KDF_ID_OFFSET] != KDF_ARGON2ID || file[PARAMS_ID_OFFSET] != PROFILE_ID {
            return Err(Error::Failed);
        }
        debug_assert_eq!(
            Some(body.len()),
            file.len().checked_sub(format::FIELDS_OFFSET),
            "the parse must not have consumed past the prefix"
        );

        let mut salt = [0u8; ARGON2_SALT_SIZE];
        salt.copy_from_slice(&file[ARGON2_SALT_OFFSET..PAYLOAD_TYPE_OFFSET]);

        let m_cost = read_u32(file, M_COST_OFFSET)?;
        let t_cost = read_u32(file, T_COST_OFFSET)?;
        let p_cost = read_u32(file, P_COST_OFFSET)?;
        let payload_len = read_u32(file, PAYLOAD_LEN_OFFSET)? as usize;

        if payload_len > 64 {
            return Err(Error::Failed);
        }
        match format::exact_length(HEADER_SIZE, payload_len, TAG_SIZE) {
            Some(expected) if expected == file.len() => {}
            _ => return Err(Error::Failed),
        }

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
            salt,
            payload_type: file[PAYLOAD_TYPE_OFFSET],
            payload_len,
        })
    }
}

/// Reads a big endian `u32` at `offset`.
///
/// Returns an error rather than a number when the range is out of the buffer.
/// Every call site has already length checked the whole file, so this cannot
/// fire, but saying so with a fallible read costs nothing and removes the
/// unchecked index arithmetic that a caller could otherwise move.
fn read_u32(file: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Failed)?;
    let bytes: [u8; 4] = file
        .get(offset..end)
        .ok_or(Error::Failed)?
        .try_into()
        .map_err(|_| Error::Failed)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Rejects an empty password.
///
/// Argon2 accepts an empty password and would derive a real key from it. A
/// caller who passes an empty buffer has a bug, and a key file that opens with
/// the empty password is a key file whose protection is a coin flip.
pub(crate) fn check_password(password: &[u8]) -> Result<(), Error> {
    if password.is_empty() {
        return Err(Error::Failed);
    }
    Ok(())
}

/// Rejects cost parameters outside the range mili accepts.
///
/// All three bounds are checked before any memory is reserved, so a hostile file
/// cannot name a cost that costs the reader more than the profile does.
pub(crate) fn check_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), Error> {
    if !(M_COST_FLOOR..=M_COST_CEILING).contains(&m_cost) {
        return Err(Error::Failed);
    }
    if !(T_COST_FLOOR..=T_COST_CEILING).contains(&t_cost) {
        return Err(Error::Failed);
    }
    if !(P_COST_FLOOR..=P_COST_CEILING).contains(&p_cost) {
        return Err(Error::Failed);
    }
    // Argon2 requires at least `4 * p_cost` blocks for its block layout, and it
    // reports a `BannedTooMuchMemory` style configuration error rather than
    // producing output if the memory is too small. Rejecting here keeps that out
    // of the caller's error path.
    if (m_cost as u64) < 4 * (p_cost as u64) {
        return Err(Error::Failed);
    }
    Ok(())
}

/// Derives the AEAD wrapping key for a key file.
fn wrap_key_for(
    password: &[u8],
    salt: &[u8; ARGON2_SALT_SIZE],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<SecretBytes<32>, Error> {
    let kek = derive_kek(password, salt, m_cost, t_cost, p_cost)?;
    kdf::derive::<32>(Domain::KeyWrap, kek.as_bytes(), salt)
}

/// Derives the Argon2id key encryption key.
///
/// # Panics under miri
///
/// The miri build panics instead of deriving. This is a guard, not a policy: a
/// test that reaches this without `#[cfg(not(miri))]` would interpret 64 MiB of
/// Argon2 three times over and the miri job would appear to hang rather than
/// fail. One of the two overflow regression tests added for the bug the
/// `open_backup` fuzz target found was missing the attribute, and the symptom was
/// a job that never finished rather than a message saying which test was wrong.
#[cfg(not(miri))]
pub(crate) fn derive_kek(
    password: &[u8],
    salt: &[u8; ARGON2_SALT_SIZE],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<SecretBytes<32>, Error> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|_| Error::Failed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut memory = WorkingMemory::new(argon2.params().block_count())?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into_with_memory(password, salt, out.as_mut(), memory.blocks.as_mut_slice())
        .map_err(|_| Error::Failed)?;
    Ok(SecretBytes::from_bytes(*out))
}

/// See the note on the real `derive_kek`.
#[cfg(miri)]
pub(crate) fn derive_kek(
    _password: &[u8],
    _salt: &[u8; ARGON2_SALT_SIZE],
    _m_cost: u32,
    _t_cost: u32,
    _p_cost: u32,
) -> Result<SecretBytes<32>, Error> {
    panic!(
        "mili: a test reached an Argon2id derivation under miri. Add \
         #[cfg(not(miri))] to it. Argon2id at the documented profile is not \
         something to interpret."
    )
}

/// Argon2's working memory, wiped when it is dropped.
///
/// The allocating entry point of the `argon2` crate does not clear the blocks it
/// uses, and those blocks hold the password's memory-hardness work product. This
/// owns the allocation and clears it, including on the error paths.
///
/// Gated with the real `derive_kek` for the same reason as the imports above:
/// nothing constructs it under miri, and CI denies the warning that would say so.
#[cfg(not(miri))]
struct WorkingMemory {
    blocks: Vec<Block>,
}

#[cfg(not(miri))]
impl WorkingMemory {
    /// Allocates `count` zeroed 1 KiB blocks.
    fn new(count: usize) -> Result<Self, Error> {
        let mut blocks = Vec::new();
        // Reserving first keeps an allocation failure a returned error rather
        // than an abort inside `resize`.
        blocks.try_reserve_exact(count).map_err(|_| Error::Failed)?;
        blocks.resize(count, Block::new());
        Ok(Self { blocks })
    }
}

#[cfg(not(miri))]
impl Drop for WorkingMemory {
    fn drop(&mut self) {
        for block in &mut self.blocks {
            block.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    // Most of the tests in this module are excluded under miri, which leaves their
    // imports and helpers unreferenced. The ones that still run are the parsing and
    // layout checks, which do not derive a key.
    #![cfg_attr(miri, allow(unused))]
    use super::{build_header, wrap_key_for, AeadKey, AeadNonce};
    use super::{
        check_params, derive_kek, key_id_of, KeyFile, ARGON2_SALT_SIZE, HEADER_SIZE, KDF_ARGON2ID,
        KDF_ID_OFFSET, KEY_ID_SIZE, M_COST, M_COST_CEILING, M_COST_FLOOR, M_COST_OFFSET,
        PARAMS_ID_OFFSET, PAYLOAD_SEALING, PAYLOAD_SIGNING, PAYLOAD_SYMMETRIC, PROFILE, PROFILE_ID,
        P_COST, P_COST_CEILING, P_COST_FLOOR, P_COST_OFFSET, T_COST, T_COST_CEILING, T_COST_FLOOR,
        T_COST_OFFSET,
    };
    use crate::aead::TAG_SIZE;
    use crate::{Error, SealingKey, SigningKey, SymmetricKey};

    // Argon2id at 64 MiB takes about 0.2 seconds on this machine, and each
    // open or wrap runs it once. The tests below are written to keep the number
    // of derivations low: one round trip per key type, one per failure mode, and
    // the sweeps reuse a single wrapped file rather than re-wrapping per case.
    // The tests are excluded under miri because Argon2 interprets every 64 bit
    // multiplication of 64 MiB of blocks, which is far slower than it sounds.
    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn sealing() -> SealingKey {
        SealingKey::from_bytes([0x31u8; 32])
    }

    fn signing() -> SigningKey {
        let mut bytes = [0u8; 64];
        for byte in &mut bytes[..32] {
            *byte = 0x77;
        }
        for byte in &mut bytes[32..] {
            *byte = 0x88;
        }
        SigningKey::from_bytes(bytes)
    }

    fn symmetric() -> SymmetricKey {
        SymmetricKey::generate().expect("OS randomness is available")
    }

    const ARGON2_VECTORS: &str = include_str!("../../tests/vectors/argon2id_crosscheck.json");

    #[derive(serde::Deserialize)]
    struct Argon2File {
        version: u32,
        algorithm: String,
        tag_length: usize,
        secret: String,
        associated_data: String,
        cases: Vec<Argon2Case>,
    }

    #[derive(serde::Deserialize)]
    struct Argon2Case {
        name: String,
        note: String,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
        in_accepted_range: bool,
        password: String,
        salt: String,
        tag: String,
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "hex string has an odd length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex string"))
            .collect()
    }

    #[test]
    #[cfg(not(miri))]
    fn argon2id_vectors_from_the_reference_implementation() {
        // Tags produced by argon2-cffi, which binds the reference C
        // implementation. This is what pins the KDF: without it, a crate bump
        // that changed the derivation would pass every other test in this file,
        // because every other test derives and re-derives with the same code.
        let file: Argon2File =
            serde_json::from_str(ARGON2_VECTORS).expect("argon2id vector file parses");
        assert_eq!(file.algorithm, "argon2id");
        assert_eq!(file.version, 0x13, "Argon2 version 19");
        assert_eq!(file.tag_length, 32);
        assert!(file.secret.is_empty(), "mili passes no secret");
        assert!(
            file.associated_data.is_empty(),
            "mili passes no associated data"
        );
        assert!(!file.cases.is_empty(), "the argon2id file is empty");

        for case in &file.cases {
            let salt_bytes = hex_decode(&case.salt);
            let mut salt = [0u8; ARGON2_SALT_SIZE];
            salt.copy_from_slice(&salt_bytes);

            let derived = derive_kek(
                &hex_decode(&case.password),
                &salt,
                case.m_cost,
                case.t_cost,
                case.p_cost,
            );
            let derived = derived.unwrap_or_else(|_| panic!("{} derived", case.name));
            assert_eq!(
                hex_encode(derived.as_bytes()),
                case.tag,
                "{} disagrees with the reference implementation",
                case.name
            );
        }
    }

    #[test]
    fn argon2id_vector_file_shape_is_pinned() {
        let file: Argon2File =
            serde_json::from_str(ARGON2_VECTORS).expect("argon2id vector file parses");
        let names: Vec<&str> = file.cases.iter().map(|c| c.name.as_str()).collect();

        // mili's own profile has to be in there, or the vectors would only cover
        // shapes mili never uses.
        for required in ["mili_profile", "memory_floor", "memory_high"] {
            assert!(
                names.iter().any(|n| n.starts_with(required)),
                "{required} is missing from {names:?}"
            );
        }
        // And so does one shape mili refuses, so that the reference
        // implementation and the Rust crate are compared somewhere mili would
        // never reach.
        assert!(
            names.iter().any(|n| n.starts_with("rfc9106_shape")),
            "{names:?}"
        );

        let mut in_range = 0usize;
        for case in &file.cases {
            assert_eq!(case.salt.len(), ARGON2_SALT_SIZE * 2, "{}", case.name);
            assert_eq!(case.tag.len(), 64, "{}", case.name);
            assert!(!case.note.is_empty(), "{} has no note", case.name);

            // The file has to agree with the implementation about which
            // parameters mili accepts, or the flag is decoration.
            assert_eq!(
                check_params(case.m_cost, case.t_cost, case.p_cost).is_ok(),
                case.in_accepted_range,
                "{}: the file and check_params disagree",
                case.name
            );
            if case.in_accepted_range {
                in_range += 1;
            }
        }
        assert!(
            in_range >= 3 * 4,
            "only {in_range} cases are inside the accepted range"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn the_documented_profile_matches_its_own_vector() {
        // The profile mili writes, exercised end to end through a key file, so a
        // change to the profile constants cannot pass unnoticed.
        let salt = [0x5Cu8; ARGON2_SALT_SIZE];
        let derived = derive_kek(
            PASSWORD,
            &salt,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )
        .expect("derives");
        let again = derive_kek(
            PASSWORD,
            &salt,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )
        .expect("derives");
        assert_eq!(
            derived.as_bytes(),
            again.as_bytes(),
            "derivation is not deterministic"
        );

        let mut other_salt = salt;
        other_salt[0] ^= 0x01;
        let elsewhere = derive_kek(
            PASSWORD,
            &other_salt,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )
        .expect("derives");
        assert_ne!(
            derived.as_bytes(),
            elsewhere.as_bytes(),
            "the salt is not in the derivation"
        );

        let other_password = derive_kek(
            b"different",
            &salt,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )
        .expect("derives");
        assert_ne!(
            derived.as_bytes(),
            other_password.as_bytes(),
            "the password is not in the derivation"
        );
    }

    #[test]
    fn documented_profile() {
        assert_eq!(M_COST, 65_536, "64 MiB");
        assert_eq!(T_COST, 3);
        assert_eq!(P_COST, 4);
        assert_eq!(ARGON2_SALT_SIZE, 16);
        assert_eq!(M_COST_FLOOR, 32_768);
        assert_eq!(M_COST_CEILING, 1_048_576);
        assert_eq!(T_COST_FLOOR, 2);
        assert_eq!(T_COST_CEILING, 8);
        assert_eq!(P_COST_FLOOR, 1);
        assert_eq!(P_COST_CEILING, 16);
        assert_eq!(HEADER_SIZE, 41);
        assert_eq!(KDF_ARGON2ID, 0x01);
        assert_eq!(PROFILE_ID, 0x01);
        assert_eq!(KDF_ID_OFFSET, 6);
        assert_eq!(PARAMS_ID_OFFSET, 7);
        assert_eq!(M_COST_OFFSET, 8);
        assert_eq!(T_COST_OFFSET, 12);
        assert_eq!(P_COST_OFFSET, 16);
        assert_eq!(PAYLOAD_SEALING, 0x01);
        assert_eq!(PAYLOAD_SIGNING, 0x02);
        assert_eq!(PAYLOAD_SYMMETRIC, 0x03);
        assert_eq!(PROFILE.m_cost, M_COST);
        assert_eq!(PROFILE.t_cost, T_COST);
        assert_eq!(PROFILE.p_cost, P_COST);
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip_sealing_key() {
        let key = sealing();
        let file = KeyFile::from_sealing_key(&key, PASSWORD).expect("wrap");
        assert_eq!(file.as_bytes().len(), HEADER_SIZE + 32 + TAG_SIZE);
        let opened = file.open_sealing_key(PASSWORD).expect("open");
        assert_eq!(
            opened.encapsulation_key().to_bytes(),
            key.encapsulation_key().to_bytes()
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip_signing_key() {
        let key = signing();
        let file = KeyFile::from_signing_key(&key, PASSWORD).expect("wrap");
        assert_eq!(file.as_bytes().len(), HEADER_SIZE + 64 + TAG_SIZE);
        let opened = file.open_signing_key(PASSWORD).expect("open");
        assert_eq!(
            opened.verifying_key().to_bytes(),
            key.verifying_key().to_bytes()
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip_symmetric_key() {
        let key = symmetric();
        let file = KeyFile::from_symmetric_key(&key, PASSWORD).expect("wrap");
        assert_eq!(file.as_bytes().len(), HEADER_SIZE + 32 + TAG_SIZE);
        let opened = file.open_symmetric_key(PASSWORD).expect("open");
        assert_eq!(opened, key);
    }

    #[test]
    #[cfg(not(miri))]
    fn the_header_is_where_the_specification_says() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        let bytes = file.as_bytes();

        assert_eq!(&bytes[0..4], b"mili");
        assert_eq!(bytes[4], 0x10);
        assert_eq!(bytes[5], 0x01);
        assert_eq!(bytes[6], 0x01, "kdf_id must be Argon2id");
        assert_eq!(bytes[7], 0x01, "params_id must be the fixed profile");
        assert_eq!(&bytes[8..12], &M_COST.to_be_bytes());
        assert_eq!(&bytes[12..16], &T_COST.to_be_bytes());
        assert_eq!(&bytes[16..20], &P_COST.to_be_bytes());
        assert_eq!(bytes[36], 0x01, "payload_type must be sealing");
        assert_eq!(&bytes[37..41], &32u32.to_be_bytes());
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_password_is_rejected() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        assert!(matches!(
            file.open_sealing_key(b"not the password"),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_empty_password_is_rejected_on_both_sides() {
        // Argon2 accepts an empty password, so mili refuses it before it gets
        // there. A key file that opens with the empty password is a key file whose
        // protection is a coin flip.
        let key = sealing();
        assert!(matches!(
            KeyFile::from_sealing_key(&key, b""),
            Err(Error::Failed)
        ));

        let file = KeyFile::from_sealing_key(&key, PASSWORD).expect("wrap");
        assert!(matches!(file.open_sealing_key(b""), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn the_opener_must_match_the_payload_type() {
        let sealing_file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        let signing_file = KeyFile::from_signing_key(&signing(), PASSWORD).expect("wrap");
        let symmetric_file = KeyFile::from_symmetric_key(&symmetric(), PASSWORD).expect("wrap");

        assert!(matches!(
            sealing_file.open_signing_key(PASSWORD),
            Err(Error::Failed)
        ));
        assert!(matches!(
            sealing_file.open_symmetric_key(PASSWORD),
            Err(Error::Failed)
        ));
        assert!(matches!(
            signing_file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
        assert!(matches!(
            signing_file.open_symmetric_key(PASSWORD),
            Err(Error::Failed)
        ));
        assert!(matches!(
            symmetric_file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
        assert!(matches!(
            symmetric_file.open_signing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn every_byte_of_the_file_is_covered_by_the_tag() {
        // Exhaustive over the whole file, done at the AEAD layer so the cost is
        // one ChaCha20-Poly1305 operation per byte rather than one Argon2
        // derivation. Argon2 at 64 MiB takes long enough in a debug build that
        // 89 derivations would dominate the whole suite.
        let key = sealing();
        let payload = key.expose();
        let salt = [0x5Cu8; ARGON2_SALT_SIZE];
        let header = build_header(
            PAYLOAD_SEALING,
            payload.len(),
            &salt,
            M_COST,
            T_COST,
            P_COST,
        );

        let wrap_key = wrap_key_for(PASSWORD, &salt, M_COST, T_COST, P_COST).expect("derive");
        let aead = AeadKey::from_secret(&wrap_key).expect("aead");

        let mut baseline = payload.to_vec();
        aead.seal_extend(AeadNonce::ZERO, &header, &mut baseline)
            .expect("seal");

        let mut file = header.clone();
        file.extend_from_slice(&baseline);

        aead.open_in_place(AeadNonce::ZERO, &header, &mut baseline_clone(&baseline))
            .expect("the untampered file authenticates");

        for index in 0..file.len() {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;
            let mut body = tampered[HEADER_SIZE..].to_vec();
            assert!(
                aead.open_in_place(AeadNonce::ZERO, &tampered[..HEADER_SIZE], &mut body)
                    .is_err(),
                "byte {index} was accepted after a bit flip"
            );
        }
    }

    /// Returns a copy of the ciphertext, so a decrypt attempt cannot disturb the
    /// baseline the sweep compares against.
    fn baseline_clone(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    #[test]
    #[cfg(not(miri))]
    fn sampled_tampering_is_rejected_end_to_end() {
        // The same coverage as the sweep above, through the public entry point.
        // Sampled, because each call here runs Argon2.
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        let original = file.as_bytes().to_vec();

        for index in (0..original.len()).step_by(11) {
            let mut tampered = original.clone();
            tampered[index] ^= 0x80;
            let round = KeyFile::from_bytes(&tampered).expect("parses");
            assert!(
                round.open_sealing_key(PASSWORD).is_err(),
                "byte {index} was accepted"
            );
        }
        for index in (0..original.len()).rev().step_by(11) {
            let mut tampered = original.clone();
            tampered[index] ^= 0x80;
            let round = KeyFile::from_bytes(&tampered).expect("parses");
            assert!(
                round.open_sealing_key(PASSWORD).is_err(),
                "byte {index} was accepted"
            );
        }

        let restored = KeyFile::from_bytes(&original).expect("parses");
        assert!(restored.open_sealing_key(PASSWORD).is_ok());
    }

    #[test]
    #[cfg(not(miri))]
    fn every_truncation_is_rejected() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        let original = file.as_bytes();
        for len in 0..original.len() {
            let result =
                KeyFile::from_bytes(&original[..len]).and_then(|f| f.open_sealing_key(PASSWORD));
            assert!(result.is_err(), "truncation to {len} bytes was accepted");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn appended_bytes_are_rejected() {
        let mut file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        let mut bytes = file.as_bytes().to_vec();
        bytes.push(0);
        file = KeyFile::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_format_type_is_rejected() {
        let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
            .expect("wrap")
            .as_bytes()
            .to_vec();
        bytes[4] = 0x11;
        let file = KeyFile::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_unknown_version_is_reported_as_such() {
        let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
            .expect("wrap")
            .as_bytes()
            .to_vec();
        bytes[5] = 0x02;
        let file = KeyFile::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            file.open_sealing_key(PASSWORD),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_kdf_id_is_rejected() {
        let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
            .expect("wrap")
            .as_bytes()
            .to_vec();
        bytes[6] = 0x02;
        let file = KeyFile::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_params_id_is_rejected() {
        let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
            .expect("wrap")
            .as_bytes()
            .to_vec();
        bytes[7] = 0x02;
        let file = KeyFile::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_downgraded_memory_cost_is_rejected() {
        // The attack this stops: an attacker who can rewrite a key file weakens
        // the parameters and then guesses the password offline against a cheap
        // derivation.
        for m_cost in [0u32, 8, 1024, M_COST_FLOOR - 1] {
            let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
                .expect("wrap")
                .as_bytes()
                .to_vec();
            bytes[8..12].copy_from_slice(&m_cost.to_be_bytes());
            let file = KeyFile::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(file.open_sealing_key(PASSWORD), Err(Error::Failed)),
                "m_cost {m_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_downgraded_pass_count_is_rejected() {
        for t_cost in [0u32, 1, T_COST_FLOOR - 1] {
            let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
                .expect("wrap")
                .as_bytes()
                .to_vec();
            bytes[12..16].copy_from_slice(&t_cost.to_be_bytes());
            let file = KeyFile::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(file.open_sealing_key(PASSWORD), Err(Error::Failed)),
                "t_cost {t_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_downgraded_lane_count_is_rejected() {
        let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
            .expect("wrap")
            .as_bytes()
            .to_vec();
        bytes[16..20].copy_from_slice(&0u32.to_be_bytes());
        let file = KeyFile::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            file.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_absurd_pass_count_is_rejected_before_anything_is_allocated() {
        // `t_cost` is read from the file. Without a ceiling a file naming two
        // billion passes would tie up whoever opens it, which is a denial of
        // service delivered by the file itself.
        for t_cost in [T_COST_CEILING + 1, 1_000_000, u32::MAX / 2] {
            let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
                .expect("wrap")
                .as_bytes()
                .to_vec();
            bytes[12..16].copy_from_slice(&t_cost.to_be_bytes());
            let round = KeyFile::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open_sealing_key(PASSWORD), Err(Error::Failed)),
                "t_cost {t_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn an_absurd_lane_count_is_rejected_before_anything_is_allocated() {
        for p_cost in [P_COST_CEILING + 1, 1_000_000, u32::MAX / 2] {
            let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
                .expect("wrap")
                .as_bytes()
                .to_vec();
            bytes[16..20].copy_from_slice(&p_cost.to_be_bytes());
            let round = KeyFile::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open_sealing_key(PASSWORD), Err(Error::Failed)),
                "p_cost {p_cost} was accepted"
            );
        }
    }

    #[test]
    fn a_lane_count_larger_than_the_memory_can_serve_is_rejected() {
        // Argon2 needs at least four blocks per lane. The floors cannot produce
        // this combination, but a hostile file can, and it is checked before any
        // memory is reserved rather than surfacing as a library error.
        assert!(check_params(M_COST_FLOOR, T_COST_FLOOR, 8_192).is_err());
        assert!(check_params(8, T_COST_FLOOR, 4).is_err());
    }

    #[test]
    fn the_accepted_range_is_inclusive_at_both_ends() {
        assert!(check_params(M_COST_FLOOR, T_COST_FLOOR, P_COST_FLOOR).is_ok());
        assert!(check_params(M_COST_CEILING, T_COST_CEILING, P_COST_CEILING).is_ok());
        assert!(check_params(M_COST_FLOOR - 1, T_COST, P_COST).is_err());
        assert!(check_params(M_COST_CEILING + 1, T_COST, P_COST).is_err());
        assert!(check_params(M_COST, T_COST_FLOOR - 1, P_COST).is_err());
        assert!(check_params(M_COST, T_COST_CEILING + 1, P_COST).is_err());
        assert!(check_params(M_COST, T_COST, P_COST_FLOOR - 1).is_err());
        assert!(check_params(M_COST, T_COST, P_COST_CEILING + 1).is_err());
    }

    #[test]
    #[cfg(not(miri))]
    fn an_absurd_memory_cost_is_rejected_before_anything_is_allocated() {
        // A file claiming 256 GiB must cost nothing to reject. If the check ran
        // after the allocation this test would be what notices, by taking a very
        // long time or exhausting the machine.
        for m_cost in [M_COST_CEILING + 1, 4 * 1024 * 1024, u32::MAX / 2] {
            let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
                .expect("wrap")
                .as_bytes()
                .to_vec();
            bytes[8..12].copy_from_slice(&m_cost.to_be_bytes());
            let file = KeyFile::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(file.open_sealing_key(PASSWORD), Err(Error::Failed)),
                "m_cost {m_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_floor_and_ceiling_are_inclusive() {
        for m_cost in [M_COST_FLOOR, M_COST_CEILING] {
            let mut bytes = KeyFile::from_sealing_key(&sealing(), PASSWORD)
                .expect("wrap")
                .as_bytes()
                .to_vec();
            bytes[8..12].copy_from_slice(&m_cost.to_be_bytes());
            // The parameters no longer match the wrap, so the payload will not
            // authenticate, but the file must get past the parameter check and
            // fail on the AEAD rather than on the bound.
            let file = KeyFile::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(file.open_sealing_key(PASSWORD), Err(Error::Failed)),
                "m_cost {m_cost} should be accepted by the bounds and fail later"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn rotation_keeps_the_key_and_changes_the_file() {
        let key = sealing();
        let file = KeyFile::from_sealing_key(&key, PASSWORD).expect("wrap");
        let rotated = file.rotate(PASSWORD).expect("rotate");

        assert_ne!(
            rotated.as_bytes(),
            file.as_bytes(),
            "rotation changed nothing"
        );
        assert_ne!(
            &rotated.as_bytes()[20..36],
            &file.as_bytes()[20..36],
            "the salt is the same"
        );

        let opened = rotated.open_sealing_key(PASSWORD).expect("open");
        assert_eq!(
            opened.encapsulation_key().to_bytes(),
            key.encapsulation_key().to_bytes()
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn rotation_does_not_accept_a_wrong_password() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        assert!(matches!(file.rotate(b"wrong"), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn rotation_preserves_the_payload_type() {
        let signing_file = KeyFile::from_signing_key(&signing(), PASSWORD).expect("wrap");
        let rotated = signing_file.rotate(PASSWORD).expect("rotate");
        assert_eq!(rotated.as_bytes()[36], PAYLOAD_SIGNING);
        assert!(rotated.open_signing_key(PASSWORD).is_ok());
        assert!(matches!(
            rotated.open_sealing_key(PASSWORD),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn two_wraps_of_the_same_key_differ() {
        let key = sealing();
        let a = KeyFile::from_sealing_key(&key, PASSWORD).expect("wrap");
        let b = KeyFile::from_sealing_key(&key, PASSWORD).expect("wrap");
        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "the salt repeated between two wraps"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn the_payload_never_appears_in_the_clear() {
        let key = sealing();
        let file = KeyFile::from_sealing_key(&key, PASSWORD).expect("wrap");
        let bytes = file.as_bytes();
        for len in [4usize, 8, 16, 32] {
            assert!(
                !bytes.windows(len).any(|w| w == &key.expose()[..len]),
                "a {len} byte run of the key appears in the key file"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_password_never_appears_in_the_file() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        assert!(!file
            .as_bytes()
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD));
    }

    #[test]
    #[cfg(not(miri))]
    fn debug_is_redacted() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        assert_eq!(format!("{file:?}"), "KeyFile([REDACTED])");
    }

    #[test]
    #[cfg(not(miri))]
    fn key_ids_are_deterministic_and_distinct() {
        let a = sealing();
        let b = signing();
        let id_a = key_id_of(Some(&a.encapsulation_key().to_bytes()), None).expect("id");
        let id_b = key_id_of(Some(&b.verifying_key().to_bytes()), None).expect("id");
        let id_a2 = key_id_of(Some(&a.encapsulation_key().to_bytes()), None).expect("id");

        assert_eq!(id_a, id_a2, "the identifier is not deterministic");
        assert_ne!(id_a, id_b, "two different keys share an identifier");
        assert_eq!(id_a.len(), KEY_ID_SIZE);
    }

    #[test]
    #[cfg(not(miri))]
    fn a_key_id_is_different_for_every_key() {
        let mut seen: Vec<[u8; KEY_ID_SIZE]> = Vec::new();
        for index in 0u8..6 {
            let key = SealingKey::from_bytes([index; 32]);
            let id = key_id_of(Some(&key.encapsulation_key().to_bytes()), None).expect("id");
            assert!(!seen.contains(&id), "two sealing keys share an identifier");
            seen.push(id);
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn bytes_round_trip_through_the_type() {
        let file = KeyFile::from_sealing_key(&sealing(), PASSWORD).expect("wrap");
        let restored = KeyFile::from_bytes(file.as_bytes()).expect("parses");
        assert_eq!(restored.as_bytes(), file.as_bytes());
        assert!(restored.open_sealing_key(PASSWORD).is_ok());

        let short = vec![0u8; HEADER_SIZE + TAG_SIZE - 1];
        assert!(KeyFile::from_bytes(&short).is_err());
        assert!(KeyFile::from_bytes(&[]).is_err());
    }

    #[test]
    #[cfg(not(miri))]
    fn key_file_bytes_round_trip_through_into_bytes() {
        let file = KeyFile::from_signing_key(&signing(), PASSWORD).expect("wrap");
        let bytes = file.into_bytes();
        let restored = KeyFile::from_bytes(&bytes).expect("parses");
        assert_eq!(restored.as_bytes(), &bytes[..]);
    }
}
