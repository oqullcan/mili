//! The backup container: the `mili-backup-v1` format.
//!
//! A backup holds several keys under one password. `docs/SPEC.md` section 8 has the
//! layout.
//!
//! # Why this exists
//!
//! Losing a key is not something mili can detect: every failure returns the same
//! error. The designed answer is that a key whose only copy is one key file has
//! no recovery path, and this container is the alternative. `docs/DISCLAIMER.md` says
//! so in its operational notes, and `docs/THREAT_MODEL.md` section 6 lists the key
//! file as the asset whose loss ends every file encrypted under it.
//!
//! # What an entry holds
//!
//! An entry is key material with its type tag, not a key file. The entries region
//! is encrypted once, under a wrapping key derived from the container's password
//! and Argon2 salt, so Argon2 runs exactly once for a backup of any size.
//!
//! An earlier draft of `docs/SPEC.md` section 8 said an entry is "the bytes of the key
//! file of section 7". That cannot work, and the reason is worth recording: a
//! key file inside the container would need its own password, so restoring the
//! backup would need two passwords, and the container's would buy nothing. An
//! entry is therefore the key itself, and restoring produces a key that the
//! caller then wraps into a key file of their choosing.
//!
//! # Identifiers
//!
//! Each entry carries a 16 byte key identifier, computed as `docs/SPEC.md` section 11
//! defines. A key file has no identifier, so opening a key file is the only way
//! to find out what it holds. A backup needs one, because it holds several keys
//! at once and the caller has to be able to tell whether the backup they opened
//! is the backup they meant.

use zeroize::Zeroizing;

use crate::aead::{AeadKey, AeadNonce, TAG_SIZE};
use crate::error::Error;
use crate::format;
use crate::kdf::{self, Domain};
use crate::kem::SealingKey;
use crate::keyfile::{
    check_params, derive_kek, key_id_of, ARGON2_SALT_SIZE, KDF_ARGON2ID, KEY_ID_SIZE, PROFILE,
    PROFILE_ID,
};
use crate::secret::{SecretBytes, SymmetricKey, SYMMETRIC_KEY_SIZE};
use crate::signature::{SigningKey, SIGNING_KEY_SIZE};

/// The `format_type` byte of a backup container.
pub const FORMAT_TYPE: u8 = 0x11;

/// Offset of the `kdf_id` field.
const KDF_ID_OFFSET: usize = 6;

/// Offset of the `params_id` field.
const PARAMS_ID_OFFSET: usize = 7;

/// Offset of the `m_cost` field.
const M_COST_OFFSET: usize = 8;

/// Offset of the `t_cost` field.
const T_COST_OFFSET: usize = 12;

/// Offset of the `p_cost` field.
const P_COST_OFFSET: usize = 16;

/// Offset of the Argon2 salt.
const ARGON2_SALT_OFFSET: usize = P_COST_OFFSET + 4;

/// Offset of the `entry_count` field.
const ENTRY_COUNT_OFFSET: usize = ARGON2_SALT_OFFSET + ARGON2_SALT_SIZE;

/// Offset of the `entries_len` field.
const ENTRIES_LEN_OFFSET: usize = ENTRY_COUNT_OFFSET + 4;

/// Length of the authenticated header: everything before the entries.
pub const HEADER_SIZE: usize = ENTRIES_LEN_OFFSET + 8;

const _: () = {
    // The layout is load bearing. If any of these move, every backup written by an
    // earlier build becomes unreadable, so they are asserted at compile time.
    assert!(KDF_ID_OFFSET == 6);
    assert!(PARAMS_ID_OFFSET == 7);
    assert!(M_COST_OFFSET == 8);
    assert!(T_COST_OFFSET == 12);
    assert!(P_COST_OFFSET == 16);
    assert!(ARGON2_SALT_OFFSET == 20);
    assert!(ENTRY_COUNT_OFFSET == 36);
    assert!(ENTRIES_LEN_OFFSET == 40);
    assert!(HEADER_SIZE == 48);
};

/// Bytes an entry costs before its payload: identifier length, identifier,
/// payload length.
const ENTRY_OVERHEAD: usize = 2 + KEY_ID_SIZE + 4;

/// Bytes an entry's payload costs before its key: type tag and length.
const PAYLOAD_OVERHEAD: usize = 1 + 4;

/// The largest key a backup will store, which is the largest key mili has.
const MAX_KEY_SIZE: usize = SIGNING_KEY_SIZE;

/// A key held in a backup.
pub enum StoredKey {
    /// An X-Wing sealing key.
    Sealing(SealingKey),
    /// A composite signing key.
    Signing(SigningKey),
    /// A 256 bit symmetric key.
    Symmetric(SymmetricKey),
}

impl StoredKey {
    /// The `payload_type` byte this key is written with.
    fn payload_type(&self) -> Result<u8, Error> {
        match self {
            StoredKey::Sealing(_) => Ok(crate::keyfile::PAYLOAD_SEALING),
            StoredKey::Signing(_) => Ok(crate::keyfile::PAYLOAD_SIGNING),
            StoredKey::Symmetric(_) => Ok(crate::keyfile::PAYLOAD_SYMMETRIC),
        }
    }

    /// The identifier of this key, as `docs/SPEC.md` section 11 defines.
    pub fn key_id(&self) -> Result<[u8; KEY_ID_SIZE], Error> {
        match self {
            StoredKey::Sealing(key) => key_id_of(Some(&key.encapsulation_key().to_bytes()), None),
            StoredKey::Signing(key) => key_id_of(Some(&key.verifying_key().to_bytes()), None),
            StoredKey::Symmetric(key) => key_id_of(None, Some(key.expose())),
        }
    }
}

impl core::fmt::Debug for StoredKey {
    /// Names the variant and nothing else. A key's identifier is public, but
    /// printing it in a log line is not something a caller asked for.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoredKey::Sealing(_) => f.write_str("Sealing([REDACTED])"),
            StoredKey::Signing(_) => f.write_str("Signing([REDACTED])"),
            StoredKey::Symmetric(_) => f.write_str("Symmetric([REDACTED])"),
        }
    }
}

/// One key in a backup, with the identifier that names it.
pub struct BackupEntry {
    /// The 16 byte key identifier, as `docs/SPEC.md` section 11 defines.
    pub key_id: [u8; KEY_ID_SIZE],
    /// The key itself.
    pub key: StoredKey,
}

impl core::fmt::Debug for BackupEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BackupEntry")
            .field("key_id", &self.key_id)
            .field("key", &self.key)
            .finish()
    }
}

/// A backup container, as a byte string.
pub struct Backup(Vec<u8>);

/// What a backup container says about itself, before any password is supplied.
///
/// Everything here is read from the unauthenticated header, so it is a statement
/// about what the file claims rather than a statement about what it is. A caller
/// should use it to decide whether to prompt for a password and to report the
/// Argon2 profile it is about to run, not to make a trust decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupInfo {
    /// The Argon2id memory cost in kibibytes.
    pub m_cost: u32,
    /// The Argon2id iteration count.
    pub t_cost: u32,
    /// The Argon2id lane count.
    pub p_cost: u32,
    /// How many entries the header claims.
    pub entry_count: u32,
}

impl Backup {
    /// Reads what this container says about itself, without a password.
    ///
    /// This is the operation a tool needs before it can do anything useful: to
    /// report "this is a mili backup, N keys, Argon2id 64 MiB" and ask for a
    /// password, rather than running Argon2 at 64 MiB on a file that may not be a
    /// mili backup at all. Opening with `open` instead means paying for the
    /// derivation before knowing whether the file was worth it.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] if the file declares a format version this
    /// build does not implement, and [`Error::Failed`] if the magic, the format
    /// type, the KDF identifiers or the length arithmetic do not hold. The
    /// password is not consulted and no key material is read.
    pub fn info(&self) -> Result<BackupInfo, Error> {
        let header = Header::parse(&self.0)?;
        Ok(BackupInfo {
            m_cost: header.m_cost,
            t_cost: header.t_cost,
            p_cost: header.p_cost,
            entry_count: header.entry_count,
        })
    }
}

impl Backup {
    /// Builds a backup from keys, under one password.
    ///
    /// The password is used once: Argon2 runs a single time for the whole
    /// container, whatever the number of keys. Each key's identifier is computed
    /// here, so the caller does not have to.
    ///
    /// Two entries with the same identifier are rejected, because a backup that
    /// holds two copies of the same key is a backup whose contents the reader
    /// cannot describe.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the password is empty, if the operating system
    /// randomness source is unavailable, if the 64 MiB working allocation fails,
    /// or if two entries carry the same identifier.
    pub fn from_keys(password: &[u8], keys: Vec<StoredKey>) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::Failed);
        }

        let mut entries: Vec<u8> = Vec::new();
        let mut count: u32 = 0;
        let mut seen: Vec<[u8; KEY_ID_SIZE]> = Vec::with_capacity(keys.len());

        for key in keys {
            let key_id = key.key_id()?;
            if seen.contains(&key_id) {
                return Err(Error::Failed);
            }
            seen.push(key_id);

            let payload = encode_payload(&key)?;
            entries.extend_from_slice(&(KEY_ID_SIZE as u16).to_be_bytes());
            entries.extend_from_slice(&key_id);
            entries.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            entries.extend_from_slice(&payload);
            // The loop runs once per key in the caller's list, so this cannot
            // pass `u32::MAX` before the allocation that holds the list has.
            count = count.checked_add(1).ok_or(Error::Failed)?;
        }

        let salt = crate::rng::array::<ARGON2_SALT_SIZE>()?;
        let mut header = build_header(count, entries.len() as u64, &salt);
        let wrap_key = wrap_key_for(
            password,
            &salt,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )?;

        // Only the entries region goes into the cipher's buffer. The header is
        // the associated data and stays in the clear, so a reader can find the
        // salt and the cost parameters before it can decrypt anything.
        let aead = AeadKey::from_secret(&wrap_key)?;
        let mut region = entries;
        aead.seal_extend(AeadNonce::ZERO, &header, &mut region)?;

        header.extend_from_slice(&region);
        Ok(Self(header))
    }

    /// Opens this backup and returns its keys.
    ///
    /// The identifiers come back with the keys, so a caller can check that the
    /// backup it opened is the one it expected without opening anything twice.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedVersion`] if the version byte names a version this
    /// build does not implement. [`Error::Failed`] for a short file, a wrong
    /// magic, a wrong `format_type`, a `kdf_id` or `params_id` other than the
    /// one mili writes, cost parameters outside the accepted range, an empty
    /// password, an allocation failure, an entry region that does not parse, and
    /// a region that does not authenticate. A wrong password and a corrupted file
    /// are the same error.
    pub fn open(&self, password: &[u8]) -> Result<Vec<BackupEntry>, Error> {
        if password.is_empty() {
            return Err(Error::Failed);
        }
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

        let mut region = self.0[HEADER_SIZE..].to_vec();
        aead.open_in_place(AeadNonce::ZERO, &self.0[..HEADER_SIZE], &mut region)?;
        if region.len() != header.entries_len {
            return Err(Error::Failed);
        }

        parse_entries(&region, header.entry_count)
    }

    /// Borrows the backup bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Takes the backup bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Wraps backup bytes back into a `Backup`.
    ///
    /// # Errors
    ///
    /// [`Error::Failed`] if the bytes are too short to be a backup. The rest of
    /// the header is checked on open, where the parameters can be judged.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE + TAG_SIZE {
            return Err(Error::Failed);
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl core::fmt::Debug for Backup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Backup([REDACTED])")
    }
}

/// Encodes one key as `payload_type || payload_len || payload`.
fn encode_payload(key: &StoredKey) -> Result<Vec<u8>, Error> {
    let (payload_type, bytes) = match key {
        StoredKey::Sealing(key) => (crate::keyfile::PAYLOAD_SEALING, key.expose().as_slice()),
        StoredKey::Signing(key) => (crate::keyfile::PAYLOAD_SIGNING, key.expose().as_slice()),
        StoredKey::Symmetric(key) => (crate::keyfile::PAYLOAD_SYMMETRIC, key.expose().as_slice()),
    };
    debug_assert!(key.payload_type()? == payload_type);

    let mut out = Vec::with_capacity(PAYLOAD_OVERHEAD.saturating_add(bytes.len()));
    out.push(payload_type);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Parses the authenticated entry region.
fn parse_entries(region: &[u8], count: u32) -> Result<Vec<BackupEntry>, Error> {
    // Every entry costs at least its own length prefix, so a count that cannot
    // fit in the region is rejected before anything is allocated.
    if (count as usize).saturating_mul(ENTRY_OVERHEAD) > region.len() {
        return Err(Error::Failed);
    }

    let mut entries = Vec::with_capacity(count as usize);
    let mut seen: Vec<[u8; KEY_ID_SIZE]> = Vec::with_capacity(count as usize);
    let mut offset = 0usize;

    for _ in 0..count {
        let remaining = region.len().checked_sub(offset).ok_or(Error::Failed)?;
        if remaining < ENTRY_OVERHEAD {
            return Err(Error::Failed);
        }
        // The identifier length is written even though mili only ever writes 16,
        // so that a future version can use a different length without a format
        // change. A length other than 16 is rejected rather than skipped.
        if read_u16(region, offset)? as usize != KEY_ID_SIZE {
            return Err(Error::Failed);
        }
        let id_start = offset.checked_add(2).ok_or(Error::Failed)?;
        let id_end = id_start.checked_add(KEY_ID_SIZE).ok_or(Error::Failed)?;
        let len_end = id_end.checked_add(4).ok_or(Error::Failed)?;
        if len_end > region.len() {
            return Err(Error::Failed);
        }

        let mut key_id = [0u8; KEY_ID_SIZE];
        key_id.copy_from_slice(&region[id_start..id_end]);
        // The same rule `from_keys` enforces when writing, enforced here when
        // reading. A container written by any other implementation of this format
        // could otherwise hold two entries under one identifier, and the
        // identifier exists for exactly one purpose: to tell the entries apart
        // and to detect a wrong backup. Making the rule write-side only would
        // mean a caller got two entries back under one id and no signal.
        if seen.contains(&key_id) {
            return Err(Error::Failed);
        }
        seen.push(key_id);
        let entry_len = read_u32(region, id_end)? as usize;

        let payload_start = offset.checked_add(ENTRY_OVERHEAD).ok_or(Error::Failed)?;
        let available = region
            .len()
            .checked_sub(payload_start)
            .ok_or(Error::Failed)?;
        if entry_len > available {
            return Err(Error::Failed);
        }
        let payload_end = payload_start.checked_add(entry_len).ok_or(Error::Failed)?;
        let key = decode_payload(&region[payload_start..payload_end])?;
        entries.push(BackupEntry { key_id, key });
        offset = payload_end;
    }

    if offset != region.len() {
        return Err(Error::Failed);
    }
    Ok(entries)
}

/// Decodes one entry payload.
fn decode_payload(payload: &[u8]) -> Result<StoredKey, Error> {
    if payload.len() < PAYLOAD_OVERHEAD {
        return Err(Error::Failed);
    }
    let payload_type = payload[0];
    let available = payload
        .len()
        .checked_sub(PAYLOAD_OVERHEAD)
        .ok_or(Error::Failed)?;
    let payload_len = read_u32(payload, 1)? as usize;
    if payload_len != available || payload_len > MAX_KEY_SIZE {
        return Err(Error::Failed);
    }

    let body = payload.get(PAYLOAD_OVERHEAD..).ok_or(Error::Failed)?;
    let mut key_bytes = Zeroizing::new([0u8; MAX_KEY_SIZE]);
    let target = key_bytes.get_mut(..payload_len).ok_or(Error::Failed)?;
    target.copy_from_slice(body);

    match payload_type {
        crate::keyfile::PAYLOAD_SEALING => {
            if payload_len != crate::SEALING_KEY_SIZE {
                return Err(Error::Failed);
            }
            let mut seed = [0u8; crate::SEALING_KEY_SIZE];
            seed.copy_from_slice(&key_bytes[..crate::SEALING_KEY_SIZE]);
            Ok(StoredKey::Sealing(SealingKey::from_bytes(seed)))
        }
        crate::keyfile::PAYLOAD_SIGNING => {
            if payload_len != SIGNING_KEY_SIZE {
                return Err(Error::Failed);
            }
            let mut seed = [0u8; SIGNING_KEY_SIZE];
            seed.copy_from_slice(&key_bytes[..SIGNING_KEY_SIZE]);
            Ok(StoredKey::Signing(SigningKey::from_bytes(seed)))
        }
        crate::keyfile::PAYLOAD_SYMMETRIC => {
            if payload_len != SYMMETRIC_KEY_SIZE {
                return Err(Error::Failed);
            }
            let mut seed = [0u8; SYMMETRIC_KEY_SIZE];
            seed.copy_from_slice(&key_bytes[..SYMMETRIC_KEY_SIZE]);
            Ok(StoredKey::Symmetric(SymmetricKey::from_bytes(seed)))
        }
        _ => Err(Error::Failed),
    }
}

/// Builds the 48 byte header of a backup.
fn build_header(entry_count: u32, entries_len: u64, salt: &[u8; ARGON2_SALT_SIZE]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_SIZE);
    format::write_fields(&mut header, FORMAT_TYPE);
    header.push(KDF_ARGON2ID);
    header.push(PROFILE_ID);
    header.extend_from_slice(&PROFILE.m_cost.to_be_bytes());
    header.extend_from_slice(&PROFILE.t_cost.to_be_bytes());
    header.extend_from_slice(&PROFILE.p_cost.to_be_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(&entry_count.to_be_bytes());
    header.extend_from_slice(&entries_len.to_be_bytes());
    debug_assert_eq!(header.len(), HEADER_SIZE);
    header
}

/// The parsed, still unauthenticated header of a backup.
struct Header {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; ARGON2_SALT_SIZE],
    entry_count: u32,
    entries_len: usize,
}

impl Header {
    /// Parses and length checks a backup header.
    fn parse(file: &[u8]) -> Result<Self, Error> {
        format::parse_fields(file, FORMAT_TYPE, HEADER_SIZE + TAG_SIZE)?;

        if file[KDF_ID_OFFSET] != KDF_ARGON2ID || file[PARAMS_ID_OFFSET] != PROFILE_ID {
            return Err(Error::Failed);
        }

        let mut salt = [0u8; ARGON2_SALT_SIZE];
        salt.copy_from_slice(&file[ARGON2_SALT_OFFSET..ENTRY_COUNT_OFFSET]);

        let m_cost = read_u32(file, M_COST_OFFSET)?;
        let t_cost = read_u32(file, T_COST_OFFSET)?;
        let p_cost = read_u32(file, P_COST_OFFSET)?;
        let entry_count = read_u32(file, ENTRY_COUNT_OFFSET)?;
        let entries_len = read_u64(file, ENTRIES_LEN_OFFSET)?;

        // A u64 length that does not fit in a usize is rejected rather than
        // truncated, so a file cannot be made to look a different length on a
        // 32 bit target than it does here.
        let entries_len = usize::try_from(entries_len).map_err(|_| Error::Failed)?;
        match format::exact_length(HEADER_SIZE, entries_len, TAG_SIZE) {
            Some(expected) if expected == file.len() => {}
            _ => return Err(Error::Failed),
        }

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
            salt,
            entry_count,
            entries_len,
        })
    }
}

/// Reads a big endian `u16` at `offset`.
///
/// Returns an error rather than a number when the range is out of the buffer.
/// Every call site has already length checked the whole file, so this cannot
/// fire, but saying so with a fallible read costs nothing and removes the
/// unchecked index arithmetic that a caller could otherwise move.
fn read_u16(file: &[u8], offset: usize) -> Result<u16, Error> {
    let end = offset.checked_add(2).ok_or(Error::Failed)?;
    let bytes: [u8; 2] = file
        .get(offset..end)
        .ok_or(Error::Failed)?
        .try_into()
        .map_err(|_| Error::Failed)?;
    Ok(u16::from_be_bytes(bytes))
}

/// Reads a big endian `u32` at `offset`. See [`read_u16`].
fn read_u32(file: &[u8], offset: usize) -> Result<u32, Error> {
    let end = offset.checked_add(4).ok_or(Error::Failed)?;
    let bytes: [u8; 4] = file
        .get(offset..end)
        .ok_or(Error::Failed)?
        .try_into()
        .map_err(|_| Error::Failed)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Reads a big endian `u64` at `offset`. See [`read_u16`].
fn read_u64(file: &[u8], offset: usize) -> Result<u64, Error> {
    let end = offset.checked_add(8).ok_or(Error::Failed)?;
    let bytes: [u8; 8] = file
        .get(offset..end)
        .ok_or(Error::Failed)?
        .try_into()
        .map_err(|_| Error::Failed)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Derives the AEAD wrapping key for a backup.
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

const _: () = {
    // The offsets above are load bearing; this keeps them from drifting.
    assert!(ENTRY_COUNT_OFFSET == 36);
    assert!(ENTRIES_LEN_OFFSET == 40);
    assert!(HEADER_SIZE == 48);
};

#[cfg(test)]
mod tests {
    // Most of the tests in this module are excluded under miri, which leaves their
    // imports and helpers unreferenced. The ones that still run are the parsing and
    // layout checks, which do not derive a key.
    #![cfg_attr(miri, allow(unused))]
    use super::{
        build_header, check_params, encode_payload, parse_entries, wrap_key_for, AeadKey,
        AeadNonce, Header,
    };
    use super::{
        read_u32, read_u64, Backup, BackupEntry, StoredKey, ARGON2_SALT_OFFSET, ENTRIES_LEN_OFFSET,
        ENTRY_COUNT_OFFSET, ENTRY_OVERHEAD, FORMAT_TYPE, HEADER_SIZE, KDF_ARGON2ID, KDF_ID_OFFSET,
        MAX_KEY_SIZE, M_COST_OFFSET, PARAMS_ID_OFFSET, PAYLOAD_OVERHEAD, PROFILE_ID, P_COST_OFFSET,
        T_COST_OFFSET,
    };
    use crate::aead::TAG_SIZE;
    use crate::keyfile::{ARGON2_SALT_SIZE, KEY_ID_SIZE, PROFILE, P_COST_CEILING, T_COST_CEILING};
    use crate::signature::SIGNING_KEY_SIZE;
    use crate::SYMMETRIC_KEY_SIZE;
    use crate::{Error, SealingKey, SigningKey, SymmetricKey};

    // Argon2 at 64 MiB is too slow and too allocation heavy to interpret under
    // miri, so the tests that derive a key are excluded there. The tests that
    // only exercise parsing and layout still run.
    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn sealing(seed: u8) -> SealingKey {
        SealingKey::from_bytes([seed; 32])
    }

    fn signing() -> SigningKey {
        let mut bytes = [0u8; 64];
        for (position, byte) in bytes.iter_mut().enumerate() {
            *byte = if position < 32 { 0x77 } else { 0x88 };
        }
        SigningKey::from_bytes(bytes)
    }

    fn ids(entries: &[BackupEntry]) -> Vec<[u8; KEY_ID_SIZE]> {
        entries.iter().map(|entry| entry.key_id).collect()
    }

    #[test]
    fn documented_offsets() {
        assert_eq!(FORMAT_TYPE, 0x11);
        assert_eq!(KDF_ID_OFFSET, 6);
        assert_eq!(PARAMS_ID_OFFSET, 7);
        assert_eq!(M_COST_OFFSET, 8);
        assert_eq!(T_COST_OFFSET, 12);
        assert_eq!(P_COST_OFFSET, 16);
        assert_eq!(ARGON2_SALT_OFFSET, 20);
        assert_eq!(ENTRY_COUNT_OFFSET, 36);
        assert_eq!(ENTRIES_LEN_OFFSET, 40);
        assert_eq!(HEADER_SIZE, 48);
        assert_eq!(ENTRY_OVERHEAD, 22);
        assert_eq!(PAYLOAD_OVERHEAD, 5);
        assert_eq!(MAX_KEY_SIZE, SIGNING_KEY_SIZE);
    }

    #[test]
    #[cfg(not(miri))]
    fn round_trip_of_every_key_type() {
        let keys = vec![
            StoredKey::Sealing(sealing(0x31)),
            StoredKey::Signing(signing()),
            StoredKey::Symmetric(SymmetricKey::from_bytes([0x9Eu8; 32])),
        ];
        let backup = Backup::from_keys(PASSWORD, keys).expect("build");
        let opened = backup.open(PASSWORD).expect("open");

        assert_eq!(opened.len(), 3);

        match &opened[0].key {
            StoredKey::Sealing(key) => assert_eq!(
                key.encapsulation_key().to_bytes(),
                sealing(0x31).encapsulation_key().to_bytes()
            ),
            other => panic!("wrong type: {other:?}"),
        }
        match &opened[1].key {
            StoredKey::Signing(key) => assert_eq!(
                key.verifying_key().to_bytes(),
                signing().verifying_key().to_bytes()
            ),
            other => panic!("wrong type: {other:?}"),
        }
        match &opened[2].key {
            StoredKey::Symmetric(key) => assert_eq!(*key, SymmetricKey::from_bytes([0x9Eu8; 32])),
            other => panic!("wrong type: {other:?}"),
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_header_is_where_the_specification_says() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        let bytes = backup.as_bytes();

        assert_eq!(&bytes[0..4], b"mili");
        assert_eq!(bytes[4], 0x11);
        assert_eq!(bytes[5], 0x01);
        assert_eq!(bytes[6], KDF_ARGON2ID, "kdf_id must be Argon2id");
        assert_eq!(bytes[7], PROFILE_ID, "params_id must be the fixed profile");
        assert_eq!(&bytes[8..12], &PROFILE.m_cost.to_be_bytes());
        assert_eq!(&bytes[12..16], &PROFILE.t_cost.to_be_bytes());
        assert_eq!(&bytes[16..20], &PROFILE.p_cost.to_be_bytes());
        assert_eq!(read_u32(bytes, 36).expect("in range"), 1, "one entry");
    }

    #[test]
    #[cfg(not(miri))]
    fn an_empty_backup_round_trips() {
        let backup = Backup::from_keys(PASSWORD, Vec::new()).expect("build");
        assert_eq!(backup.as_bytes().len(), HEADER_SIZE + TAG_SIZE);
        assert!(backup.open(PASSWORD).expect("open").is_empty());
    }

    /// `info` answers "is this a mili backup and what will opening it cost"
    /// without running Argon2.
    ///
    /// It exists because the README promised a backup container could be
    /// inspected and no such operation did. The alternative for a tool was to run
    /// a 64 MiB Argon2 derivation on a file that might not be a mili backup at
    /// all, or to hand-parse the header itself.
    #[test]
    #[cfg(not(miri))]
    fn info_reads_the_header_without_a_password() {
        let keys = vec![
            StoredKey::Sealing(sealing(0x31)),
            StoredKey::Symmetric(SymmetricKey::from_bytes([0x77u8; SYMMETRIC_KEY_SIZE])),
        ];
        let backup = Backup::from_keys(PASSWORD, keys).expect("build");

        let info = backup.info().expect("info");
        assert_eq!(info.entry_count, 2);
        assert_eq!(info.m_cost, 64 * 1024);
        assert_eq!(info.t_cost, 3);
        assert_eq!(info.p_cost, 4);
    }

    #[test]
    #[cfg(not(miri))]
    fn info_of_something_that_is_not_a_backup_is_refused() {
        // A wrong password is irrelevant here: `info` never consults one.
        let backup = Backup::from_keys(PASSWORD, Vec::new()).expect("build");
        assert!(backup.info().is_ok());

        assert!(matches!(
            Backup::from_bytes(b"not a backup at all"),
            Err(Error::Failed)
        ));
        assert!(matches!(Backup::from_bytes(&[]), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn entry_count_and_length_are_written() {
        let keys: Vec<StoredKey> = (0..3u8).map(|i| StoredKey::Sealing(sealing(i))).collect();
        let backup = Backup::from_keys(PASSWORD, keys).expect("build");
        let bytes = backup.as_bytes();

        assert_eq!(read_u32(bytes, 36).expect("in range"), 3);
        let entries_len = read_u64(bytes, 40).expect("in range") as usize;
        assert_eq!(bytes.len(), HEADER_SIZE + entries_len + TAG_SIZE);
        // Each entry is a 2 byte identifier length, a 16 byte identifier, a 4 byte
        // payload length, then a 1 byte type, a 4 byte length and a 32 byte key.
        assert_eq!(entries_len, 3 * (ENTRY_OVERHEAD + PAYLOAD_OVERHEAD + 32));
    }

    #[test]
    #[cfg(not(miri))]
    fn the_identifiers_come_back_with_the_keys() {
        let backup = Backup::from_keys(
            PASSWORD,
            vec![
                StoredKey::Sealing(sealing(0x31)),
                StoredKey::Signing(signing()),
                StoredKey::Symmetric(SymmetricKey::from_bytes([0x9Eu8; 32])),
            ],
        )
        .expect("build");

        let opened = backup.open(PASSWORD).expect("open");
        assert_eq!(
            ids(&opened),
            vec![
                StoredKey::Sealing(sealing(0x31)).key_id().expect("id"),
                StoredKey::Signing(signing()).key_id().expect("id"),
                StoredKey::Symmetric(SymmetricKey::from_bytes([0x9Eu8; 32]))
                    .key_id()
                    .expect("id"),
            ]
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn a_duplicate_identifier_is_rejected() {
        let result = Backup::from_keys(
            PASSWORD,
            vec![
                StoredKey::Sealing(sealing(0x31)),
                StoredKey::Sealing(sealing(0x31)),
            ],
        );
        assert!(matches!(result, Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_wrong_password_is_rejected() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        assert!(matches!(
            backup.open(b"not the password"),
            Err(Error::Failed)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_empty_password_is_rejected_on_both_sides() {
        assert!(matches!(
            Backup::from_keys(b"", vec![StoredKey::Sealing(sealing(0x31))]),
            Err(Error::Failed)
        ));
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        assert!(matches!(backup.open(b""), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn every_byte_of_the_file_is_refused() {
        // Exhaustive over the whole file at the parse and AEAD layers, so the
        // cost is one ChaCha20-Poly1305 operation per byte instead of one Argon2
        // derivation. A 182 byte backup would otherwise spend two minutes in
        // Argon2 and slow the whole suite down.
        let keys = [
            StoredKey::Sealing(sealing(0x31)),
            StoredKey::Symmetric(SymmetricKey::from_bytes([0x9Eu8; 32])),
        ];

        let mut region = Vec::new();
        for key in &keys {
            let payload = encode_payload(key).expect("encode");
            region.extend_from_slice(&(KEY_ID_SIZE as u16).to_be_bytes());
            region.extend_from_slice(&key.key_id().expect("id"));
            region.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            region.extend_from_slice(&payload);
        }

        let salt = [0x5Cu8; ARGON2_SALT_SIZE];
        let header = build_header(keys.len() as u32, region.len() as u64, &salt);

        let wrap_key = wrap_key_for(
            PASSWORD,
            &salt,
            PROFILE.m_cost,
            PROFILE.t_cost,
            PROFILE.p_cost,
        )
        .expect("derive");
        let aead = AeadKey::from_secret(&wrap_key).expect("aead");

        let region_len = region.len();
        let mut sealed = region;
        aead.seal_extend(AeadNonce::ZERO, &header, &mut sealed)
            .expect("seal");

        let mut file = header;
        file.extend_from_slice(&sealed);
        assert_eq!(file.len(), HEADER_SIZE + region_len + TAG_SIZE);

        // Sanity: the untampered file parses and authenticates.
        let parsed = Header::parse(&file).expect("parses");
        assert_eq!(parsed.entry_count, 2);
        let mut pristine = file[HEADER_SIZE..].to_vec();
        aead.open_in_place(AeadNonce::ZERO, &file[..HEADER_SIZE], &mut pristine)
            .expect("authenticates");
        assert_eq!(parse_entries(&pristine, 2).expect("parses").len(), 2);

        for index in 0..file.len() {
            let mut tampered = file.clone();
            tampered[index] ^= 0x01;

            let refused = match Header::parse(&tampered) {
                Err(_) => true,
                Ok(parsed) => {
                    check_params(parsed.m_cost, parsed.t_cost, parsed.p_cost).is_err() || {
                        let mut body = tampered[HEADER_SIZE..].to_vec();
                        aead.open_in_place(AeadNonce::ZERO, &tampered[..HEADER_SIZE], &mut body)
                            .is_err()
                    }
                }
            };
            assert!(refused, "byte {index} was accepted after a bit flip");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn sampled_tampering_is_rejected_end_to_end() {
        // The same coverage as the sweep above, through the public entry point.
        // Sampled, because every call here runs Argon2 at 64 MiB.
        let backup = Backup::from_keys(
            PASSWORD,
            vec![
                StoredKey::Sealing(sealing(0x31)),
                StoredKey::Symmetric(SymmetricKey::from_bytes([0x9Eu8; 32])),
            ],
        )
        .expect("build");
        let original = backup.as_bytes().to_vec();

        for index in (0..original.len()).step_by(13) {
            let mut tampered = original.clone();
            tampered[index] ^= 0x80;
            let round = Backup::from_bytes(&tampered).expect("parses");
            assert!(round.open(PASSWORD).is_err(), "byte {index} was accepted");
        }
        for index in (0..original.len()).rev().step_by(13) {
            let mut tampered = original.clone();
            tampered[index] ^= 0x80;
            let round = Backup::from_bytes(&tampered).expect("parses");
            assert!(round.open(PASSWORD).is_err(), "byte {index} was accepted");
        }

        let restored = Backup::from_bytes(&original).expect("parses");
        assert_eq!(restored.open(PASSWORD).expect("open").len(), 2);
    }

    #[test]
    #[cfg(not(miri))]
    fn every_truncation_is_rejected() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        let original = backup.as_bytes();
        for len in 0..original.len() {
            let result = Backup::from_bytes(&original[..len]).and_then(|b| b.open(PASSWORD));
            assert!(result.is_err(), "truncation to {len} bytes was accepted");
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn appended_bytes_are_rejected() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        let mut bytes = backup.as_bytes().to_vec();
        bytes.push(0);
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_format_type_is_rejected() {
        let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("build")
            .as_bytes()
            .to_vec();
        bytes[4] = 0x10;
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_unknown_version_is_reported_as_such() {
        let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("build")
            .as_bytes()
            .to_vec();
        bytes[5] = 0x02;
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            round.open(PASSWORD),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_downgraded_memory_cost_is_rejected() {
        for m_cost in [0u32, 1024, 32_767] {
            let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
                .expect("build")
                .as_bytes()
                .to_vec();
            bytes[8..12].copy_from_slice(&m_cost.to_be_bytes());
            let round = Backup::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open(PASSWORD), Err(Error::Failed)),
                "m_cost {m_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn a_downgraded_pass_count_is_rejected() {
        let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("build")
            .as_bytes()
            .to_vec();
        bytes[12..16].copy_from_slice(&1u32.to_be_bytes());
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_absurd_memory_cost_is_rejected_before_anything_is_allocated() {
        // Each of these would ask for gigabytes if it were not for the ceiling
        // check, which runs before the working memory is reserved.
        for m_cost in [1_048_577u32, 4 * 1024 * 1024, u32::MAX / 2] {
            let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
                .expect("build")
                .as_bytes()
                .to_vec();
            bytes[8..12].copy_from_slice(&m_cost.to_be_bytes());
            let round = Backup::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open(PASSWORD), Err(Error::Failed)),
                "m_cost {m_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn an_absurd_pass_count_is_rejected_before_anything_is_allocated() {
        for t_cost in [T_COST_CEILING + 1, 1_000_000, u32::MAX / 2] {
            let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
                .expect("build")
                .as_bytes()
                .to_vec();
            bytes[12..16].copy_from_slice(&t_cost.to_be_bytes());
            let round = Backup::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open(PASSWORD), Err(Error::Failed)),
                "t_cost {t_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn an_absurd_lane_count_is_rejected_before_anything_is_allocated() {
        for p_cost in [P_COST_CEILING + 1, 1_000_000, u32::MAX / 2] {
            let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
                .expect("build")
                .as_bytes()
                .to_vec();
            bytes[16..20].copy_from_slice(&p_cost.to_be_bytes());
            let round = Backup::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open(PASSWORD), Err(Error::Failed)),
                "p_cost {p_cost} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn an_inflated_entry_count_is_rejected() {
        let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("build")
            .as_bytes()
            .to_vec();
        bytes[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn an_inflated_entries_length_is_rejected() {
        let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("build")
            .as_bytes()
            .to_vec();
        bytes[40..48].copy_from_slice(&(u64::MAX / 2).to_be_bytes());
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    #[cfg(not(miri))]
    fn a_foreign_kdf_or_parameter_profile_is_rejected() {
        for (index, value) in [(6u8, 0x02u8), (7, 0x02)] {
            let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
                .expect("build")
                .as_bytes()
                .to_vec();
            bytes[index as usize] = value;
            let round = Backup::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open(PASSWORD), Err(Error::Failed)),
                "byte {index} set to {value} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_keys_never_appear_in_the_clear() {
        let key = sealing(0x31);
        let exposed = *key.expose();
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        let bytes = backup.as_bytes();
        for len in [4usize, 8, 16, 32] {
            assert!(
                !bytes.windows(len).any(|w| w == &exposed[..len]),
                "a {len} byte run of the key appears in the backup"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn the_password_never_appears_in_the_backup() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        assert!(!backup
            .as_bytes()
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD));
    }

    #[test]
    #[cfg(not(miri))]
    fn two_backups_of_the_same_keys_differ() {
        let one =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        let two =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        assert_ne!(
            one.as_bytes(),
            two.as_bytes(),
            "the salt repeated between two backups"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn debug_is_redacted() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        assert_eq!(format!("{backup:?}"), "Backup([REDACTED])");

        let entry = BackupEntry {
            key_id: [0u8; KEY_ID_SIZE],
            key: StoredKey::Sealing(sealing(0x31)),
        };
        let rendered = format!("{entry:?}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        // The identifier is public, so it may appear.
        assert!(rendered.contains("key_id"), "{rendered}");

        assert_eq!(
            format!(
                "{:?}",
                StoredKey::Symmetric(SymmetricKey::from_bytes([0u8; 32]))
            ),
            "Symmetric([REDACTED])"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn bytes_round_trip_through_the_type() {
        let backup =
            Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))]).expect("build");
        let restored = Backup::from_bytes(backup.as_bytes()).expect("parses");
        assert_eq!(restored.as_bytes(), backup.as_bytes());
        assert_eq!(restored.open(PASSWORD).expect("open").len(), 1);

        let moved = backup.into_bytes();
        assert_eq!(
            Backup::from_bytes(&moved).expect("parses").as_bytes(),
            &moved[..]
        );

        assert!(Backup::from_bytes(&[]).is_err());
        assert!(Backup::from_bytes(&[0u8; HEADER_SIZE + TAG_SIZE - 1]).is_err());
    }

    #[test]
    fn a_short_buffer_is_rejected_without_panicking() {
        for len in 0..HEADER_SIZE + TAG_SIZE {
            assert!(
                Backup::from_bytes(&vec![0u8; len]).is_err(),
                "len {len} accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn an_entries_length_that_overflows_is_rejected() {
        // Found by the `open_backup` fuzz target. `HEADER_SIZE + entries_len +
        // TAG_SIZE` overflowed for a length near `usize::MAX`, and on a release
        // build without overflow checks the sum wrapped to a value small enough
        // to compare equal to a real file length.
        for entries_len in [u64::MAX, u64::MAX - 10, 1 << 63, usize::MAX as u64 - 64] {
            let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
                .expect("build")
                .as_bytes()
                .to_vec();
            bytes[40..48].copy_from_slice(&entries_len.to_be_bytes());
            let round = Backup::from_bytes(&bytes).expect("parses");
            assert!(
                matches!(round.open(PASSWORD), Err(Error::Failed)),
                "entries_len {entries_len} was accepted"
            );
        }
    }

    #[test]
    #[cfg(not(miri))]
    fn an_entries_length_that_cannot_fit_a_usize_is_rejected() {
        // A 32 bit target reads this same field as a different number. A file
        // that is a valid backup on one target must be the same verdict on the
        // other, so a length that does not fit is refused rather than truncated.
        let mut bytes = Backup::from_keys(PASSWORD, vec![StoredKey::Sealing(sealing(0x31))])
            .expect("build")
            .as_bytes()
            .to_vec();
        bytes[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    fn a_wrong_magic_is_rejected_before_argon2() {
        let mut bytes = vec![0u8; HEADER_SIZE + TAG_SIZE];
        bytes[0] = b'x';
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(round.open(PASSWORD), Err(Error::Failed)));
    }

    #[test]
    fn an_unknown_version_is_reported_before_argon2() {
        let mut bytes = vec![0u8; HEADER_SIZE + TAG_SIZE];
        bytes[..6].copy_from_slice(b"mili\x11\x02");
        let round = Backup::from_bytes(&bytes).expect("parses");
        assert!(matches!(
            round.open(PASSWORD),
            Err(Error::UnsupportedVersion)
        ));
    }
}
