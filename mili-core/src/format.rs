//! The bytes every mili file starts with.
//!
//! Magic, format type and version. Three formats share them, the sealed box of
//! `crate::seal`, the stream of `crate::stream` and the key file of
//! `crate::keyfile`, and checking them in one place is what keeps the three from
//! drifting apart, which would mean a file that one of them accepts and another
//! misreads.
//!
//! # The salt is not part of this
//!
//! The sealed box and the stream carry a 32 byte salt at [`SALT_OFFSET`], because
//! their payload key is derived from it. The key file does not: it carries an
//! Argon2 salt at a different offset, and that salt serves the same purpose.
//! Forcing a second unused salt into the key file would cost 32 bytes and buy
//! nothing, so the common prefix stops at the version byte and each format
//! parses its own fields after it. [`parse_with_salt`] is the sealed box and
//! stream form; [`parse_fields`] is the key file form.
//!
//! `SPEC.md` section 2 is normative for the first six bytes.

use crate::Error;

/// The magic every mili file starts with.
pub const MAGIC: [u8; 4] = *b"mili";

/// The `version` byte of every mili-v1 file.
pub const VERSION: u8 = 0x01;

/// Offset of the first byte after magic, format type and version.
pub(crate) const FIELDS_OFFSET: usize = 6;

/// Offset of the `salt` field in the formats that have one.
pub(crate) const SALT_OFFSET: usize = FIELDS_OFFSET;

/// Length of the `salt` field in the formats that have one.
pub(crate) const SALT_SIZE: usize = 32;

/// Offset one past the end of that `salt` field.
pub(crate) const SALT_END: usize = SALT_OFFSET + SALT_SIZE;

/// Parses and length checks the first six bytes of a file.
///
/// `minimum_length` is the smallest total length this format can have. `body` is
/// everything after the version byte.
///
/// Nothing here is a security check. The three bytes are public, and
/// authentication happens in the AEAD step that follows. This function only
/// decides whether the buffer is shaped like this format at all.
pub(crate) fn parse_fields(
    file: &[u8],
    format_type: u8,
    minimum_length: usize,
) -> Result<&[u8], Error> {
    if file.len() < minimum_length {
        return Err(Error::Failed);
    }
    if file[..4] != MAGIC {
        return Err(Error::Failed);
    }
    if file[4] != format_type {
        return Err(Error::Failed);
    }
    if file[5] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    Ok(&file[FIELDS_OFFSET..])
}

/// Parses a file that carries a 32 byte salt at [`SALT_OFFSET`].
///
/// `body` is everything after the salt.
pub(crate) fn parse_with_salt<'a>(
    file: &'a [u8],
    format_type: u8,
    minimum_length: usize,
) -> Result<Prefix<'a>, Error> {
    if file.len() < minimum_length {
        return Err(Error::Failed);
    }
    let body = parse_fields(file, format_type, minimum_length)?;
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&file[SALT_OFFSET..SALT_END]);
    Ok(Prefix {
        salt,
        body: &body[SALT_SIZE..],
    })
}

/// Appends magic, format type and version to `out`.
pub(crate) fn write_fields(out: &mut Vec<u8>, format_type: u8) {
    out.extend_from_slice(&MAGIC);
    out.push(format_type);
    out.push(VERSION);
}

/// The common prefix plus salt of a file that has one.
pub(crate) struct Prefix<'a> {
    /// The 32 byte per-file salt.
    pub(crate) salt: [u8; SALT_SIZE],
    /// Everything after the salt, which is format specific.
    pub(crate) body: &'a [u8],
}

#[cfg(test)]
mod tests {
    use super::{
        parse_fields, parse_with_salt, write_fields, FIELDS_OFFSET, MAGIC, SALT_END, SALT_OFFSET,
        SALT_SIZE, VERSION,
    };
    use crate::Error;

    const SEALED_BOX: u8 = 0x01;

    fn file(format_type: u8, version: u8, salt: &[u8; SALT_SIZE], extra: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_fields(&mut out, format_type);
        out[5] = version;
        out.extend_from_slice(salt);
        out.extend_from_slice(extra);
        out
    }

    #[test]
    fn documented_offsets() {
        assert_eq!(MAGIC, [0x6D, 0x69, 0x6C, 0x69]);
        assert_eq!(VERSION, 0x01);
        assert_eq!(FIELDS_OFFSET, 6);
        assert_eq!(SALT_OFFSET, 6);
        assert_eq!(SALT_SIZE, 32);
        assert_eq!(SALT_END, 38);
    }

    #[test]
    fn a_well_formed_file_parses() {
        let buffer = file(SEALED_BOX, VERSION, &[7u8; SALT_SIZE], &[1, 2, 3]);
        let parsed = parse_with_salt(&buffer, SEALED_BOX, SALT_END + 3).expect("parses");
        assert_eq!(parsed.salt, [7u8; SALT_SIZE]);
        assert_eq!(parsed.body, &[1, 2, 3]);
    }

    #[test]
    fn parse_fields_stops_at_the_version_byte() {
        let buffer = file(SEALED_BOX, VERSION, &[7u8; SALT_SIZE], &[9, 9]);
        let body = parse_fields(&buffer, SEALED_BOX, FIELDS_OFFSET + 1).expect("parses");
        assert_eq!(body.len(), buffer.len() - FIELDS_OFFSET);
        assert_eq!(&body[..SALT_SIZE], &[7u8; SALT_SIZE]);
    }

    #[test]
    fn a_short_buffer_is_rejected() {
        let buffer = file(SEALED_BOX, VERSION, &[7u8; SALT_SIZE], &[1, 2, 3]);
        for len in 0..SALT_END + 3 {
            assert!(parse_with_salt(&buffer[..len], SEALED_BOX, SALT_END + 3).is_err());
            assert!(parse_fields(&buffer[..len], SEALED_BOX, SALT_END + 3).is_err());
        }
    }

    #[test]
    fn a_bad_magic_is_rejected() {
        let mut buffer = file(SEALED_BOX, VERSION, &[7u8; SALT_SIZE], &[1, 2, 3]);
        buffer[0] ^= 0xFF;
        assert!(matches!(
            parse_with_salt(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn a_foreign_format_type_is_rejected() {
        let buffer = file(0x02, VERSION, &[7u8; SALT_SIZE], &[1, 2, 3]);
        assert!(matches!(
            parse_with_salt(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::Failed)
        ));
    }

    #[test]
    fn an_unknown_version_is_reported_as_such() {
        let buffer = file(SEALED_BOX, 0x02, &[7u8; SALT_SIZE], &[1, 2, 3]);
        assert!(matches!(
            parse_with_salt(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::UnsupportedVersion)
        ));
        assert!(matches!(
            parse_fields(&buffer, SEALED_BOX, SALT_END + 3),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn the_writer_and_the_parser_agree() {
        let mut out = Vec::new();
        write_fields(&mut out, SEALED_BOX);
        out.extend_from_slice(&[0xABu8; SALT_SIZE]);
        out.extend_from_slice(b"body");

        let parsed = parse_with_salt(&out, SEALED_BOX, SALT_END + 4).expect("parses");
        assert_eq!(parsed.salt, [0xABu8; SALT_SIZE]);
        assert_eq!(parsed.body, b"body");
    }
}
