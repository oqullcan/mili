//! The single error type returned by every fallible mili operation.
//!
//! The design rule is that an error must not tell an adversary which check
//! failed. Parsing failures, authentication failures, wrong keys, wrong
//! passwords and truncated files all produce [`Error::Failed`], whose `Display`
//! is the fixed string `mili: operation failed` and whose
//! [`std::error::Error::source`] is `None`.
//!
//! Two variants exist because their distinctions are not security oracles.
//! [`Error::UnsupportedVersion`] describes a public field that the caller can
//! already read, and [`Error::Io`] describes the caller's own input stream.
//! [`Error::Internal`] means an invariant inside mili was violated, which no
//! caller input should be able to cause; it carries no detail either.
//!
//! Adding a variant that separates cryptographic failure modes is a change to
//! the security properties of this crate, not an ordinary API change.

use core::fmt;
use std::io;

/// A failure of a mili operation.
#[derive(Debug)]
pub enum Error {
    /// A parse, key agreement or authentication check did not succeed.
    ///
    /// This variant covers every way cryptographic input can be rejected and
    /// carries no information about which one occurred. Its `Display` is the
    /// fixed string `mili: operation failed` and it has no source error.
    Failed,

    /// The `version` byte of a file names a format version this build does not
    /// implement.
    ///
    /// The version byte is in cleartext in every mili format, so naming the
    /// version of a file leaks nothing an observer cannot already read.
    UnsupportedVersion,

    /// An underlying reader or writer failed.
    ///
    /// The wrapped error is the one produced by the [`std::io`] caller. mili
    /// constructs `io::Error` values only from static strings that contain no
    /// key material and no plaintext, so this variant carries no crypto
    /// information even when a foreign `io::Error` is wrapped.
    Io(io::Error),

    /// An invariant inside mili was violated.
    ///
    /// No caller-supplied input should be able to produce this. It carries no
    /// detail, because the detail would describe mili's own internal state.
    Internal,
}

impl Error {
    /// The fixed message used for every cryptographic failure.
    const FAILED_MESSAGE: &'static str = "mili: operation failed";

    /// Reports whether this error is the uniform cryptographic failure.
    ///
    /// This exists so that callers can branch on the distinction without
    /// needing a pattern match, and so that tests can assert the property. It
    /// does not reveal anything beyond what a pattern match on the enum would.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, Error::Failed)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Failed => Self::FAILED_MESSAGE,
            Error::UnsupportedVersion => "mili: unsupported format version",
            Error::Io(_) => "mili: io error",
            Error::Internal => "mili: internal error",
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            Error::Failed | Error::UnsupportedVersion | Error::Internal => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::error::Error as _;
    use std::io;

    #[test]
    fn failed_message_is_fixed_and_carries_no_detail() {
        let error = Error::Failed;
        assert_eq!(error.to_string(), "mili: operation failed");
        assert!(error.source().is_none());
    }

    #[test]
    fn cryptographic_failures_are_one_variant() {
        // Every way a caller can be told that cryptographic input was bad must
        // land on Error::Failed. This test is the regression guard for the rule
        // that mili does not distinguish failure modes.
        assert!(Error::Failed.is_failed());
        assert!(!Error::UnsupportedVersion.is_failed());
        assert!(!Error::Io(io::Error::other("x")).is_failed());
        assert!(!Error::Internal.is_failed());
    }

    #[test]
    fn internal_variant_has_no_source() {
        assert!(Error::Internal.source().is_none());
        assert_eq!(Error::Internal.to_string(), "mili: internal error");
    }

    #[test]
    fn io_variant_keeps_its_source() {
        let error = Error::from(io::Error::new(io::ErrorKind::UnexpectedEof, "short read"));
        assert!(matches!(error, Error::Io(_)));
        assert_eq!(error.to_string(), "mili: io error");
        assert!(error.source().is_some());
    }
}
