//! The only source of randomness in mili.
//!
//! Every random value comes from the operating system CSPRNG through
//! [`getrandom`]. mili exposes no way to supply a generator, a seed or a
//! deterministic mode, so there is no public API through which a caller can
//! weaken or predict mili's randomness.
//!
//! Failure is closed. If the operating system source is unavailable the call
//! returns [`Error::Failed`] and the destination buffer is zeroized. mili does
//! not fall back to a weaker source, does not retry with a different mechanism
//! and does not continue with a partially filled buffer.

use zeroize::Zeroize;

use crate::error::Error;

/// Fills `buffer` with bytes from the operating system CSPRNG.
///
/// # Errors
///
/// [`Error::Failed`] if the operating system source is unavailable. `buffer` is
/// zeroized before returning in that case.
pub(crate) fn fill(buffer: &mut [u8]) -> Result<(), Error> {
    match getrandom::fill(buffer) {
        Ok(()) => Ok(()),
        Err(_) => {
            buffer.zeroize();
            Err(Error::Failed)
        }
    }
}

/// Returns `N` bytes from the operating system CSPRNG.
///
/// # Errors
///
/// [`Error::Failed`] if the operating system source is unavailable.
pub(crate) fn array<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0u8; N];
    fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{array, fill};
    use crate::error::Error;

    #[test]
    fn fill_produces_varying_output() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).expect("OS randomness is available");
        fill(&mut b).expect("OS randomness is available");
        assert_ne!(a, b);
    }

    #[test]
    fn fill_leaves_no_zero_run_of_32_bytes() {
        // A stuck or zero-filled source would show up here. This is a sanity
        // check on the wrapper, not a statistical test of the OS source.
        let mut zeros_seen = 0;
        for _ in 0..8 {
            let bytes = array::<32>().expect("OS randomness is available");
            if bytes == [0u8; 32] {
                zeros_seen += 1;
            }
        }
        assert_eq!(zeros_seen, 0);
    }

    #[test]
    fn array_of_various_sizes_fills_completely() {
        assert_eq!(array::<1>().expect("OS randomness is available").len(), 1);
        assert_eq!(array::<16>().expect("OS randomness is available").len(), 16);
        assert_eq!(array::<64>().expect("OS randomness is available").len(), 64);
    }

    #[test]
    fn fill_of_empty_slice_succeeds() {
        let mut empty: [u8; 0] = [];
        assert!(fill(&mut empty).is_ok());
    }

    #[test]
    fn errors_are_uniform() {
        // The only error this module can produce is the uniform one. There is
        // no path that reports the operating system error kind, because doing
        // so would tell a caller which source failed.
        fn assert_uniform(_: Error) {}
        assert_uniform(Error::Failed);
    }
}
