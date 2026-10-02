# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(**Security** → **Advisories** → **Report a vulnerability**).

That channel opens a private thread between the reporter and the maintainer. It
does not require an email address in your GitHub profile, it does not notify
anyone else, and nothing is published until a fix exists. Please do not open a
public issue for anything that looks like a vulnerability.

If private reporting is unavailable to you, open a public issue that says only
that you would like to discuss a security matter privately, without the details.

## What is worth reporting

mili is parameter selection and a wrapper around third-party cryptography
crates. The interesting failures are the ones where mili's own choices are
wrong, so these are in scope:

- A parameter, a key schedule or a key hierarchy step that does not match
  `docs/SPEC.md`, or that `docs/SPEC.md` documents wrongly.
- An authentication, key agreement or cryptographic parse failure that produces
  a distinguishable result — anything that breaks the uniformity claim in
  `README.md` rule 4 or `docs/THREAT_MODEL.md` section 3.
- An attacker-controlled length, index or count that reaches an allocation or a
  copy before it is bounded. `docs/SPEC.md` section 6 requires every length to be
  checked against a documented limit first.
- A plaintext that is released before the data covering it has been
  authenticated, in `mili-core` or across the C ABI in `mili-ffi`.
- A panic, an out of bounds access or a use after free in `mili-ffi`. A panic
  must not cross the boundary.
- A secret that outlives its use in a way the documentation says it does not.
- A test vector, known answer test or NIST ACVP case that a pinned version
  fails, or a published defect affecting a pinned version.

## What is not a vulnerability here

These are documented positions, and a report that consists of one of them is a
question rather than a defect:

- Any algorithm, key size or parameter choice. mili selects parameters and does
  not offer alternatives. `docs/SPEC.md` section 2 is the argument for each one.
- Absence of padding, cover traffic or fixed-size output.
  `docs/THREAT_MODEL.md` section 5.3 and 5.4 say so directly.
- Anything in `docs/THREAT_MODEL.md` section 5, which is the out-of-scope list:
  compromised host, coercion, traffic analysis, length hiding, and hardware side
  channels beyond what the upstream crates handle.
- A defect in an upstream crate. Those are worth reporting upstream. If it
  affects a pinned version, note it here too, since a version bump may be the
  fix.
- The two partial reviews named in `supply-chain/README.md`. `libc` and
  `curve25519-dalek` are recorded as partly read, and a finding in the part that
  was not read is a real report rather than a criticism of the note.

## Scope of a fix

mili pins every dependency with `=` and treats a version change as an explicit
edit, so a fix that requires one is expected to be argued rather than made
quietly. `docs/SPEC.md` section 16 records the reproducibility constraints that
constrain the options.
