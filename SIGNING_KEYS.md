# Release signing keys

The public half of every Ed25519 key that has signed a mili release tag appears
here. There is no private key in this repository, in CI, or in any encrypted file
in this repository, and there is no key server to revoke against.

`SPEC.md` section 17 states the policy. This file is the record of who has signed
what, so that a user can check a tag against a key whose half is published rather
than against one they were handed at download time.

## Why this is a file rather than a key server

An offline key with a published public half has one property a hosted key
infrastructure does not: it cannot be silently rotated, compromised and replaced
without the change being visible in this file's history. The cost is that
revocation is a manual act, so this file is the revocation mechanism. Removing a
line does not un-sign a tag; it tells a reader that the key is no longer trusted.

## Keys

No key has signed a tag yet. This repository has no releases.

When a key is generated, add a section here before the first tag it signs, so that
the public half is published in the same commit or an earlier one than the tag it
appears on. A key first seen in the same commit as the tag it signed would let
anyone who read that commit also have signed the tag.

Record for each key:

- the fingerprint, which for `ssh-keygen -lf` is a SHA-256 digest of the public
  key and is the value to check against a downloaded tag;
- the date it was generated, offline;
- the date it is withdrawn, if it ever is, and why.

## Checking a tag

A release tag is a signed tag, so `git verify-tag` is the check and
`git tag -v` prints the signing key's fingerprint for comparison against this
file:

```sh
git fetch --tags
git tag -v mili-v1.0.0
```

A tag that does not verify, or that verifies with a fingerprint absent from this
file, is not a mili release. Build provenance is a separate matter and is
produced keyless with sigstore from the workflow run, which needs no key at all;
see `SPEC.md` section 17.

## If a key is suspected of exposure

There is no revocation shortcut. The procedure in `SPEC.md` section 17 applies:
release history is re-signed with a new key, this file records the withdrawal and
its reason, and both facts appear in the release notes for the re-signed tag. A
user who downloaded a build signed by the withdrawn key has to decide what to do
with it, and the honest answer is that the withdrawal date is the information
they need to reason about when they downloaded it.