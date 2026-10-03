# mili CLI: design notes

There is no CLI. `mili-core` is a library, `mili-ffi` is a C ABI, and the one Go
program in the tree is the binding's test suite. That is a deliberate stopping
point rather than an oversight, and this document records what a CLI would have to
get right, so the decision can be revisited with the reasoning intact rather than
from scratch.

It is written after reading Ente's Rust CLI, which has the same problem in a
larger workspace and has solved some of it well and some of it badly. What
follows is the part worth copying and the part worth refusing. Nothing here is
implemented, and nothing here promises that a CLI will exist.

## Why a CLI is not obvious for this crate

A command line tool is the obvious way to make a format usable, and there is
reason to be careful about it here specifically.

mili's test suite is slow on purpose. Opening a key file or a backup runs
Argon2id at 64 MiB, which is about a fifth of a second on a laptop and closer to
half a second in a container with a small memory budget. A CLI that performs
several derivations in sequence is a CLI where a user waits seconds per command,
and where a shell script around it multiplies that. The library's choice of
parameters is not negotiable — `docs/SPEC.md` section 7.2 is the argument for it —
so the cost cannot be tuned away. It has to be designed around.

The second reason is that a CLI needs somewhere to keep things. A library keeps
nothing; a CLI needs a home directory, a config location, a cache and somewhere
for a password to arrive from. Every one of those is a place to leak a key or to
get the file permissions wrong, and there is a worked example of that going
wrong in the reference project below.

## The shape that works

### Ask for a secret in three ways, never one

A password has to reach the program by some route, and the routes are not
equivalent. Ente's CLI takes `--password` as an argument. That is a command line
flag, which means it lands in the shell history file and is visible in `ps` to
every process on the machine for as long as the command runs. It has no
environment variable route and no standard-input route for the password, only
the paste secret, which is the exception rather than the rule.

Three routes, in descending order of preference:

- an environment variable, read and zeroized immediately, for scripts
- standard input, for anything a person types
- an interactive prompt that does not echo, as the default when a terminal is
  present

A flag may exist for tests, as it does in Ente's, but it must not be the only
way. `mili-ffi` has the same property for free: `mili_backup_open` takes the
password as bytes the caller already has, and says nothing about where they came
from. A CLI has to answer that question and a library does not.

### Zeroize everything, including the copies

Ente's `AccountSecrets` derives `Zeroize` and `#[zeroize(drop)]`, and then every
use site clones it into a plain `Vec<u8>` to write to SQLite. The wrapper is
zeroized; the copy is not, and the copy is the one that lives in the database and
in SQLite's page cache.

`mili-core` starts out better than that, for two structural reasons rather than one.
Every key type wraps a `SecretBytes<N>` that zeroes on drop, and none of them
offers a `into_vec` — the two that hand bytes back, `KeyFile::into_bytes` and
`Backup::into_bytes`, return the *container*, not the key, and those bytes are
ciphertext. So a CLI cannot accidentally get at a key as a plain slice. The
discipline it has to keep is not to copy out of a key type into a local `Vec<u8>`
and then drop the original, and anything reaching an operating system call has to
be wrapped as it goes. `docs/THREAT_MODEL.md` section 4.1 records which of mili's
own buffers get this treatment and which deliberately do not.

### Test the binary, not the library

Integration tests should run the compiled binary. Ente's harness is 83 lines and
uses `std::process::Command` with `env!("CARGO_BIN_EXE_ente-rs")`, which is the
whole of it: no `assert_cmd`, no PTY, no extra dependency. Two details are worth
taking:

- **One environment variable gives per-test isolation.** Ente's harness passes
  `ENTE_CLI_CONFIG_DIR` pointing at a directory under the test's temp dir, and
  each scenario gets its own. No global state, no cleanup step, no test that
  depends on running before another. mili would want `MILI_HOME` or similar for
  whatever a CLI keeps, and the same per-test subdirectory.
- **Assert on what was printed, not only that it failed.** Ente checks that the
  second attempt at a consumed paste failed *and* that stderr contains `HTTP 410`,
  and separately checks a negative — that a consumed paste did **not** print the
  "password cannot be empty" complaint, because the client checks availability
  before asking for a password. That is the level at which a CLI's behaviour is
  worth pinning: the order of operations is observable, and a test that only
  checks the exit code cannot see it.

### Put the prompts behind a trait, then test with a script

Without a PTY, interactive code is untestable. Ente solves this by making the
prompts a trait: `AuthFlowUi` has one method per thing the protocol might need to
ask a person, and the CLI implements it with `dialoguer`. The integration tests
never touch `dialoguer`; they pre-seed the implementation with flags
(`--otp 123456`) so the interactive path is bypassed, and the retry logic is
unit-tested by injecting a scripted implementation that returns a queue of answers
and records what it was asked.

This is the right shape for mili and it costs one trait. A password prompt, an
overwrite confirmation and a "this file already exists, replace it" question are
three methods. Everything else in a CLI is argument parsing and I/O, which test
fine without a terminal.

### One `--password` retry rule, applied consistently

Ente retries a rejected password only if the person typed it. A password that
came from a flag or an environment variable is not retried, because it is
scripted input and a loop over it is a script that hangs. It encodes the two
cases as a small enum rather than a boolean, which is clearer than a flag that
means "maybe":

```rust
enum PasswordAttempt {
    FromEnvironment,
    Prompted,
}

impl PasswordAttempt {
    fn can_retry(&self) -> bool {
        matches!(self, Self::Prompted(_))
    }
}
```

Worth copying because it is the kind of rule that looks obvious once written and
is easy to get backwards.

## The shape to refuse

### Do not open state before parsing arguments

Ente's `main` opens the config directory and the SQLite database, and only then
calls `Cli::parse()`. The consequence is that `--help`, `--version` and every
subcommand that does not need the database create `~/.config/ente-cli/ente.db` as
a side effect. A read-only command that writes to disk is a surprise, and on a
machine where the config directory is a network mount it is a hang.

Parse first, open second, and only in the branch that needs it.

### Do not create a world-readable file

Ente's CLI stores the account's master key in a SQLite blob and sets no
permissions: no `chmod`, no `set_permissions`, no `OpenOptions::mode`. The
directory lands at `0755` and the database at `0644` under a normal umask. On a
multi-user host that is the master key, readable by every local account, in a
file that is not encrypted at rest.

mili has the material to get this right and no excuse not to. A CLI that writes
anything holding key material should set `0600` at creation with
`OpenOptionsExt::mode` and verify it afterwards with `metadata().permissions()`,
because the mode is only as good as the umask it was created under and a
pre-existing file keeps whatever it had. `docs/THREAT_MODEL.md` section 5 covers
the compromised host; this is not that, it is a default that leaks to other
accounts on a host that is otherwise fine.

### Do not print a secret because a flag asked for it

Ente's `account get-token` prints the session token to stdout, and the setup flow
prints the TOTP secret to stdout unconditionally, discarding the QR code it
fetched. Both are deliberate features and both put a long-lived secret into a
terminal scrollback, a terminal scrollback file, and any CI job that captures
output. If a mili CLI ever needs to emit a secret, it should write to a file the
user names with `0600`, or to a file descriptor the caller opened, and say on
stderr that it did.

### Do not derive more than once per command

This one is mili's own, not Ente's, and it is the largest cost a CLI would add.
A user restoring a backup wants to know what is in it, and the natural command is
`mili backup info` — which needs no password, and mili has `Backup::info`
specifically so it does not. The command that then needs a password will pay for
one derivation. What must not happen is a command that derives, then re-derives
because a sub-step wanted the key again, because at half a second each that is
the difference between a tool and a nuisance.

`Backup::info` existing at all is what makes the useful command cheap, and that is
the argument for keeping it: it is the difference between "the tool has to guess
whether this file is a mili backup" and "the tool can say, and then ask".

## Dependencies, if this happens

A CLI should add as little as possible, and the additions worth arguing about:

- an argument parser. `clap` is the obvious one and Ente's use of it is
  unremarkable: `#[derive(Parser)]` plus `#[derive(Subcommand)]`, aliases where
  they help, `conflicts_with` for mutually exclusive arguments. Nothing about
  mili requires a parser framework; nothing about it argues against one either.
- a prompt library, if prompts are wanted. `dialoguer` does no-echo and is what
  Ente uses. It is the largest single dependency this would add and the one
  least tied to crypto, so it is the first place to look for something smaller.
- a way to read a password without echo, if not using the above. On Unix that is
  a termios change, which is small and which a reviewer can read. Cross-platform
  it stops being small, which is the argument for the library.

What it should **not** need: a keyring. An OS credential store ties the key to an
account on a machine, which is a different trust model from "the file and the
password", and it means the recovery story depends on the desktop session.
Ente's choice — an encrypted local file — is defensible for the same reason, but
mili's would have to be a mili key file, which is a thing mili already has.

## What a first version should be able to do

Ordered by what the library already supports and by cost per invocation.

1. `mili version`. Prints the crate version and the format version byte. Costs
   nothing, allocates nothing, and should not touch the filesystem.
2. `mili backup info <file>`. Wraps `Backup::info`. No password, no derivation,
   no file creation. Prints the Argon2 profile and the entry count. This is the
   command that makes the argument in "Ask for a secret in three ways" concrete:
   it is the reason a password prompt is not the first thing a user sees.
3. `mili backup keys <file>`. Wraps `Backup::open` and prints the key
   identifiers, which needs one derivation.
4. `mili backup restore <file> --out <dir>`. Wraps `Backup::open` and writes key
   files.
5. `mili key wrap` and `mili key unwrap`, once there is a decision about what
   happens to the password at rest.

The first two need no password handling at all, which is the right place to
start: they are the commands that let a user decide whether they want to continue.

## Summary

The library is ready for a CLI and the wire format is specified tightly enough
that one cannot get the file handling wrong by accident. What is missing is a
decision about where a password comes from and where state is kept, and both of
those are privacy decisions rather than engineering ones. That is the reason this
is a document and not a crate.