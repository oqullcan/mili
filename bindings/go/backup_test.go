package mili

import (
	"bytes"
	"errors"
	"testing"
)

func mustBackup(t *testing.T, entries ...func(*BackupBuilder) error) Backup {
	t.Helper()
	builder := NewBackupBuilder()
	for _, add := range entries {
		if err := add(builder); err != nil {
			t.Fatalf("adding an entry: %v", err)
		}
	}
	backup, err := builder.Build(testPassword)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return backup
}

func addSealing(key SealingKey) func(*BackupBuilder) error {
	return func(b *BackupBuilder) error { return b.AddSealingKey(key) }
}

func addSigning(key SigningKey) func(*BackupBuilder) error {
	return func(b *BackupBuilder) error { return b.AddSigningKey(key) }
}

func addSymmetric(key SymmetricKey) func(*BackupBuilder) error {
	return func(b *BackupBuilder) error { return b.AddSymmetricKey(key) }
}

func TestBackupRoundTripsEveryKindOfKey(t *testing.T) {
	sealing := mustSealingKey(t)
	signing := mustSigningKey(t)
	symmetric := mustSymmetricKey(t)

	backup := mustBackup(t, addSealing(sealing), addSigning(signing), addSymmetric(symmetric))
	if !bytes.HasPrefix(backup.Bytes(), []byte("mili\x11\x01")) {
		t.Errorf("a backup does not start with mili\\x11\\x01: %x", backup.Bytes()[:6])
	}

	entries, err := backup.Open(testPassword)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("the backup came back with %d entries, want 3", len(entries))
	}

	if entries[0].Kind() != KindSealing || !bytes.Equal(entries[0].Key.Sealing, sealing) {
		t.Error("the sealing key came back wrong")
	}
	if entries[1].Kind() != KindSigning || !bytes.Equal(entries[1].Key.Signing, signing) {
		t.Error("the signing key came back wrong")
	}
	if entries[2].Kind() != KindSymmetric || !bytes.Equal(entries[2].Key.Symmetric, symmetric) {
		t.Error("the symmetric key came back wrong")
	}
}

// TestEveryEntryHasADistinctIdentifier is what SPEC.md section 8 promises and what a
// caller uses to tell its backups apart.
func TestEveryEntryHasADistinctIdentifier(t *testing.T) {
	backup := mustBackup(t,
		addSealing(mustSealingKey(t)),
		addSigning(mustSigningKey(t)),
		addSymmetric(mustSymmetricKey(t)),
	)
	entries, err := backup.Open(testPassword)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		if len(entry.KeyID) != 16 {
			t.Errorf("an identifier is 16 bytes, got %d", len(entry.KeyID))
		}
		if seen[string(entry.KeyID)] {
			t.Error("two entries share an identifier")
		}
		seen[string(entry.KeyID)] = true
	}
}

// TestTheSameKeysGiveTheSameIdentifiers is what makes an identifier usable: it has to
// be a property of the key, not of the container it happened to land in.
func TestTheSameKeysGiveTheSameIdentifiers(t *testing.T) {
	sealing := mustSealingKey(t)

	first := mustBackup(t, addSealing(sealing))
	second := mustBackup(t, addSealing(sealing))

	firstEntries, err := first.Open(testPassword)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	secondEntries, err := second.Open(testPassword)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(firstEntries[0].KeyID, secondEntries[0].KeyID) {
		t.Error("the same key got two identifiers")
	}
}

func TestTwoBackupsOfTheSameKeysDiffer(t *testing.T) {
	sealing := mustSealingKey(t)
	first := mustBackup(t, addSealing(sealing))
	second := mustBackup(t, addSealing(sealing))
	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("two backups of the same keys are byte identical, so the salt repeated")
	}
}

func TestBackupRejectsAWrongPassword(t *testing.T) {
	backup := mustBackup(t, addSealing(mustSealingKey(t)))
	if _, err := backup.Open([]byte("the wrong password")); !errors.Is(err, ErrFailed) {
		t.Errorf("a wrong password gave %v, want ErrFailed", err)
	}
}

func TestBackupRejectsAnEmptyPassword(t *testing.T) {
	builder := NewBackupBuilder()
	if err := builder.AddSealingKey(mustSealingKey(t)); err != nil {
		t.Fatalf("AddSealingKey: %v", err)
	}
	if _, err := builder.Build(nil); !errors.Is(err, ErrFailed) {
		t.Errorf("an empty password on the way in gave %v, want ErrFailed", err)
	}

	backup := mustBackup(t, addSealing(mustSealingKey(t)))
	if _, err := backup.Open(nil); !errors.Is(err, ErrFailed) {
		t.Errorf("an empty password on the way out gave %v, want ErrFailed", err)
	}
}

func TestBackupNeedsAtLeastOneKey(t *testing.T) {
	if _, err := NewBackupBuilder().Build(testPassword); err == nil {
		t.Error("an empty backup was built")
	}
}

func TestBackupRejectsADuplicateKey(t *testing.T) {
	key := mustSealingKey(t)
	builder := NewBackupBuilder()
	if err := builder.AddSealingKey(key); err != nil {
		t.Fatalf("AddSealingKey: %v", err)
	}
	if err := builder.AddSealingKey(key); err != nil {
		t.Fatalf("AddSealingKey: %v", err)
	}
	if _, err := builder.Build(testPassword); !errors.Is(err, ErrFailed) {
		t.Errorf("a duplicate key gave %v, want ErrFailed", err)
	}
}

func TestBackupRejectsAKeyOfTheWrongLength(t *testing.T) {
	builder := NewBackupBuilder()
	if err := builder.AddSealingKey(SealingKey(mustSigningKey(t))); err == nil {
		t.Error("a 64 byte value was added as a sealing key")
	}
	if err := builder.AddSigningKey(SigningKey(mustSealingKey(t))); err == nil {
		t.Error("a 32 byte value was added as a signing key")
	}
}

func TestBackupRejectsArbitraryBytes(t *testing.T) {
	for _, length := range []int{0, 1, 63, 64, 200} {
		backup := Backup(make([]byte, length))
		if _, err := backup.Open(testPassword); !errors.Is(err, ErrFailed) {
			t.Errorf("a %d byte buffer opened with %v, want ErrFailed", length, err)
		}
	}
}

func TestBackupRejectsATamperedByte(t *testing.T) {
	backup := mustBackup(t, addSealing(mustSealingKey(t)), addSigning(mustSigningKey(t)))

	for index := 0; index < len(backup); index += 11 {
		tampered := append(Backup(nil), backup...)
		tampered[index] ^= 0x01
		if _, err := tampered.Open(testPassword); !errors.Is(err, ErrFailed) {
			t.Fatalf("byte %d of a tampered backup opened", index)
		}
	}
}

func TestKindStringNamesEveryKind(t *testing.T) {
	for kind, want := range map[Kind]string{
		KindSealing:   "sealing",
		KindSigning:   "signing",
		KindSymmetric: "symmetric",
	} {
		if got := kind.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", kind, got, want)
		}
	}
	if got := Kind(99).String(); got != "unknown" {
		t.Errorf("Kind(99).String() = %q, want %q", got, "unknown")
	}
}

// Info reports what a backup claims without running a 64 MiB derivation, and KeyID
// computes the other half of the identifier workflow SPEC.md section 11 describes.
// Only the readable half existed before: a caller could read the identifiers out of
// a backup but not compute the expected one for a key it held.
func TestBackupInfoAndKeyID(t *testing.T) {
	sealing, err := GenerateSealingKey()
	if err != nil {
		t.Fatalf("GenerateSealingKey: %v", err)
	}
	builder := NewBackupBuilder()
	if err := builder.AddSealingKey(sealing); err != nil {
		t.Fatalf("AddSealingKey: %v", err)
	}
	backup, err := builder.Build([]byte(testPassword))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	info, err := backup.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.EntryCount != 1 {
		t.Errorf("EntryCount = %d, want 1", info.EntryCount)
	}
	if info.MCost != 64*1024 || info.TCost != 3 || info.PCost != 4 {
		t.Errorf("profile = %d/%d/%d, want 65536/3/4", info.MCost, info.TCost, info.PCost)
	}

	id, err := sealing.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	entries, err := backup.Open([]byte(testPassword))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if string(entries[0].KeyID) != string(id) {
		t.Errorf("the computed identifier does not match the one in the backup")
	}

	// Deterministic.
	again, err := sealing.ID()
	if err != nil {
		t.Fatalf("ID again: %v", err)
	}
	if string(again) != string(id) {
		t.Error("the identifier is not deterministic")
	}

	// Not a backup, and an empty key.
	if _, err := Backup([]byte("nope")).Info(); !errors.Is(err, ErrFailed) {
		t.Errorf("Info on a non-backup gave %v, want ErrFailed", err)
	}
	if _, err := KeyID(BackupKey{}); err == nil {
		t.Error("KeyID of an empty key was accepted")
	}
}

// A symmetric key file could be opened but not created before this.
func TestWrapSymmetricKeyFile(t *testing.T) {
	key, err := GenerateSymmetricKey()
	if err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	file, err := WrapSymmetricKeyFile(key, []byte(testPassword))
	if err != nil {
		t.Fatalf("WrapSymmetricKeyFile: %v", err)
	}

	if kind := file.PayloadType(); kind != PayloadSymmetric {
		t.Errorf("PayloadType = %v, want PayloadSymmetric", kind)
	}

	// Unwrap takes the expected kind as an argument, so this is the path a caller
	// uses to ask for the symmetric key back.
	opened, err := file.unwrap(PayloadSymmetric, []byte(testPassword))
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(opened) != string(key) {
		t.Error("the key came back different")
	}

	// The other typed openers still refuse it.
	if _, err := file.UnwrapSealing([]byte(testPassword)); !errors.Is(err, ErrFailed) {
		t.Errorf("a symmetric key file opened as a sealing key: %v, want ErrFailed", err)
	}
}
