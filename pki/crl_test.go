package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewCRL_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	crl, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}
	if crl == nil {
		t.Fatal("expected non-nil CRL")
	}
	if crl.Path != path {
		t.Errorf("path mismatch: got %s, want %s", crl.Path, path)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("CRL file was not created on disk")
	}
}

func TestNewCRL_CreatesDirectoryStructure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "test.crl")

	_, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed to create nested dirs: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("CRL file not found after nested dir creation")
	}
}

func TestNewCRL_FailsIfAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	if _, err := NewCRL(path); err != nil {
		t.Fatalf("first NewCRL failed: %v", err)
	}

	_, err := NewCRL(path)
	if err == nil {
		t.Fatal("expected error on duplicate NewCRL, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestNewCRL_WritesCorrectHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	if _, err := NewCRL(path); err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read CRL file: %v", err)
	}
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	if firstLine != HEADER_CRL {
		t.Errorf("wrong header: got %q, want %q", firstLine, HEADER_CRL)
	}
}

func TestLoadCRL_LoadsEmptyCRL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	if _, err := NewCRL(path); err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}

	crl, err := LoadCRL(path)
	if err != nil {
		t.Fatalf("LoadCRL failed: %v", err)
	}
	if crl == nil {
		t.Fatal("expected non-nil CRL")
	}
	if len(crl.revoked) != 0 {
		t.Errorf("expected empty revocation list, got %d entries", len(crl.revoked))
	}
}

func TestLoadCRL_RejectsInvalidHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.crl")

	if err := os.WriteFile(path, []byte("INVALID HEADER\n"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadCRL(path)
	if err == nil {
		t.Fatal("expected error for invalid header, got nil")
	}
	if !strings.Contains(err.Error(), "invalid header") {
		t.Errorf("expected 'invalid header' in error, got: %v", err)
	}
}

func TestLoadCRL_ReturnsErrorForMissingFile(t *testing.T) {
	_, err := LoadCRL("/nonexistent/path/test.crl")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadCRL_LoadsRecordsCorrectly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	content := HEADER_CRL + "\n" +
		"SERIAL001" + SEPARATOR + "keyCompromise\n" +
		"SERIAL002" + SEPARATOR + "cessationOfOperation\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test CRL: %v", err)
	}

	crl, err := LoadCRL(path)
	if err != nil {
		t.Fatalf("LoadCRL failed: %v", err)
	}
	if len(crl.revoked) != 2 {
		t.Fatalf("expected 2 records, got %d", len(crl.revoked))
	}

	cases := []CRLRecord{
		{Serial: "SERIAL001", Reason: "keyCompromise"},
		{Serial: "SERIAL002", Reason: "cessationOfOperation"},
	}
	for i, want := range cases {
		got := crl.revoked[i]
		if got.Serial != want.Serial || got.Reason != want.Reason {
			t.Errorf("record[%d]: got {%s %s}, want {%s %s}",
				i, got.Serial, got.Reason, want.Serial, want.Reason)
		}
	}
}

func TestLoadCRL_SkipsLinesWithoutSeparator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	content := HEADER_CRL + "\n" +
		"SERIAL001" + SEPARATOR + "keyCompromise\n" +
		"this line has no separator\n" +
		"SERIAL002" + SEPARATOR + "affiliationChanged\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test CRL: %v", err)
	}

	crl, err := LoadCRL(path)
	if err != nil {
		t.Fatalf("LoadCRL failed: %v", err)
	}
	if len(crl.revoked) != 2 {
		t.Errorf("expected 2 valid records (bad line skipped), got %d", len(crl.revoked))
	}
}

func TestRevoke_AddsRecordInMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	crl, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}

	if err := crl.revoke("SERIAL001", "keyCompromise"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if len(crl.revoked) != 1 {
		t.Fatalf("expected 1 revoked record, got %d", len(crl.revoked))
	}
	if crl.revoked[0].Serial != "SERIAL001" || crl.revoked[0].Reason != "keyCompromise" {
		t.Errorf("unexpected record: %+v", crl.revoked[0])
	}
}

func TestRevoke_PersistsAcrossLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	crl, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}
	if err := crl.revoke("SERIAL001", "keyCompromise"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if err := crl.revoke("SERIAL002", "cessationOfOperation"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	loaded, err := LoadCRL(path)
	if err != nil {
		t.Fatalf("LoadCRL failed after revoke: %v", err)
	}
	if len(loaded.revoked) != 2 {
		t.Fatalf("expected 2 records after reload, got %d", len(loaded.revoked))
	}
	if !loaded.isRevoked("SERIAL001") {
		t.Error("SERIAL001 not found in reloaded CRL")
	}
	if !loaded.isRevoked("SERIAL002") {
		t.Error("SERIAL002 not found in reloaded CRL")
	}
}

func TestRevoke_FailsOnDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	crl, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}

	if err := crl.revoke("SERIAL001", "keyCompromise"); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	if err := crl.revoke("SERIAL001", "keyCompromise"); err == nil {
		t.Fatal("expected error on duplicate revoke, got nil")
	}
}

func TestIsRevoked_ReturnsTrueForRevokedSerial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	crl, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}
	if err := crl.revoke("SERIAL001", "keyCompromise"); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	if !crl.isRevoked("SERIAL001") {
		t.Error("expected SERIAL001 to be revoked")
	}
}

func TestIsRevoked_ReturnsFalseForUnknownSerial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.crl")

	crl, err := NewCRL(path)
	if err != nil {
		t.Fatalf("NewCRL failed: %v", err)
	}

	if crl.isRevoked("NONEXISTENT") {
		t.Error("expected NONEXISTENT to not be revoked")
	}
}

func TestIsRevoked_EmptyList(t *testing.T) {
	crl := &CRL{revoked: make([]CRLRecord, 0)}
	if crl.isRevoked("ANYTHING") {
		t.Error("isRevoked on empty list should always return false")
	}
}
