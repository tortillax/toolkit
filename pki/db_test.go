package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- NewCADB ---

func TestNewCADB_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil CADB")
	}
	if db.Path != path {
		t.Errorf("path mismatch: got %s, want %s", db.Path, path)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("DB file was not created on disk")
	}
}

func TestNewCADB_CreatesDirectoryStructure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "test.db")

	if _, err := NewCADB(path); err != nil {
		t.Fatalf("NewCADB failed to create nested dirs: %v", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("DB file not found after nested dir creation")
	}
}

func TestNewCADB_FailsIfAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	if _, err := NewCADB(path); err != nil {
		t.Fatalf("first NewCADB failed: %v", err)
	}
	_, err := NewCADB(path)
	if err == nil {
		t.Fatal("expected error on duplicate NewCADB, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestNewCADB_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	if _, err := NewCADB(path); err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("wrong permissions: got %o, want %o", info.Mode().Perm(), 0600)
	}
}

func TestNewCADB_WritesCorrectHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	if _, err := NewCADB(path); err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read DB file: %v", err)
	}
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	if firstLine != HEADER_CADB {
		t.Errorf("wrong header: got %q, want %q", firstLine, HEADER_CADB)
	}
}

func TestNewCADB_StartsWithEmptyIssuedList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if len(db.issued) != 0 {
		t.Errorf("expected empty issued list, got %d entries", len(db.issued))
	}
}

// --- LoadCADB ---

func TestLoadCADB_LoadsEmptyDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	if _, err := NewCADB(path); err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	db, err := LoadCADB(path)
	if err != nil {
		t.Fatalf("LoadCADB failed: %v", err)
	}
	if len(db.issued) != 0 {
		t.Errorf("expected empty issued list, got %d entries", len(db.issued))
	}
}

func TestLoadCADB_RejectsInvalidHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.db")

	if err := os.WriteFile(path, []byte("TOTALLY WRONG\n"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	_, err := LoadCADB(path)
	if err == nil {
		t.Fatal("expected error for invalid header, got nil")
	}
	if !strings.Contains(err.Error(), "invalid header") {
		t.Errorf("expected 'invalid header' in error, got: %v", err)
	}
}

func TestLoadCADB_ReturnsErrorForMissingFile(t *testing.T) {
	_, err := LoadCADB("/nonexistent/path/test.db")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadCADB_FillsIssuedList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	content := HEADER_CADB + "\n00000001\n00000002\n00000003\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test DB: %v", err)
	}
	db, err := LoadCADB(path)
	if err != nil {
		t.Fatalf("LoadCADB failed: %v", err)
	}

	want := []string{"00000001", "00000002", "00000003"}
	if len(db.issued) != len(want) {
		t.Fatalf("expected %d records, got %d: %v", len(want), len(db.issued), db.issued)
	}
	for i, w := range want {
		if db.issued[i] != w {
			t.Errorf("record[%d]: got %q, want %q", i, db.issued[i], w)
		}
	}
}

func TestLoadCADB_SkipsEmptyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	content := HEADER_CADB + "\n00000001\n\n00000002\n\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test DB: %v", err)
	}
	db, err := LoadCADB(path)
	if err != nil {
		t.Fatalf("LoadCADB failed: %v", err)
	}
	if len(db.issued) != 2 {
		t.Errorf("expected 2 records (empty lines skipped), got %d: %v", len(db.issued), db.issued)
	}
}

// --- nextSerial ---

func TestNextSerial_FirstSerialOnEmptyDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	serial, err := db.nextSerial()
	if err != nil {
		t.Fatalf("nextSerial failed: %v", err)
	}
	if serial != "00000001" {
		t.Errorf("expected %q, got %q", "00000001", serial)
	}
}

func TestNextSerial_IncrementsFromLast(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if err := db.issue("00000001"); err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if err := db.issue("00000002"); err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	serial, err := db.nextSerial()
	if err != nil {
		t.Fatalf("nextSerial failed: %v", err)
	}
	if serial != "3" {
		t.Errorf("expected %q, got %q", "3", serial)
	}
}

func TestNextSerial_FailsOnNonNumericLastEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	content := HEADER_CADB + "\nNOTANUMBER\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test DB: %v", err)
	}
	db, err := LoadCADB(path)
	if err != nil {
		t.Fatalf("LoadCADB failed: %v", err)
	}
	_, err = db.nextSerial()
	if err == nil {
		t.Fatal("expected error for non-numeric serial, got nil")
	}
}

// --- issue ---

func TestIssue_AddsRecordInMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if err := db.issue("00000001"); err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	if len(db.issued) != 1 || db.issued[0] != "00000001" {
		t.Errorf("unexpected issued list: %v", db.issued)
	}
}

func TestIssue_FailsOnDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if err := db.issue("00000001"); err != nil {
		t.Fatalf("first issue failed: %v", err)
	}
	if err := db.issue("00000001"); err == nil {
		t.Fatal("expected error on duplicate issue, got nil")
	}
}

func TestIssue_FailsOnNonNumericSerial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if err := db.issue("NOTANUMBER"); err == nil {
		t.Fatal("expected error for non-numeric serial, got nil")
	}
}

func TestIssue_PersistsAcrossLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	serials := []string{"00000001", "00000002", "00000003"}
	for _, s := range serials {
		if err := db.issue(s); err != nil {
			t.Fatalf("issue(%s) failed: %v", s, err)
		}
	}

	loaded, err := LoadCADB(path)
	if err != nil {
		t.Fatalf("LoadCADB failed: %v", err)
	}
	for _, s := range serials {
		ok, err := loaded.wasIssued(s)
		if err != nil {
			t.Fatalf("wasIssued(%s) error: %v", s, err)
		}
		if !ok {
			t.Errorf("serial %q not found after reload", s)
		}
	}
}

// --- wasIssued ---

func TestWasIssued_ReturnsTrueForIssuedSerial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	if err := db.issue("00000001"); err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	ok, err := db.wasIssued("00000001")
	if err != nil {
		t.Fatalf("wasIssued error: %v", err)
	}
	if !ok {
		t.Error("expected 00000001 to be marked as issued")
	}
}

func TestWasIssued_ReturnsFalseForUnknownSerial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	ok, err := db.wasIssued("00000099")
	if err != nil {
		t.Fatalf("wasIssued error: %v", err)
	}
	if ok {
		t.Error("expected 00000099 to not be issued")
	}
}

func TestWasIssued_ReturnsFalseOnEmptyList(t *testing.T) {
	db := &CADB{issued: make([]string, 0)}
	ok, err := db.wasIssued("00000001")
	if err != nil {
		t.Fatalf("wasIssued error: %v", err)
	}
	if ok {
		t.Error("wasIssued on empty list should return false")
	}
}

func TestWasIssued_FailsOnNonNumericSerial(t *testing.T) {
	db := &CADB{issued: []string{"00000001"}}
	_, err := db.wasIssued("NOTANUMBER")
	if err == nil {
		t.Fatal("expected error for non-numeric serial, got nil")
	}
}

func TestWasIssued_MatchesByNumericValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := NewCADB(path)
	if err != nil {
		t.Fatalf("NewCADB failed: %v", err)
	}
	// issue with zero-padded format
	if err := db.issue("00000001"); err != nil {
		t.Fatalf("issue failed: %v", err)
	}
	// wasIssued with plain integer string — should still match (numeric comparison)
	ok, err := db.wasIssued("1")
	if err != nil {
		t.Fatalf("wasIssued error: %v", err)
	}
	if !ok {
		t.Error("wasIssued should match numerically (00000001 == 1)")
	}
}
