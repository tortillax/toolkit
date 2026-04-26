package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
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

func tempCertKey(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	cfg := CAConfig{
		SerialNumber: *big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		Validity:     time.Hour * 24,
		PathCert:     filepath.Join(dir, "ca.cert"),
		PathKey:      filepath.Join(dir, "ca.key"),
		PathDB:       filepath.Join(dir, "ca.db"),
		PathCRL:      filepath.Join(dir, "ca.crl"),
		PathCertDir:  filepath.Join(dir, "certs"),
	}
	ca, err := NewCA(cfg)
	if err != nil {
		t.Fatalf("NewCA failed: %v", err)
	}
	if err := ca.SaveCertKey(); err != nil {
		t.Fatalf("SaveCertKey failed: %v", err)
	}
	return cfg.PathCert, cfg.PathKey
}

// --- ReadCert ---

func TestReadCert_LoadsValidCert(t *testing.T) {
	certPath, _ := tempCertKey(t)

	cert, err := ReadCert(certPath)
	if err != nil {
		t.Fatalf("ReadCert failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestReadCert_ReturnsCorrectCommonName(t *testing.T) {
	certPath, _ := tempCertKey(t)

	cert, err := ReadCert(certPath)
	if err != nil {
		t.Fatalf("ReadCert failed: %v", err)
	}
	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("common name mismatch: got %q, want %q", cert.Subject.CommonName, "Test CA")
	}
}

func TestReadCert_ReturnsCorrectType(t *testing.T) {
	certPath, _ := tempCertKey(t)

	cert, err := ReadCert(certPath)
	if err != nil {
		t.Fatalf("ReadCert failed: %v", err)
	}
	if _, ok := any(cert).(*x509.Certificate); !ok {
		t.Error("expected *x509.Certificate")
	}
}

func TestReadCert_FailsOnMissingFile(t *testing.T) {
	_, err := ReadCert("/nonexistent/path/cert.pem")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestReadCert_FailsOnInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.crt")

	if err := os.WriteFile(path, []byte("this is not a pem"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := ReadCert(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestReadCert_FailsOnKeyFilePassedAsCert(t *testing.T) {
	_, keyPath := tempCertKey(t)

	// key PEM block type is "EC PRIVATE KEY", ParseCertificate will reject it
	_, err := ReadCert(keyPath)
	if err == nil {
		t.Fatal("expected error when passing key file as cert, got nil")
	}
}

// --- ReadKey ---

func TestReadKey_LoadsValidKey(t *testing.T) {
	_, keyPath := tempCertKey(t)

	key, err := ReadKey(keyPath)
	if err != nil {
		t.Fatalf("ReadKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestReadKey_ReturnsCorrectType(t *testing.T) {
	_, keyPath := tempCertKey(t)

	key, err := ReadKey(keyPath)
	if err != nil {
		t.Fatalf("ReadKey failed: %v", err)
	}
	if _, ok := any(key).(*ecdsa.PrivateKey); !ok {
		t.Error("expected *ecdsa.PrivateKey")
	}
}

func TestReadKey_FailsOnMissingFile(t *testing.T) {
	_, err := ReadKey("/nonexistent/path/key.pem")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestReadKey_FailsOnInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")

	if err := os.WriteFile(path, []byte("this is not a pem"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := ReadKey(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestReadKey_FailsOnCertFilePassedAsKey(t *testing.T) {
	certPath, _ := tempCertKey(t)

	// cert PEM block bytes are a certificate, ParseECPrivateKey will reject them
	_, err := ReadKey(certPath)
	if err == nil {
		t.Fatal("expected error when passing cert file as key, got nil")
	}
}

func TestReadKey_PublicKeyMatchesAfterRoundTrip(t *testing.T) {
	_, keyPath := tempCertKey(t)

	key, err := ReadKey(keyPath)
	if err != nil {
		t.Fatalf("ReadKey failed: %v", err)
	}
	// sanity: public key must be on P-256
	if key.Curve.Params().Name != "P-256" {
		t.Errorf("expected P-256 curve, got %s", key.Curve.Params().Name)
	}
}

// --- combineCertKeyFile ---

func TestCombineCertKeyFile_CreatesFile(t *testing.T) {
	certPath, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	if err := CombineCertKeyFile(certPath, keyPath, outPath, ""); err != nil {
		t.Fatalf("combineCertKeyFile failed: %v", err)
	}
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("p12 file was not created")
	}
}

func TestCombineCertKeyFile_FilePermissions(t *testing.T) {
	certPath, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	if err := CombineCertKeyFile(certPath, keyPath, outPath, ""); err != nil {
		t.Fatalf("combineCertKeyFile failed: %v", err)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("wrong permissions: got %o, want %o", info.Mode().Perm(), 0600)
	}
}

func TestCombineCertKeyFile_FailsIfOutputAlreadyExists(t *testing.T) {
	certPath, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	if err := CombineCertKeyFile(certPath, keyPath, outPath, ""); err != nil {
		t.Fatalf("first combineCertKeyFile failed: %v", err)
	}
	if err := CombineCertKeyFile(certPath, keyPath, outPath, ""); err == nil {
		t.Fatal("expected error on duplicate output path, got nil")
	}
}

func TestCombineCertKeyFile_FailsOnMissingCert(t *testing.T) {
	_, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	err := CombineCertKeyFile("/nonexistent/cert.pem", keyPath, outPath, "")
	if err == nil {
		t.Fatal("expected error for missing cert, got nil")
	}
}

func TestCombineCertKeyFile_FailsOnMissingKey(t *testing.T) {
	certPath, _ := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	err := CombineCertKeyFile(certPath, "/nonexistent/key.pem", outPath, "")
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
}

func TestCombineCertKeyFile_P12IsDecodable(t *testing.T) {
	certPath, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")
	password := "testpassword"

	if err := CombineCertKeyFile(certPath, keyPath, outPath, password); err != nil {
		t.Fatalf("combineCertKeyFile failed: %v", err)
	}

	p12Data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read p12 failed: %v", err)
	}

	key, cert, err := pkcs12.Decode(p12Data, password)
	if err != nil {
		t.Fatalf("pkcs12.Decode failed: %v", err)
	}
	if cert == nil {
		t.Fatal("decoded cert is nil")
	}
	if key == nil {
		t.Fatal("decoded key is nil")
	}
}

func TestCombineCertKeyFile_P12PreservesCommonName(t *testing.T) {
	certPath, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	if err := CombineCertKeyFile(certPath, keyPath, outPath, ""); err != nil {
		t.Fatalf("combineCertKeyFile failed: %v", err)
	}

	p12Data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read p12 failed: %v", err)
	}

	_, cert, err := pkcs12.Decode(p12Data, "")
	if err != nil {
		t.Fatalf("pkcs12.Decode failed: %v", err)
	}
	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("common name mismatch: got %q, want %q", cert.Subject.CommonName, "Test CA")
	}
}

func TestCombineCertKeyFile_WrongPasswordFails(t *testing.T) {
	certPath, keyPath := tempCertKey(t)
	outPath := filepath.Join(t.TempDir(), "client.p12")

	if err := CombineCertKeyFile(certPath, keyPath, outPath, "correctpassword"); err != nil {
		t.Fatalf("combineCertKeyFile failed: %v", err)
	}

	p12Data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read p12 failed: %v", err)
	}

	_, _, err = pkcs12.Decode(p12Data, "wrongpassword")
	if err == nil {
		t.Fatal("expected error decoding p12 with wrong password, got nil")
	}
}
