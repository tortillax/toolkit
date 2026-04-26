package pki

import (
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/x509/pkix"
)

// --- helpers ---

func tempCA(t *testing.T) (*CA, string) {
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
	if err := os.MkdirAll(cfg.PathCertDir, 0755); err != nil {
		t.Fatalf("mkdir certs failed: %v", err)
	}
	if err := ca.SaveCertKey(); err != nil {
		t.Fatalf("SaveCertKey failed: %v", err)
	}
	return ca, dir
}

// --- NewCA ---

func TestNewCA_ReturnsValidObject(t *testing.T) {
	ca, _ := tempCA(t)
	if ca.certificate == nil {
		t.Error("certificate is nil")
	}
	if ca.privateKey == nil {
		t.Error("privateKey is nil")
	}
	if ca.db == nil {
		t.Error("db is nil")
	}
	if ca.crl == nil {
		t.Error("crl is nil")
	}
}

func TestNewCA_CertIsCA(t *testing.T) {
	ca, _ := tempCA(t)
	if !ca.certificate.IsCA {
		t.Error("CA certificate IsCA flag not set")
	}
}

func TestNewCA_CertKeyUsage(t *testing.T) {
	ca, _ := tempCA(t)
	if ca.certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert missing KeyUsageCertSign")
	}
	if ca.certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("CA cert missing KeyUsageCRLSign")
	}
}

func TestNewCA_FailsIfFilesAlreadyExist(t *testing.T) {
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
		t.Fatalf("first NewCA failed: %v", err)
	}
	if err := ca.SaveCertKey(); err != nil {
		t.Fatalf("SaveCertKey failed: %v", err)
	}
	// second NewCA should fail on CRL or DB already existing
	_, err = NewCA(cfg)
	if err == nil {
		t.Fatal("expected error on duplicate NewCA, got nil")
	}
}

// --- SaveCertKey ---

func TestSaveCertKey_FilesExistWithCorrectPermissions(t *testing.T) {
	_, dir := tempCA(t)

	keyInfo, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("key file not found: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key permissions: got %o, want %o", keyInfo.Mode().Perm(), 0600)
	}

	certInfo, err := os.Stat(filepath.Join(dir, "ca.cert"))
	if err != nil {
		t.Fatalf("cert file not found: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("cert permissions: got %o, want %o", certInfo.Mode().Perm(), 0644)
	}
}

func TestSaveCertKey_FailsIfAlreadyExists(t *testing.T) {
	ca, _ := tempCA(t) // already saved once
	err := ca.SaveCertKey()
	if err == nil {
		t.Fatal("expected error on second SaveCertKey, got nil")
	}
}

// --- LoadCA ---

func TestLoadCA_RoundTrip(t *testing.T) {
	ca, dir := tempCA(t)

	loaded, err := LoadCA(
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "ca.cert"),
		filepath.Join(dir, "ca.db"),
		filepath.Join(dir, "ca.crl"),
		filepath.Join(dir, "certs"),
	)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if loaded.certificate.SerialNumber.Cmp(ca.certificate.SerialNumber) != 0 {
		t.Error("serial mismatch after load")
	}
	if loaded.certificate.Subject.CommonName != ca.certificate.Subject.CommonName {
		t.Error("common name mismatch after load")
	}
}

func TestLoadCA_FailsOnMissingFiles(t *testing.T) {
	_, err := LoadCA("/bad/ca.key", "/bad/ca.cert", "/bad/ca.db", "/bad/ca.crl", "/bad/certs")
	if err == nil {
		t.Fatal("expected error for missing files, got nil")
	}
}

// --- GenerateExportCertKey ---

func TestGenerateExportCertKey_ServerCert(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	if cert == nil {
		t.Fatal("returned nil cert")
	}
	if isServer(cert) == false {
		t.Error("expected server ExtKeyUsage")
	}
	if isCA(cert) {
		t.Error("issued cert should not be CA")
	}
	if certType(cert) != "backend" {
		t.Errorf("certType: got %q, want %q", certType(cert), "backend")
	}
}

func TestGenerateExportCertKey_ClientCert(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("client-a", "ops", nil, nil, time.Hour*24, false)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	if isServer(cert) {
		t.Error("client cert should not have ServerAuth EKU")
	}
}

func TestGenerateExportCertKey_PEMFilesCreated(t *testing.T) {
	ca, dir := tempCA(t)

	_, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}

	ns := ca.db.issued[len(ca.db.issued)-1]
	certPath := filepath.Join(dir, "certs", ns+".crt")
	keyPath := filepath.Join(dir, "certs", ns+".key")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("cert PEM file not found: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("key PEM file not found: %s", keyPath)
	}
}

func TestGenerateExportCertKey_KeyFilePermissions(t *testing.T) {
	ca, dir := tempCA(t)

	_, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}

	// serial filename matches what nextSerial/issue stored, not cert.SerialNumber.String()
	ns := ca.db.issued[len(ca.db.issued)-1]
	keyPath := filepath.Join(dir, "certs", ns+".key")

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key permissions: got %o, want %o", info.Mode().Perm(), 0600)
	}
}

func TestGenerateExportCertKey_SerialRegisteredInDB(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}

	wi, err := ca.db.wasIssued(getSerial(cert))
	if err != nil {
		t.Fatalf("can not convert serial %s", getSerial(cert))
	}
	if !wi {
		t.Error("serial not registered in DB after issuance")
	}
}

func TestGenerateExportCertKey_SerialsPersistAcrossLoad(t *testing.T) {
	ca, dir := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	serial := getSerial(cert)

	loaded, err := LoadCA(
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "ca.cert"),
		filepath.Join(dir, "ca.db"),
		filepath.Join(dir, "ca.crl"),
		filepath.Join(dir, "certs"),
	)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}
	wi, err := loaded.db.wasIssued(serial)
	if err != nil {
		t.Fatalf("can not convert serial %s", getSerial(cert))
	}
	if !wi {
		t.Error("serial not registered in DB after issuance")
	}
}

// --- Revoke / IsRevoked ---

func TestRevoke_MarksSerialRevoked(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	serial := getSerial(cert)

	if err := ca.Revoke(serial, "keyCompromise"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if !ca.IsRevoked(serial) {
		t.Error("serial should be revoked")
	}
}

func TestCARevoke_PersistsAcrossLoad(t *testing.T) {
	ca, dir := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	serial := getSerial(cert)

	if err := ca.Revoke(serial, "keyCompromise"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	loaded, err := LoadCA(
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "ca.cert"),
		filepath.Join(dir, "ca.db"),
		filepath.Join(dir, "ca.crl"),
		filepath.Join(dir, "certs"),
	)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}
	if !loaded.IsRevoked(serial) {
		t.Error("revocation not persisted after CA reload")
	}
}

func TestCARevoke_FailsOnDuplicate(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	serial := getSerial(cert)

	if err := ca.Revoke(serial, "keyCompromise"); err != nil {
		t.Fatalf("first Revoke failed: %v", err)
	}
	if err := ca.Revoke(serial, "keyCompromise"); err == nil {
		t.Fatal("expected error on duplicate Revoke, got nil")
	}
}

// --- VerifyCert ---

func TestVerifyCert_ValidCert(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}

	ok, err := VerifyCert(cert, ca.certificate, ca.crl)
	if !ok || err != nil {
		t.Errorf("expected valid cert, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyCert_RevokedCert(t *testing.T) {
	ca, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}

	if err := ca.Revoke(getSerial(cert), "keyCompromise"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	ok, err := VerifyCert(cert, ca.certificate, ca.crl)
	if ok || err == nil {
		t.Error("expected revoked cert to fail verification")
	}
}

func TestVerifyCert_WrongCA(t *testing.T) {
	ca, _ := tempCA(t)
	ca2, _ := tempCA(t)

	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}

	// verify cert from ca against ca2 — should fail
	ok, err := VerifyCert(cert, ca2.certificate, ca2.crl)
	if ok || err == nil {
		t.Error("expected verification failure against wrong CA")
	}
}

// --- helpers ---

func TestGetSerial_ReturnsNonEmpty(t *testing.T) {
	ca, _ := tempCA(t)
	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	if getSerial(cert) == "" {
		t.Error("getSerial returned empty string")
	}
}

func TestIsCA_TrueForCAFalseForLeaf(t *testing.T) {
	ca, _ := tempCA(t)
	if !isCA(ca.certificate) {
		t.Error("CA certificate should return true for isCA")
	}
	cert, err := ca.GenerateExportCertKey("svc.internal", "backend", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	if isCA(cert) {
		t.Error("leaf certificate should return false for isCA")
	}
}

func TestCertType_ReturnsOU(t *testing.T) {
	ca, _ := tempCA(t)
	cert, err := ca.GenerateExportCertKey("svc.internal", "myunit", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("GenerateExportCertKey failed: %v", err)
	}
	if certType(cert) != "myunit" {
		t.Errorf("certType: got %q, want %q", certType(cert), "myunit")
	}
}

// --- integration ---

func TestIntegration_FullLifecycle(t *testing.T) {
	ca, dir := tempCA(t)

	// issue server + client cert
	server, err := ca.GenerateExportCertKey("api.internal", "api", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	client, err := ca.GenerateExportCertKey("client-a", "ops", nil, nil, time.Hour*24, false)
	if err != nil {
		t.Fatalf("issue client cert: %v", err)
	}

	// both verify
	if ok, err := VerifyCert(server, ca.certificate, ca.crl); !ok {
		t.Errorf("server cert should be valid: %v", err)
	}
	if ok, err := VerifyCert(client, ca.certificate, ca.crl); !ok {
		t.Errorf("client cert should be valid: %v", err)
	}

	// correct EKU separation
	if !isServer(server) {
		t.Error("server cert missing ServerAuth EKU")
	}
	if isServer(client) {
		t.Error("client cert should not have ServerAuth EKU")
	}

	// revoke server cert
	if err := ca.Revoke(getSerial(server), "keyCompromise"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, _ := VerifyCert(server, ca.certificate, ca.crl); ok {
		t.Error("revoked cert should not verify")
	}
	// client still valid
	if ok, err := VerifyCert(client, ca.certificate, ca.crl); !ok {
		t.Errorf("client cert should still be valid: %v", err)
	}

	// reload CA and verify state is fully persisted
	loaded, err := LoadCA(
		filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "ca.cert"),
		filepath.Join(dir, "ca.db"),
		filepath.Join(dir, "ca.crl"),
		filepath.Join(dir, "certs"),
	)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}

	if !loaded.IsRevoked(getSerial(server)) {
		t.Error("revocation not persisted")
	}
	wi, err := loaded.db.wasIssued(getSerial(server))
	if err != nil {
		t.Fatalf("can not convert serial %s", getSerial(server))
	}
	if !wi {
		t.Error("server serial not registered in DB after issuance")
	}
	wi, err = loaded.db.wasIssued(getSerial(client))
	if err != nil {
		t.Fatalf("can not convert serial %s", getSerial(client))
	}
	if !wi {
		t.Error("client serial not registered in DB after issuance")
	}

	// issue a third cert from reloaded CA — proves serial counter continues correctly
	third, err := loaded.GenerateExportCertKey("svc-b", "infra", nil, nil, time.Hour*24, true)
	if err != nil {
		t.Fatalf("issue from reloaded CA: %v", err)
	}
	if ok, err := VerifyCert(third, loaded.certificate, loaded.crl); !ok {
		t.Errorf("third cert should verify: %v", err)
	}
}
