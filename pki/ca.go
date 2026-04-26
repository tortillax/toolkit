package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"strconv"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

const TYPE_CA_KEY = "CA KEY"
const TYPE_CA_CERT = "CERTIFICATE"

const TYPE_CERT = "CERTIFICATE"
const TYPE_KEY = "KEY"

type CA struct {
	privateKey  *ecdsa.PrivateKey
	certificate *x509.Certificate
	db          *CADB
	crl         *CRL

	PathCert    string
	PathKey     string
	PathCertDir string
}

type CAConfig struct {
	SerialNumber big.Int
	Subject      pkix.Name
	Validity     time.Duration

	PathCert    string
	PathKey     string
	PathDB      string
	PathCRL     string
	PathCertDir string
}

func (conf *CAConfig) SetMultiPath(multiPath string) {
	conf.PathCert = path.Join(multiPath, "ca.cert")
	conf.PathKey = path.Join(multiPath, "ca.key")
	conf.PathDB = path.Join(multiPath, "ca.db")
	conf.PathCRL = path.Join(multiPath, "ca.crl")
	conf.PathCertDir = path.Join(multiPath, "certs")
}

func DefaultConfig(commonName string) CAConfig {
	cac := CAConfig{
		SerialNumber: *big.NewInt(959595),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Validity: time.Hour * 24 * 365 * 10,
	}
	cac.SetMultiPath("ca")

	return cac
}

func NewCA(config CAConfig) (*CA, error) {
	//priv key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/newCA] generate key: %w", err)
	}

	//pub key + hash
	pub, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/newCA] marshal pubkey: %w", err)
	}
	pubHash := sha1.Sum(pub)

	//cert template
	tpl := x509.Certificate{
		SerialNumber:          &config.SerialNumber,
		Subject:               config.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(config.Validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		SubjectKeyId:          pubHash[:],
	}

	//create cert
	certBytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/newCA] create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/newCA] parse certificate: %w", err)
	}

	crl, err := NewCRL(config.PathCRL)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/newCA] new CRL: %w", err)
	}

	db, err := NewCADB(config.PathDB)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/newCA] new CADB: %w", err)
	}

	ca := &CA{
		privateKey:  priv,
		certificate: cert,
		crl:         crl,
		db:          db,

		PathCert:    config.PathCert,
		PathKey:     config.PathKey,
		PathCertDir: config.PathCertDir,
	}
	return ca, nil
}

func LoadCA(pathKey, pathCert, pathDB, pathCRL, pathCertDir string) (*CA, error) {
	//load cert
	certPEM, err := os.ReadFile(pathCert)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] read cert file: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] decode cert PEM: no valid block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] parse certificate: %w", err)
	}

	//load key
	keyPEM, err := os.ReadFile(pathKey)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] read key file: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] decode key PEM: no valid block found")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] parse EC private key: %w", err)
	}

	//create CA object
	db, err := LoadCADB(pathDB)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] load DB: %w", err)
	}
	crl, err := LoadCRL(pathCRL)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/loadCA] load CRL: %w", err)
	}

	return &CA{
		certificate: cert,
		privateKey:  key,
		db:          db,
		crl:         crl,

		PathCert:    pathCert,
		PathKey:     pathKey,
		PathCertDir: pathCertDir,
	}, nil
}

func (ca *CA) SaveCertKey() error {
	//create dir structure
	if err := os.MkdirAll(ca.PathCertDir, 0755); err != nil {
		return fmt.Errorf("[pki/ca/saveCertKey] create directory: %w", err)
	}

	//save key
	//marshal key
	keyBytes, err := x509.MarshalECPrivateKey(ca.privateKey)
	if err != nil {
		return fmt.Errorf("[pki/ca/saveCertKey] marshal CA key: %w", err)
	}
	//create key PEM block
	keyBlock := pem.Block{
		Type:  TYPE_CA_KEY,
		Bytes: keyBytes,
	}
	//create new file
	f, err := os.OpenFile(ca.PathKey, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("[pki/ca/saveCertKey] key file already exists: %w", err)
		} else {
			return fmt.Errorf("[pki/ca/saveCertKey] error creating key file: %w", err)
		}
	}
	defer f.Close()
	//write the key PEM block
	if err := pem.Encode(f, &keyBlock); err != nil {
		return fmt.Errorf("[pki/ca/saveCertKey] error writing key PEM block: %w", err)
	}

	//save cert
	//create cert PEM block
	certBlock := pem.Block{
		Type:  TYPE_CA_CERT,
		Bytes: ca.certificate.Raw,
	}
	//create new file
	f, err = os.OpenFile(ca.PathCert, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("[pki/ca/saveCertKey] cert file already exists: %w", err)
		} else {
			return fmt.Errorf("[pki/ca/saveCertKey] error creating cert file: %w", err)
		}
	}
	defer f.Close()
	//write the key PEM block
	if err := pem.Encode(f, &certBlock); err != nil {
		return fmt.Errorf("error writing cert PEM block: %w", err)
	}

	return nil
}

func (ca *CA) GenerateExportCertKey(name, certType string, dnsNames []string, ips []net.IP, validity time.Duration, isServer bool) (*x509.Certificate, error) {
	// generate key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/issueCert] generate key: %w", err)
	}

	//next serial
	ns, err := ca.db.nextSerial()
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/issueCert] next serial: %w", err)
	}

	//register
	if err = ca.db.issue(ns); err != nil {
		return nil, fmt.Errorf("[pki/ca/issueCert] register: %w", err)
	}

	//cert template
	now := time.Now()
	sn, err := serialBigInt(ns)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/generateExportCertKey] convert serial: %w", err)
	}

	ku := []x509.ExtKeyUsage{}
	if isServer {
		ku = append(ku, x509.ExtKeyUsageServerAuth)
	} else {
		ku = append(ku, x509.ExtKeyUsageClientAuth)
	}

	tpl := &x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:         name,
			OrganizationalUnit: []string{certType},
		},
		NotBefore:   now,
		NotAfter:    now.Add(validity),
		DNSNames:    dnsNames,
		IPAddresses: ips,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: ku,
	}

	//sign
	certBytes, err := x509.CreateCertificate(rand.Reader, tpl, ca.certificate, &key.PublicKey, ca.privateKey)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/generateExportKey] create certificate: %w", err)
	}

	//parse
	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/generateExportKey] parse certificate: %w", err)
	}

	//export
	pathCert := path.Join(ca.PathCertDir, ns+".crt")
	if err := writeCertPEM(pathCert, crt.Raw); err != nil {
		return nil, fmt.Errorf("[pki/ca/issueCert] write cert PEM: %w", err)
	}
	pathKey := path.Join(ca.PathCertDir, ns+".key")
	if err := writeKeyPEM(pathKey, key); err != nil {
		return nil, fmt.Errorf("[pki/ca/issueCert] write key PEM: %w", err)
	}

	return crt, nil
}

func (ca *CA) Revoke(serial, reason string) error {
	wi, err := ca.db.wasIssued(serial)
	if err != nil {
		return fmt.Errorf("[pki/ca/revoke] can not convert serial %s to int: %w", serial, err)
	}
	if !wi {
		return fmt.Errorf("[pki/ca/revoke] %s was never issued", serial)
	}

	return ca.crl.revoke(serial, reason)
}

func (ca *CA) IsRevoked(serial string) bool {
	return ca.crl.isRevoked(serial)
}

func (ca *CA) PathDB() string {
	return ca.db.Path
}

func (ca *CA) PathCRL() string {
	return ca.crl.Path
}

func serialBigInt(serial string) (*big.Int, error) {
	sInt, err := strconv.Atoi(serial)
	if err != nil {
		return nil, fmt.Errorf("[pki/ca/serialBigInt] convert: %w", err)
	}

	return big.NewInt(int64(sInt)), nil
}

func writeCertPEM(path string, certBytes []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("[pki/ca/writeCertPem] open cert file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  TYPE_CERT,
		Bytes: certBytes,
	})
}

func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("[pki/ca/writeKey] marshal EC key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("[pki/ca/writeKey] open key file: %w", err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  TYPE_KEY,
		Bytes: keyBytes,
	})
}

func VerifyCert(cert, ca *x509.Certificate, crl *CRL) (bool, error) {
	//crl
	if crl.isRevoked(getSerial(cert)) {
		return false, fmt.Errorf("[pki/ca/verifyCert] CRL - %s(%s) is revoked", cert.Subject.CommonName, getSerial(cert))
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca)

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       rootPool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return false, fmt.Errorf("[pki/ca/verifyCert] cerify: %w", err)
	}

	return true, nil
}

func getSerial(cert *x509.Certificate) string {
	return cert.SerialNumber.String()
}

func isServer(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func isCA(cert *x509.Certificate) bool {
	return cert.IsCA
}

func certType(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return ""
	}
	return cert.Subject.OrganizationalUnit[0]
}

func ReadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[pki/ReadCert] read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("[pki/ReadCert] no valid PEM block found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[pki/ReadCert] parse certificate: %w", err)
	}

	return cert, nil
}

func ReadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[pki/ReadKey] read file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("[pki/ReadKey] no valid PEM block found in %s", path)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[pki/ReadKey] parse EC private key: %w", err)
	}

	return key, nil
}

func CombineCertKeyFile(certPath, keyPath, outPath, password string) error {
	cert, err := ReadCert(certPath)
	if err != nil {
		return fmt.Errorf("[pki/ca/combineCertKeyFile] read cert: %w", err)
	}

	key, err := ReadKey(keyPath)
	if err != nil {
		return fmt.Errorf("[pki/ca/combineCertKeyFile] read key: %w", err)
	}

	p12Data, err := pkcs12.Modern.Encode(key, cert, nil, password)
	if err != nil {
		return fmt.Errorf("[pki/ca/combineCertKeyFile] encode p12: %w", err)
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("[pki/ca/combineCertKeyFile] create output file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(p12Data); err != nil {
		return fmt.Errorf("[pki/ca/combineCertKeyFile] write p12: %w", err)
	}

	return nil
}
