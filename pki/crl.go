package pki

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const HEADER_CRL = "CA CRL"
const SEPARATOR = ":#:"

type CRL struct {
	Path    string
	revoked []CRLRecord
}

type CRLRecord struct {
	Serial string
	Reason string
}

func NewCRL(path string) (*CRL, error) {
	crl := &CRL{
		Path:    path,
		revoked: make([]CRLRecord, 0),
	}

	//create dir structure
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && err != os.ErrExist {
		return nil, fmt.Errorf("[pki/crl/newCRL] create directory: %w", err)
	}

	//check if already exists + create file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("[pki/crl/newCRL]CRL file already exists: %w", err)
		} else {
			return nil, fmt.Errorf("[pki/crl/newCRL]error creating CRL file: %w", err)
		}
	}
	defer f.Close()

	if _, err = f.WriteString(HEADER_CRL + "\n"); err != nil {
		return nil, fmt.Errorf("[pki/crl/newCRL] write CRL header: %w", err)
	}

	return crl, nil
}

func LoadCRL(path string) (*CRL, error) {
	crl := &CRL{
		Path:    path,
		revoked: make([]CRLRecord, 0),
	}

	//load file
	fb, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[pki/crl/loadCRL] read CRL file: %w", err)
	}
	fLines := strings.Split(string(fb), "\n")

	//check header
	hLine := strings.TrimSpace(fLines[0])
	if !strings.HasPrefix(hLine, HEADER_CRL) {
		return nil, fmt.Errorf("[pki/crl/loadCRL] invalid header: %s != %s", hLine, HEADER_CRL)
	}

	//fill revocation list
	if len(fLines) == 1 {
		return crl, nil
	}

	for i := 1; i < len(fLines); i++ {
		line := strings.TrimSpace(fLines[i])

		//skip invalid line, missing separator
		if !strings.Contains(line, SEPARATOR) {
			continue
		}

		lineSplit := strings.Split(line, SEPARATOR)
		crl.revoked = append(crl.revoked, CRLRecord{
			Serial: lineSplit[0],
			Reason: lineSplit[1],
		})
	}

	return crl, nil
}

func (crl *CRL) revoke(serial, reason string) error {
	//check if already revoked
	if crl.isRevoked(serial) {
		return fmt.Errorf("[pki/crl/revoke] already revoked: %s", serial)
	}

	rr := CRLRecord{
		Serial: serial,
		Reason: reason,
	}

	//revoke in memory
	crl.revoked = append(crl.revoked, rr)

	//revoke in file
	f, err := os.OpenFile(crl.Path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("[pki/crl/revoke] open file: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s%s%s\n", serial, SEPARATOR, reason)
	if err != nil {
		return fmt.Errorf("[pki/crl/revoke] write to file: %w", err)
	}

	return nil
}

func (crl *CRL) isRevoked(serial string) bool {
	for _, r := range crl.revoked {
		if r.Serial == serial {
			return true
		}
	}

	return false
}
