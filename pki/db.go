package pki

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const HEADER_CADB = "CA DB"

type CADB struct {
	Path   string
	issued []string
}

func NewCADB(path string) (*CADB, error) {
	db := &CADB{
		Path:   path,
		issued: make([]string, 0),
	}

	//create dir structure
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("[pki/db/newCADB] create directory: %w", err)
	}

	//check if already exists + create file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("[pki/db/newCADB]DB file already exists: %w", err)
		} else {
			return nil, fmt.Errorf("[pki/db/newCADB]error creating DB file: %w", err)
		}
	}
	defer f.Close()

	if _, err = f.WriteString(HEADER_CADB + "\n"); err != nil {
		return nil, fmt.Errorf("[pki/db/newCADB] write DB header: %w", err)
	}

	return db, nil
}

func LoadCADB(path string) (*CADB, error) {
	db := &CADB{
		Path:   path,
		issued: make([]string, 0),
	}

	//load file
	fb, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("[pki/db/loadCADB] read DB file: %w", err)
	}
	fLines := strings.Split(string(fb), "\n")

	//check header
	hLine := strings.TrimSpace(fLines[0])
	if !strings.HasPrefix(hLine, HEADER_CADB) {
		return nil, fmt.Errorf("[pki/db/loadCADB] invalid header: %s != %s", hLine, HEADER_CADB)
	}

	//fill issued list
	if len(fLines) == 1 {
		return db, nil
	}

	for i := 1; i < len(fLines); i++ {
		line := strings.TrimSpace(fLines[i])
		if line == "" {
			continue
		}

		db.issued = append(db.issued, line)
	}

	return db, nil
}

func (db *CADB) nextSerial() (string, error) {
	//get last serial
	if len(db.issued) == 0 {
		return "1", nil
	}

	lastSerial := db.issued[len(db.issued)-1]
	intSerial, err := strconv.Atoi(lastSerial)
	if err != nil {
		return "", fmt.Errorf("[pki/db/nextSerial] convert serial: %w", err)
	}

	return strconv.Itoa(intSerial + 1), nil
}

func (db *CADB) issue(serial string) error {
	//check if already issued

	if wi, err := db.wasIssued(serial); err != nil || wi {
		return fmt.Errorf("[pki/db/issue] already issued: %s", serial)
	}

	//issue in memory
	db.issued = append(db.issued, serial)

	//issue in file
	f, err := os.OpenFile(db.Path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("[pki/db/issue] open file: %w", err)
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", serial)
	if err != nil {
		return fmt.Errorf("[pki/db/issue] write to file: %w", err)
	}

	return nil
}

func (db *CADB) wasIssued(serial string) (bool, error) {
	sInt, err := strconv.Atoi(serial)
	if err != nil {
		return false, fmt.Errorf("[pki/db/wasIssued] cant convert serial: %w", err)
	}

	for _, r := range db.issued {
		rInt, err := strconv.Atoi(r)
		if err != nil {
			return false, fmt.Errorf("[pki/db/wasIssued] cant convert serial: %w", err)
		}

		if sInt == rInt {
			return true, nil
		}
	}

	return false, nil
}
