package main

import (
	"log"

	"github.com/tortillax/toolkit/pki"
)

func main() {
	/*
		pathCACert := flag.String("cert", "ca.cert", "path to the CA certificate")
		pathCAKey := flag.String("key", "ca.key", "path to the CA key")
		pathCADB := flag.String("db", "ca.db", "path to the CA database")
		pathCRL := flag.String("crl", "ca.crl", "path to the CRL")
		pathCertDir := flag.String("certdir", "certs", "path to the directory where end certificates will be generated")
		flag.Parse()
	*/

	ca, err := pki.NewCA(pki.DefaultConfig("test CA"))
	if err != nil {
		log.Fatalf("error creating new ca: %s\n", err.Error())
	}

	if err = ca.SaveCertKey(); err != nil {
		log.Fatalf("fatal error exporting CA cert and key: %s\n", err.Error())
	}

	if err = ca.Revoke("ABCDEF", "he baaad"); err != nil {
		log.Fatalf("fatal error revoking: %s\n", err.Error())
	}

	if ca.IsRevoked("ABCDEF") {
		log.Printf("ye boi he gone\n")
	}
}
