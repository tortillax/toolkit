package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tortillax/toolkit/pki"
)

const usage = `ca - simple certificate authority

commands:
  init   <cn>                          						generate new CA
  issue  <name> <type> <days> <mode> [dns1,dns2] [ip1,ip2]  issue certificate  (mode: server|client)
  revoke <serial> <reason>						            revoke certificate
  bundle <serial>                      						create browser-importable p12 bundle

examples:
  ca init "My CA"
  ca issue api.internal backend 365 server api.internal,api.local 192.168.1.1
  ca issue client-a ops 365 client
  ca revoke 1 keyCompromise
  ca bundle 1
`

var caDir string

func main() {
	flag.StringVar(&caDir, "dir", "ca", "CA base directory")
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Print(usage)
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	args := flag.Args()[1:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "issue":
		err = cmdIssue(args)
	case "revoke":
		err = cmdRevoke(args)
	case "bundle":
		err = cmdBundle(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: ca init <cn>")
	}
	cn := args[0]

	cfg := pki.DefaultConfig(cn)
	cfg.SetMultiPath(caDir)
	ca, err := pki.NewCA(cfg)
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}
	if err := ca.SaveCertKey(); err != nil {
		return fmt.Errorf("save CA: %w", err)
	}

	fmt.Printf("CA initialised\n  cert: %s\n  key:  %s\n", cfg.PathCert, cfg.PathKey)
	return nil
}

func cmdIssue(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("usage: ca issue <name> <type> <days> <server|client> [dns,...] [ip,...]")
	}
	name, certType, daysStr, mode := args[0], args[1], args[2], args[3]

	days, err := time.ParseDuration(daysStr + "h")
	if err != nil || days <= 0 {
		return fmt.Errorf("invalid days: %s", daysStr)
	}
	validity := days * 24

	isServer := false
	switch mode {
	case "server":
		isServer = true
	case "client":
		// client certs don't need SANs
	default:
		return fmt.Errorf("mode must be server or client, got: %s", mode)
	}

	var dnsNames []string
	var ips []net.IP

	if len(args) > 4 {
		dnsNames = strings.Split(args[4], ",")
	}
	if len(args) > 5 {
		for _, s := range strings.Split(args[5], ",") {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				return fmt.Errorf("invalid IP: %s", s)
			}
			ips = append(ips, ip)
		}
	}

	ca, err := loadCA()
	if err != nil {
		return err
	}

	cert, err := ca.GenerateExportCertKey(name, certType, dnsNames, ips, validity, isServer)
	if err != nil {
		return fmt.Errorf("issue cert: %w", err)
	}

	fmt.Printf("certificate issued\n  cn:     %s\n  serial: %s\n  type:   %s\n  mode:   %s\n",
		name, cert.SerialNumber.String(), certType, mode)
	return nil
}

func cmdRevoke(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: ca revoke <serial> <reason>")
	}
	serial, reason := args[0], args[1]

	ca, err := loadCA()
	if err != nil {
		return err
	}

	if err := ca.Revoke(serial, reason); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	fmt.Printf("revoked serial %s (reason: %s)\n", serial, reason)
	return nil
}

func cmdBundle(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: ca bundle <serial> [password]")
	}
	serial := args[0]
	password := ""
	if len(args) == 2 {
		password = args[1]
	}

	cfg := pki.DefaultConfig("")
	cfg.SetMultiPath(caDir)
	certPath := cfg.PathCertDir + "/" + serial + ".crt"
	keyPath := cfg.PathCertDir + "/" + serial + ".key"
	outPath := cfg.PathCertDir + "/" + serial + ".p12"

	if err := pki.CombineCertKeyFile(certPath, keyPath, outPath, password); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}

	fmt.Printf("bundle created\n  file: %s\n", outPath)
	return nil
}

func loadCA() (*pki.CA, error) {
	cfg := pki.DefaultConfig("")
	cfg.SetMultiPath(caDir)
	ca, err := pki.LoadCA(cfg.PathKey, cfg.PathCert, cfg.PathDB, cfg.PathCRL, cfg.PathCertDir)
	if err != nil {
		return nil, fmt.Errorf("load CA (run 'ca init' first?): %w", err)
	}
	return ca, nil
}
