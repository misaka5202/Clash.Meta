package snifake

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestSignerLeafVerify(t *testing.T) {
	s, err := NewSelfSignedRoot()
	if err != nil {
		t.Fatalf("root: %v", err)
	}

	cert, err := s.LeafFor("pixiv.net")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.ChainDER[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "pixiv.net" {
		t.Fatalf("bad CN: %s", leaf.Subject.CommonName)
	}
	found := false
	for _, n := range leaf.DNSNames {
		if n == "pixiv.net" {
			found = true
		}
	}
	if !found {
		t.Fatal("SAN missing pixiv.net")
	}

	// chain must verify against the root for pixiv.net
	inter := x509.NewCertPool()
	inter.AddCert(s.root)
	opts := x509.VerifyOptions{DNSName: "pixiv.net", Roots: s.VerifyPool(), Intermediates: inter}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	// cache must return the same object
	c2, _ := s.LeafFor("pixiv.net")
	if c2 != cert {
		t.Fatal("leaf not cached")
	}

	// root PEM must be parseable
	block, _ := pem.Decode([]byte(s.RootPEM()))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("bad root pem")
	}
	rc, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !rc.IsCA {
		t.Fatalf("root not CA / parse: %v", err)
	}
}

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()
	s1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, rootCertFile)); err != nil {
		t.Fatalf("root cert not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, rootKeyFile)); err != nil {
		t.Fatalf("root key not written: %v", err)
	}
	s2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if s1.RootPEM() != s2.RootPEM() {
		t.Fatal("root CA changed across reload; persistence broken")
	}
}
