// signer.go implements a minimal dynamic CA for the SNI-MITM path: a
// self-signed root that is kept in memory, plus an on-the-fly leaf issuer that
// mints a certificate matching the real destination domain. The leaf chains to
// the root, so any client app that trusts the exported root certificate will
// validate the MITM connection WITHOUT "ignore-certificate-errors" — the
// upgrade over the plain SNI-rewrite path.
package snifake

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"time"
)

// Cert is one issued leaf: chain (leaf first, then root) plus the leaf's
// private key, ready to be wrapped into a utls/tls server certificate.
type Cert struct {
	ChainDER [][]byte
	LeafKey  *ecdsa.PrivateKey
}

// Signer holds the in-memory root CA and caches issued leaves per host.
type Signer struct {
	root  *x509.Certificate
	rootK *ecdsa.PrivateKey
	mu    sync.Mutex
	cache map[string]*Cert
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// NewSelfSignedRoot generates a fresh ECDSA P-256 self-signed CA in memory.
// It is intentionally non-persistent (write-to-play): a new root is created on
// every process start, so the exported RootPEM must be re-installed after each
// restart unless you add persistence.
func NewSelfSignedRoot() (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mihomo sni-mitm root", Organization: []string{"mihomo"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Signer{root: root, rootK: key, cache: map[string]*Cert{}}, nil
}

// RootPEM returns the root certificate in PEM form, for installing into the
// system / app trust store.
func (s *Signer) RootPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.root.Raw}))
}

// LeafFor issues (or returns cached) a leaf certificate valid for host, signed
// by the root. host must be a DNS name (no IP handling in this write-up).
func (s *Signer) LeafFor(host string) (*Cert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cache[host]; ok {
		return c, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.root, &key.PublicKey, s.rootK)
	if err != nil {
		return nil, err
	}
	cert := &Cert{
		ChainDER: [][]byte{der, s.root.Raw},
		LeafKey:  key,
	}
	s.cache[host] = cert
	return cert, nil
}

// VerifyPool exposes the root as a cert pool so callers/tests can validate
// issued leaves against it.
func (s *Signer) VerifyPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.root)
	return pool
}
