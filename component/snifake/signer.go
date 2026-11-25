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
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	// DirName is the directory (under the mihomo home dir) that stores the
	// persisted root CA. Clients install <DirName>/root.crt into their trust
	// store once; the file is shared over the filesystem with the GUI.
	DirName = "sni-mitm"

	rootCertFile = "root.crt"
	rootKeyFile  = "root.key"
)

// Dir returns the directory holding the persisted root CA, or "" when the
// mihomo home directory is not known yet.
func Dir() string {
	home := C.Path.HomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, DirName)
}

// CertPath returns the path of the exported root certificate (PEM), or "" when
// the home directory is unknown. GUIs read this file to install the CA.
func CertPath() string {
	if d := Dir(); d != "" {
		return filepath.Join(d, rootCertFile)
	}
	return ""
}

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

// LoadOrCreate loads the persisted root CA from dir, generating and saving a
// fresh one when it is missing. When dir is empty the CA is kept memory-only.
// Persisting the root means the user installs the trust anchor once, and it
// keeps working across restarts.
func LoadOrCreate(dir string) (*Signer, error) {
	if dir != "" {
		s, err := loadSigner(dir)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			// corrupt or unreadable: fall through and regenerate
			_ = os.Remove(filepath.Join(dir, rootCertFile))
			_ = os.Remove(filepath.Join(dir, rootKeyFile))
		}
	}
	s, err := NewSelfSignedRoot()
	if err != nil {
		return nil, err
	}
	if dir != "" {
		if err := s.save(dir); err != nil {
			return s, err
		}
	}
	return s, nil
}

func loadSigner(dir string) (*Signer, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, rootCertFile))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, rootKeyFile))
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("sni-mitm: malformed persisted root CA")
	}
	root, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("sni-mitm: persisted root key is not ECDSA")
	}
	return &Signer{root: root, rootK: key, cache: map[string]*Cert{}}, nil
}

// save writes the root certificate and its private key to dir.
func (s *Signer) save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.root.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(s.rootK)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, rootCertFile), certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, rootKeyFile), keyPEM, 0o600)
}

// Prepare ensures the root CA exists and that its certificate has been
// exported to the home directory, so a GUI can install it into the trust store
// even before the first MITM connection happens. It is idempotent.
func Prepare() error {
	_, err := EnsureSigner()
	return err
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
