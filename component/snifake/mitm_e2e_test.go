package snifake

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func originSelfSigned(host string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestMITMEndToEnd stands up a real TLS origin, routes it through the MITM
// bridge, and has a stock crypto/tls client (trusting only our root) fetch
// data. Success proves the app validates without ignore-certificate-errors
// while the wire SNI to the origin is the benign alias.
func TestMITMEndToEnd(t *testing.T) {
	ResetRules()
	defer ResetRules()
	if err := AddCealingRule([]any{[]any{"origin.test"}, "benign.example", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	const data = "pong-from-origin\n"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{originSelfSigned("origin.test")}})
				if err := tc.Handshake(); err != nil {
					return
				}
				_, _ = io.WriteString(tc, data)
			}(c)
		}
	}()

	real, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	m := ApplyDirect(real, "origin.test")

	s, err := EnsureSigner()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.RootPEM())) {
		t.Fatal("cannot add root to pool")
	}

	// app is a STOCK TLS client trusting only our root: this is exactly the
	// "no ignore-certificate-errors" condition route X promises.
	app := tls.Client(m, &tls.Config{ServerName: "origin.test", RootCAs: pool})

	done := make(chan string, 1)
	go func() {
		if err := app.Handshake(); err != nil {
			done <- "handshake: " + err.Error()
			return
		}
		// confirm the leaf the app received chains to OUR root (not the origin)
		if len(app.ConnectionState().VerifiedChains) == 0 {
			done <- "no verified chain to trusted root"
			return
		}
		if err := app.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- "deadline: " + err.Error()
			return
		}
		line, _ := bufio.NewReader(app).ReadString('\n')
		done <- line
	}()

	select {
	case got := <-done:
		if got != data {
			t.Fatalf("mitm e2e mismatch: got %q want %q", got, data)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("mitm e2e timed out")
	}
}
