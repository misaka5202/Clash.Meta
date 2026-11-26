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

// originWithALPN is a TLS server that records the negotiated ALPN protocol.
func originWithALPN(t *testing.T, gotProto chan<- string) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "origin.test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{"origin.test", "benign.example"},
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		tc := tls.Server(c, &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err := tc.Handshake(); err != nil {
			return
		}
		select {
		case gotProto <- tc.ConnectionState().NegotiatedProtocol:
		default:
		}
		_, _ = io.WriteString(tc, "ok\n")
	}
}

// TestALPNNegotiatedEndToEnd proves the bridge negotiates the application's
// proposed ALPN protocol instead of silently dropping it. A client that
// offers "h2" must come back with "h2" negotiated on BOTH ends, otherwise
// browsers abort with http2_handshake_failed.
func TestALPNNegotiatedEndToEnd(t *testing.T) {
	ResetRules()
	defer ResetRules()
	if err := AddCealingRule([]any{[]any{"origin.test"}, "benign.example", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	gotProto := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handler := originWithALPN(t, gotProto)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(c)
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

	// the app offers "h2" first, exactly like a browser
	app := tls.Client(m, &tls.Config{
		ServerName: "origin.test",
		RootCAs:    pool,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := app.Handshake(); err != nil {
		t.Fatal("app handshake:", err)
	}
	if got := app.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("app negotiated %q, want %q", got, "h2")
	}
	line, _ := bufio.NewReader(app).ReadString('\n')
	if line != "ok\n" {
		t.Fatalf("payload mismatch: %q", line)
	}
	select {
	case p := <-gotProto:
		if p != "h2" {
			t.Fatalf("origin negotiated %q, want %q", p, "h2")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin never reported an ALPN protocol")
	}
}

// TestALPNAbsentFallsBackToHTTP11 proves a client that proposes no ALPN is
// still served (HTTP/1.1 style) instead of failing the handshake.
func TestALPNAbsentFallsBackToHTTP11(t *testing.T) {
	ResetRules()
	defer ResetRules()
	if err := AddCealingRule([]any{[]any{"origin.test"}, "benign.example", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

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
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				tmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "origin.test"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					BasicConstraintsValid: true,
					DNSNames:              []string{"origin.test"},
				}
				der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{
					Certificate: [][]byte{der}, PrivateKey: key,
				}}})
				if err := tc.Handshake(); err != nil {
					return
				}
				_, _ = io.WriteString(tc, "ok\n")
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
	pool.AppendCertsFromPEM([]byte(s.RootPEM()))
	app := tls.Client(m, &tls.Config{ServerName: "origin.test", RootCAs: pool})
	if err := app.Handshake(); err != nil {
		t.Fatal("app handshake:", err)
	}
	if got := app.ConnectionState().NegotiatedProtocol; got != "" {
		t.Fatalf("negotiated %q, want empty", got)
	}
	line, _ := bufio.NewReader(app).ReadString('\n')
	if line != "ok\n" {
		t.Fatalf("payload mismatch: %q", line)
	}
}
