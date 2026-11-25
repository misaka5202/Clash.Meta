package snifake

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRealCealingHost exercises the shipped upstream rule file end to end so a
// format regression in the wild fails the build.
func TestRealCealingHost(t *testing.T) {
	for _, name := range []string{"Cealing-Host.json", "Cealing-Host-R.json"} {
		path := filepath.Join("testdata", name)
		rules, err := LoadRulesFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rules) < 50 {
			t.Fatalf("%s: suspiciously few rules (%d)", name, len(rules))
		}

		ResetRules()
		added := 0
		for _, r := range rules {
			if err := AddCealingRule(r); err == nil {
				added++
			}
		}
		if added < len(rules)/2 {
			t.Fatalf("%s: only %d/%d rules usable", name, added, len(rules))
		}

		// every installed rule must be able to answer a plan and must carry
		// either an SNI action or a pinned destination
		for _, r := range getRules() {
			// an exact pattern must match itself; a starred one must also
			// match a subdomain of its base
			pat := r.patterns[0].positive
			host := pat
			if strings.HasPrefix(pat, "*") {
				host = "sub." + strings.TrimLeft(pat, "*.")
			}
			if host == "sub." {
				continue
			}
			if _, ok := PlanFor(host); !ok {
				t.Fatalf("%s: pattern %q does not match %q", name, r.patterns[0].positive, host)
			}
			if r.dst.address() == "" && r.mode == ModeAlias && r.alias == "" {
				t.Fatalf("%s: rule with no action", name)
			}
		}
		ResetRules()
	}
}

// TestRealCealingHostBehaviour checks the three SNI modes and IP pinning as
// they appear in the upstream file.
func TestRealCealingHostBehaviour(t *testing.T) {
	rules, err := LoadRulesFile(filepath.Join("testdata", "Cealing-Host.json"))
	if err != nil {
		t.Fatal(err)
	}
	ResetRules()
	defer ResetRules()
	for _, r := range rules {
		_ = AddCealingRule(r)
	}

	cases := []struct {
		host     string
		wantMode Mode
		wantSNI  string
		wantDial string
		needDial bool
	}{
		{"www.youtube.com", ModeAlias, "g.cn", "", false},
		{"i.pximg.net", ModeRandom, "", "210.140.139.133", true},
		{"r1.sn.googlevideo.com", ModeRandom, "", "127.0.0.1", true},
		{"www.nicovideo.jp", ModeRemove, "", "3.167.200.113", true},
		{"assets.pinterest.com", ModeRandom, "", "151.101.0.84", true},
	}
	for _, c := range cases {
		plan, ok := PlanFor(c.host)
		if !ok {
			t.Errorf("%s: no rule matched", c.host)
			continue
		}
		if plan.Mode != c.wantMode {
			t.Errorf("%s: mode = %v want %v", c.host, plan.Mode, c.wantMode)
		}
		if c.wantMode == ModeAlias && plan.SNI != c.wantSNI {
			t.Errorf("%s: sni = %q want %q", c.host, plan.SNI, c.wantSNI)
		}
		if c.wantMode == ModeRandom && !strings.Contains(plan.SNI, ".") {
			t.Errorf("%s: random sni too short: %q", c.host, plan.SNI)
		}
		if c.needDial && plan.DialTo != c.wantDial {
			t.Errorf("%s: dial = %q want %q", c.host, plan.DialTo, c.wantDial)
		}
	}
}

// TestRealCealingHostStats reports what the upstream file contributes once
// loaded natively, which the old sni-mimic-only path could not express.
func TestRealCealingHostStats(t *testing.T) {
	path := filepath.Join("testdata", "Cealing-Host.json")
	raw, err := LoadRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ResetRules()
	defer ResetRules()
	for _, r := range raw {
		if err := AddCealingRule(r); err != nil {
			t.Fatalf("usable upstream rule rejected: %v (%v)", err, r)
		}
	}

	alias, random, remove, pinned, local := 0, 0, 0, 0, 0
	for _, r := range getRules() {
		switch r.mode {
		case ModeAlias:
			alias++
		case ModeRandom:
			random++
		case ModeRemove:
			remove++
		}
		switch {
		case r.dst.ip.IsValid() && !r.dst.ip.IsLoopback():
			pinned++
		case r.dst.ip.IsLoopback():
			local++
		case r.dst.host != "":
			pinned++
		case r.dst.empty:
			// an empty ip is 127.0.0.1 upstream: the traffic is meant for a
			// local terminator, which this fork does not ship
			local++
		}
	}
	t.Logf("documents=%d patterns=%d alias=%d random=%d remove=%d pinned_ip=%d loopback=%d",
		len(raw), ruleCount(), alias, random, remove, pinned, local)
	if alias+random+remove != ruleCount() {
		t.Fatal("mode accounting mismatch")
	}
}

// TestBridgeWireSNI proves the capability end to end on a real handshake: a
// stock crypto/tls client advertises the real domain, the bridge terminates it
// with a leaf signed by our root, and the origin must observe only the fake SNI
// for every Cealing mode.
func TestBridgeWireSNI(t *testing.T) {
	cases := []struct {
		name string
		rule []any
		host string
		want func(got string) bool
	}{
		{
			name: "alias longer than the real host",
			rule: []any{[]any{"*youtube.com"}, "benign-served-by-cdn.example", "127.0.0.1"},
			host: "www.youtube.com",
			want: func(g string) bool { return g == "benign-served-by-cdn.example" },
		},
		{
			name: "generated random host",
			rule: []any{[]any{"*pximg.net"}, "", "127.0.0.1"},
			host: "i.pximg.net",
			want: func(g string) bool {
				if g == "" || g == "i.pximg.net" {
					return false
				}
				// the generated name must be one of the pools the signer uses
				for _, tld := range []string{".com", ".net", ".org"} {
					if strings.HasSuffix(g, tld) {
						return true
					}
				}
				return false
			},
		},
		{
			name: "server_name removed",
			rule: []any{[]any{"*.nicovideo.jp"}, nil, "127.0.0.1"},
			host: "www.nicovideo.jp",
			want: func(g string) bool { return g == "" },
		},
	}

	s, err := EnsureSigner()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(s.RootPEM())) {
		t.Fatal("cannot add root to pool")
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ResetRules()
			defer ResetRules()
			if err := AddCealingRule(c.rule); err != nil {
				t.Fatal(err)
			}

			const payload = "origin-payload\n"
			seen := make(chan string, 1)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			cert := originSelfSigned(c.host)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				var got string
				server := tls.Server(conn, &tls.Config{
					GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
						got = hello.ServerName
						return &cert, nil
					},
				})
				_, _ = io.WriteString(server, payload)
				seen <- got
				_ = server.Close()
			}()

			real, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			bridged := ApplyDirect(real, c.host)

			// the app is a STOCK validating client: the bridge must present a
			// leaf for the real domain that chains to our root
			app := tls.Client(bridged, &tls.Config{ServerName: c.host, RootCAs: pool})
			if err := app.Handshake(); err != nil {
				t.Fatalf("app handshake rejected the bridge: %v", err)
			}
			line, err := bufio.NewReader(app).ReadString('\n')
			if err != nil {
				t.Fatalf("read through the bridge: %v", err)
			}
			if line != payload {
				t.Fatalf("payload = %q want %q", line, payload)
			}
			app.Close()

			select {
			case got := <-seen:
				if !c.want(got) {
					t.Fatalf("origin observed SNI %q for real host %q", got, c.host)
				}
				t.Logf("origin observed %q instead of %q", got, c.host)
			case <-time.After(5 * time.Second):
				t.Fatal("origin never saw a ClientHello")
			}
		})
	}
}

// patchConn rewrites the SNI inside the first ClientHello it passes, keeping
// the record byte-length intact, i.e. the plaintext approach the bridge
// replaced.
type patchConn struct {
	net.Conn
	alias string
	done  bool
}

func (c *patchConn) Write(p []byte) (int, error) {
	if !c.done && len(p) > 5 && p[0] == 0x16 {
		c.done = true
		patchSNI(p, c.alias)
	}
	return c.Conn.Write(p)
}

// patchSNI overwrites the first host_name in place, padding with dots.
func patchSNI(p []byte, alias string) {
	off := 5 + 4 // record header + handshake header
	off += 2 + 32
	if off >= len(p) {
		return
	}
	off += 1 + int(p[off])
	if off+2 > len(p) {
		return
	}
	off += 2 + (int(p[off])<<8 | int(p[off+1]))
	if off >= len(p) {
		return
	}
	off += 1 + int(p[off])
	if off+2 > len(p) {
		return
	}
	ext := p[off+2:]
	for e := 0; e+4 <= len(ext); {
		et := int(ext[e])<<8 | int(ext[e+1])
		el := int(ext[e+2])<<8 | int(ext[e+3])
		if e+4+el > len(ext) {
			return
		}
		if et == 0 && el > 7 {
			d := ext[e+4:]
			hostLen := int(d[3])<<8 | int(d[4])
			if hostLen == len(alias) {
				copy(d[5:], alias)
			}
			return
		}
		e += 4 + el
	}
}

// TestPassthroughRewriteBreaksHandshake records why the plaintext rewrite was
// dropped: with an equal-length alias the rewrite does reach the wire, yet the
// handshake still cannot complete, because the client had already hashed the
// original ClientHello into its transcript.
func TestPassthroughRewriteBreaksHandshake(t *testing.T) {
	const (
		realHost = "pixiv.net" // 9 bytes
		alias    = "fanbox.cc" // 9 bytes, same length so no padding is needed
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	seen := make(chan string, 1)
	cert := originSelfSigned(realHost)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		var got string
		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				got = hello.ServerName
				return &cert, nil
			},
		})
		_ = server.Handshake()
		seen <- got
		server.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(&patchConn{Conn: raw, alias: alias}, &tls.Config{
		ServerName:         realHost,
		InsecureSkipVerify: true,
	})
	err = client.Handshake()
	if err == nil {
		t.Fatal("a rewritten ClientHello must not complete a handshake")
	}
	t.Logf("passthrough rewrite failed as expected: %v", err)

	select {
	case got := <-seen:
		if got != alias {
			t.Fatalf("rewrite did not reach the wire: origin saw %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin never saw a ClientHello")
	}
}

// TestPlainTrafficPassesThrough guards the non-TLS branch: a rule says nothing
// about the protocol, so a cleartext connection to a matched host must still
// reach the origin byte for byte.
func TestPlainTrafficPassesThrough(t *testing.T) {
	ResetRules()
	defer ResetRules()
	if err := AddCealingRule([]any{[]any{"*plain.test"}, "g.cn", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn) // echo
	}()

	real, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	bridged := ApplyDirect(real, "a.plain.test")

	const request = "GET / HTTP/1.1\r\nHost: a.plain.test\r\n\r\n"
	if _, err := io.WriteString(bridged, request); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(request))
	_ = bridged.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(bridged, buf); err != nil {
		t.Fatalf("cleartext did not survive the bridge: %v", err)
	}
	if string(buf) != request {
		t.Fatalf("echo mismatch: %q", buf)
	}
	bridged.Close()
}
