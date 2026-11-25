package snifake

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// buildClientHello assembles a minimal TLS record containing one ClientHello
// whose first server_name is sni, plus one decoy extension so that extension
// re-framing is exercised.
func buildClientHello(sni string) []byte {
	const sidLen, csLen, compLen = 0, 2, 1
	cipher := []byte{0x13, 0x01}
	comp := []byte{0x00}

	hostLen := len(sni)
	extBody := make([]byte, 0)
	extBody = append(extBody, byte((1+2+hostLen)>>8), byte(1+2+hostLen))
	extBody = append(extBody, 0x00)
	extBody = append(extBody, byte(hostLen>>8), byte(hostLen))
	extBody = append(extBody, sni...)

	ext := []byte{0x00, 0x00, byte(len(extBody) >> 8), byte(len(extBody))}
	ext = append(ext, extBody...)

	// decoy: supported_versions (0x002b), 2 bytes of data
	decoy := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}

	exts := append(append([]byte{}, ext...), decoy...)
	extLen := len(exts)

	v := make([]byte, 0, 2+32+1+sidLen+2+csLen+1+compLen+2+extLen)
	v = append(v, 0x03, 0x03)
	v = append(v, make([]byte, 32)...)
	v = append(v, byte(sidLen))
	v = append(v, byte(csLen>>8), byte(csLen))
	v = append(v, cipher...)
	v = append(v, byte(compLen))
	v = append(v, comp...)
	v = append(v, byte(extLen>>8), byte(extLen))
	v = append(v, exts...)

	rec := []byte{0x01, byte(len(v) >> 16), byte(len(v) >> 8), byte(len(v))}
	rec = append(rec, v...)
	p := []byte{0x16, 0x03, 0x03, byte(len(rec) >> 8), byte(len(rec))}
	p = append(p, rec...)
	return p
}

// parsedSNI reads back the server_name the record now advertises.
func parsedSNI(t *testing.T, p []byte) (string, bool) {
	t.Helper()
	v, start, end, ok := clientHelloExtents(p)
	if !ok {
		t.Fatal("not a parseable ClientHello")
	}
	s, e := findSNIExtension(v, start, end)
	if s < 0 {
		return "", false
	}
	d := v[s+4 : e] // extension data
	listLen := int(d[0])<<8 | int(d[1])
	if 2+listLen > len(d) {
		t.Fatal("bogus server_name_list length")
	}
	hostLen := int(d[3])<<8 | int(d[4])
	if 5+hostLen > len(d) {
		t.Fatal("bogus host_name length")
	}
	return string(d[5 : 5+hostLen]), true
}

// extensionIntact checks that every extension still parses after a rewrite.
func extensionIntact(t *testing.T, p []byte) {
	t.Helper()
	v, start, end, ok := clientHelloExtents(p)
	if !ok {
		t.Fatal("record no longer parses as a ClientHello")
	}
	seen := 0
	for e := start; e+4 <= end; {
		et := int(v[e])<<8 | int(v[e+1])
		el := int(v[e+2])<<8 | int(v[e+3])
		if e+4+el > end {
			t.Fatalf("extension 0x%04x overruns the block", et)
		}
		seen++
		e += 4 + el
	}
	if seen == 0 {
		t.Fatal("no extensions left after rewrite")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"wikipedia.org", "wikipedia.org", true},
		{"wikipedia.org", "www.wikipedia.org", false},
		{"*wikipedia.org", "www.wikipedia.org", true},
		{"*wikipedia.org", "wikipedia.org", true},
		{"*wik*.org", "wiktionary.org", true},
		{"*wik*.org", "example.com", false},
		{"*pinterest.com", "assets.pinterest.com", true},
		{"*.googlevideo.com", "googlevideo.com", false},
		{"*.googlevideo.com", "r1---sn.googlevideo.com", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.host); got != c.want {
			t.Errorf("globMatch(%q,%q) = %v want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestRuleModelCealing(t *testing.T) {
	ResetRules()
	defer ResetRules()

	raw := []any{
		// alias shorter than host
		[]any{[]any{"*pixiv.net", "*fanbox.cc"}, "pixivision.net", "210.140.92.187"},
		// empty sni -> random per connection
		[]any{[]any{"*pximg.net"}, "", "210.140.92.141"},
		// null sni -> extension removed
		[]any{[]any{"*.googlevideo.com"}, nil, ""},
		// disabled entry (leading ^) and browser-only entry (leading #)
		[]any{[]any{"^*disabled.test"}, "x.test", "1.2.3.4"},
		[]any{[]any{"#*browseronly.test"}, "x.test", "1.2.3.4"},
		// exclusion expression
		[]any{[]any{"*wik*.org^*wikipedia.org"}, "mirror.test", "5.6.7.8"},
		// global-only marker is kept
		[]any{[]any{"$*nyaa.si"}, "ddos-guard.net", "186.2.163.20"},
	}
	for _, item := range raw {
		if err := AddCealingRule(item); err != nil {
			t.Fatalf("AddCealingRule(%v): %v", item, err)
		}
	}

	if plan, ok := PlanFor("app-api.pixiv.net"); !ok || plan.SNI != "pixivision.net" {
		t.Fatalf("pixiv: %+v %v", plan, ok)
	}
	if _, ok := PlanFor("disabled.test"); ok {
		t.Fatal("leading ^ must disable the entry")
	}
	if _, ok := PlanFor("browseronly.test"); ok {
		t.Fatal("leading # (browser-only) must be skipped")
	}
	if _, ok := PlanFor("wikipedia.org"); ok {
		t.Fatal("exclusion (^*wikipedia.org) must reject wikipedia.org")
	}
	if plan, ok := PlanFor("wikinews.org"); !ok || plan.SNI != "mirror.test" {
		t.Fatalf("exclusion allowed match wrong: %+v %v", plan, ok)
	}
	// first match wins: pximg rule was added before the googlevideo one
	if plan, ok := PlanFor("i.pximg.net"); !ok || plan.Mode != ModeRandom {
		t.Fatalf("pximg should be random mode: %+v %v", plan, ok)
	}
	if plan, ok := PlanFor("r1.sn.googlevideo.com"); !ok || plan.Mode != ModeRemove {
		t.Fatalf("googlevideo should remove SNI: %+v %v", plan, ok)
	}
	if _, ok := PlanFor("example.com"); ok {
		t.Fatal("unrelated host must not match")
	}
}

func TestPlanDestinationPinning(t *testing.T) {
	ResetRules()
	defer ResetRules()

	if err := AddCealingRule([]any{[]any{"*pinned.test"}, "ok.test", "9.9.9.9"}); err != nil {
		t.Fatal(err)
	}
	if err := AddCealingRule([]any{[]any{"*emptyip.test"}, "ok.test", ""}); err != nil {
		t.Fatal(err)
	}
	if err := AddCealingRule([]any{[]any{"*v6.test"}, "ok.test", "[2001:db8::1]"}); err != nil {
		t.Fatal(err)
	}
	if err := AddCealingRule([]any{[]any{"*byname.test"}, "ok.test", "cdn.example.com"}); err != nil {
		t.Fatal(err)
	}

	for host, want := range map[string]string{
		"a.pinned.test":  "9.9.9.9",
		"x.emptyip.test": "127.0.0.1",
		"q.v6.test":      "2001:db8::1",
		"z.byname.test":  "cdn.example.com",
	} {
		if got, ok := LookupIP(host); !ok || got != want {
			t.Errorf("LookupIP(%s) = %q,%v want %q", host, got, ok, want)
		}
	}
}

func TestLegacyMapCompatibility(t *testing.T) {
	ResetRules()
	defer ResetRules()

	SetRules(map[string]string{"pixiv.net": "fanbox.cc"})
	if !Enabled() {
		t.Fatal("should be enabled")
	}
	if plan, ok := PlanFor("app-api.pixiv.net"); !ok || plan.SNI != "fanbox.cc" {
		t.Fatalf("suffix match failed: %+v %v", plan, ok)
	}
	if _, ok := LookupIP("app-api.pixiv.net"); ok {
		t.Fatal("legacy rules must not pin an IP")
	}
}

func TestRewriteShorterAndLongerAlias(t *testing.T) {
	for _, alias := range []string{"a.cn", "g.cn", "scontent.xx.fbcdn.net", "vercel.com"} {
		p := buildClientHello("www.youtube.com")
		out, ok := rewriteFirstClientHello(p, alias, ModeAlias)
		if !ok {
			t.Fatalf("rewrite to %q refused", alias)
		}
		extensionIntact(t, out)
		got, has := parsedSNI(t, out)
		if !has || got != alias {
			t.Fatalf("SNI after rewrite = %q,%v want %q", got, has, alias)
		}
		if bytes.Contains(out, []byte("www.youtube.com")) {
			t.Fatalf("original SNI leaked for alias %q", alias)
		}
		// the decoy extension must survive
		if !bytes.Contains(out, []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}) {
			t.Fatal("following extension was destroyed")
		}
	}
}

func TestRewriteRemovesSNIExtension(t *testing.T) {
	p := buildClientHello("r1.sn.googlevideo.com")
	out, ok := rewriteFirstClientHello(p, "", ModeRemove)
	if !ok {
		t.Fatal("remove refused")
	}
	extensionIntact(t, out)
	if _, has := parsedSNI(t, out); has {
		t.Fatal("server_name extension still present")
	}
	if bytes.Contains(out, []byte("googlevideo")) {
		t.Fatal("SNI bytes left behind")
	}
}

func TestRewriteRejectsNonHandshake(t *testing.T) {
	// application data: the rewriter reports it cannot act, and the caller
	// must therefore forward the original bytes untouched.
	junk := []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb}
	out, ok := rewriteFirstClientHello(append([]byte{}, junk...), "g.cn", ModeAlias)
	if ok || !bytes.Equal(out, junk) {
		t.Fatal("non-ClientHello record must not be modified")
	}
	// wrong handshake type
	bad := buildClientHello("x.test")
	bad[5] = 0x02
	if _, ok := rewriteFirstClientHello(bad, "g.cn", ModeAlias); ok {
		t.Fatal("non-ClientHello handshake must be refused")
	}
	// truncated buffers
	if _, ok := rewriteFirstClientHello([]byte{0x16, 0x03}, "g.cn", ModeAlias); ok {
		t.Fatal("truncated buffer must not be rewritten")
	}
	if _, ok := rewriteFirstClientHello(buildClientHello("x.test")[:10], "g.cn", ModeAlias); ok {
		t.Fatal("partial record must not be rewritten")
	}
}

func TestConnWriteRewritesFirstRecordOnly(t *testing.T) {
	ResetRules()
	defer ResetRules()
	if err := AddCealingRule([]any{[]any{"*writetest.test"}, "g.cn", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	plan, ok := PlanFor("a.writetest.test")
	if !ok {
		t.Fatal("no plan")
	}

	var sink bytes.Buffer
	c := &conn{Conn: &nopConn{w: &sink}, plan: plan}

	hello := buildClientHello("a.writetest.test")
	// feed the ClientHello split across two writes to exercise the holdback
	if _, err := c.Write(hello[:12]); err != nil {
		t.Fatal(err)
	}
	if sink.Len() != 0 {
		t.Fatal("incomplete record must be buffered, not written")
	}
	if _, err := c.Write(hello[12:]); err != nil {
		t.Fatal(err)
	}
	out := sink.Bytes()
	extensionIntact(t, out)
	if got, _ := parsedSNI(t, out); got != "g.cn" {
		t.Fatalf("SNI on the wire = %q want g.cn", got)
	}

	// a later write must be forwarded verbatim
	sink.Reset()
	payload := []byte("not-a-handshake")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sink.Bytes(), payload) {
		t.Fatal("post-handshake write altered")
	}
}

// nopConn discards writes and records them.
type nopConn struct {
	w *bytes.Buffer
}

func (c *nopConn) Read(b []byte) (int, error)       { return 0, bytes.ErrTooLarge }
func (c *nopConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *nopConn) Close() error                     { return nil }
func (c *nopConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *nopConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *nopConn) SetDeadline(time.Time) error      { return nil }
func (c *nopConn) SetReadDeadline(time.Time) error  { return nil }
func (c *nopConn) SetWriteDeadline(time.Time) error { return nil }
