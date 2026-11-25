package snifake

import (
	"bytes"
	"testing"
)

// buildClientHello assembles a minimal TLS record containing one ClientHello
// whose first server_name is sni. Everything else is filler.
func buildClientHello(sni string) []byte {
	var sidLen, csLen, compLen = 0, 2, 1
	cipher := []byte{0x13, 0x01}
	comp := []byte{0x00}

	hostLen := len(sni)
	// sni extension: listLen(2) + [nameType(1) hostLen(2) host]
	extBody := make([]byte, 0)
	extBody = append(extBody, byte((1+2+hostLen)>>8), byte(1+2+hostLen)) // server_name_list length
	extBody = append(extBody, 0x00)                                      // host_name
	extBody = append(extBody, byte(hostLen>>8), byte(hostLen))           // hostname length
	extBody = append(extBody, sni...)

	// extension framing: type(2)+len(2)+data
	ext := []byte{0x00, 0x00, byte(len(extBody) >> 8), byte(len(extBody))}
	ext = append(ext, extBody...)
	extLen := len(ext)

	v := make([]byte, 0, 2+32+1+sidLen+2+csLen+1+compLen+2+extLen)
	v = append(v, 0x03, 0x03)          // legacy_version
	v = append(v, make([]byte, 32)...) // random
	v = append(v, byte(sidLen))
	v = append(v, byte(csLen>>8), byte(csLen))
	v = append(v, cipher...)
	v = append(v, byte(compLen))
	v = append(v, comp...)
	v = append(v, byte(extLen>>8), byte(extLen))
	v = append(v, ext...)

	// handshake header
	rec := []byte{0x01, byte(len(v) >> 16), byte(len(v) >> 8), byte(len(v))}
	rec = append(rec, v...)
	// record header
	p := []byte{0x16, 0x03, 0x03, byte(len(rec) >> 8), byte(len(rec))}
	p = append(p, rec...)
	return p
}

func sniOf(p []byte) string {
	// locate first server_name host bytes for assertion
	i := bytes.Index(p, []byte{0x00, 0x00}) // SNI ext type appears; fall back to manual scan below
	_ = i
	// robust re-extract using same parser: run rewrite with sentinel
	return string(p) // not used; we assert via contains
}

func TestRewriteEqualLength(t *testing.T) {
	p := buildClientHello("pixiv.net")
	origLen := len(p)
	if !bytes.Contains(p, []byte("pixiv.net")) {
		t.Fatal("fixture missing SNI")
	}
	if !RewriteClientHello(p, "fanbox.cc") {
		t.Fatal("expected rewrite to succeed (equal length)")
	}
	if len(p) != origLen {
		t.Fatalf("length changed: %d -> %d", origLen, len(p))
	}
	if bytes.Contains(p, []byte("pixiv.net")) {
		t.Fatal("original SNI still present")
	}
	if !bytes.Contains(p, []byte("fanbox.cc")) {
		t.Fatal("alias not applied")
	}
}

func TestRewriteShorterWithPadding(t *testing.T) {
	p := buildClientHello("pixiv.net")
	origLen := len(p)
	if !RewriteClientHello(p, "f.cc") {
		t.Fatal("expected rewrite to succeed (alias shorter)")
	}
	if len(p) != origLen {
		t.Fatalf("length changed: %d -> %d", origLen, len(p))
	}
	if bytes.Contains(p, []byte("pixiv.net")) {
		t.Fatal("original SNI still present")
	}
	if !bytes.Contains(p, []byte("f.cc")) {
		t.Fatal("padded alias not applied")
	}
}

func TestRewriteLongerAliasRefused(t *testing.T) {
	p := buildClientHello("pixiv.net")
	origLen := len(p)
	if RewriteClientHello(p, "some-very-long-alias.example") {
		t.Fatal("should refuse alias longer than original")
	}
	if len(p) != origLen || !bytes.Contains(p, []byte("pixiv.net")) {
		t.Fatal("buffer should be untouched when refused")
	}
}

func TestRewriteIncompleteRecordRetries(t *testing.T) {
	full := buildClientHello("pixiv.net")
	half := full[:10] // truncated: not a complete record
	if RewriteClientHello(half, "fanbox.cc") {
		t.Fatal("should not rewrite an incomplete buffer")
	}
}

func TestLookupAndWrap(t *testing.T) {
	SetRules(map[string]string{"pixiv.net": "fanbox.cc"})
	if !Enabled() {
		t.Fatal("should be enabled")
	}
	if Lookup("app-api.pixiv.net") != "fanbox.cc" {
		t.Fatal("suffix match failed")
	}
	if Lookup("example.com") != "" {
		t.Fatal("unrelated host should not match")
	}
}
