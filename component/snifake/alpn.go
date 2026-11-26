package snifake

import (
	"encoding/binary"
	"errors"
)

// ALPN (RFC 7301) lives in ClientHello extension 16. The application proposes
// a protocol list ("h2", "http/1.1", ...) and the server must pick one. If the
// MITM bridge answers with an empty list, the client sees no negotiated
// protocol and browsers abort with "http2_handshake_failed" (Chrome expects
// "h2" to be selected when it offered it).
//
// The same proposal must also reach the ORIGIN side, otherwise the app and
// the origin end up speaking different protocols (the origin may pick "h2"
// while the app fell back to HTTP/1.1), which breaks the HTTP/2 framing.
//
// So: read the proposal out of the raw ClientHello, echo it back to the app,
// and pass the identical list to the upstream client.

// parseClientHelloALPN extracts the ALPN protocol list from a raw TLS
// ClientHello record. It returns nil when the record carries no ALPN
// extension, which is legal: HTTP/1.1-only clients do not send one.
func parseClientHelloALPN(record []byte) ([]string, error) {
	// TLSPlaintext: type(1) legacy_version(2) length(2)
	if len(record) < 5 || record[0] != 0x16 {
		return nil, errors.New("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	body := record[5:]
	if len(body) > recLen {
		body = body[:recLen]
	}
	// Handshake: msg_type(1) length(3) client_version(2) random(32) ...
	if len(body) < 4 || body[0] != 0x01 {
		return nil, errors.New("not a ClientHello")
	}
	hello := body[4:]
	if len(hello) < 34 {
		return nil, errors.New("truncated ClientHello")
	}
	p := 34 // client_version(2) + random(32)
	// session_id
	if p >= len(hello) {
		return nil, errors.New("truncated ClientHello")
	}
	sidLen := int(hello[p])
	p += 1 + sidLen
	// cipher_suites
	if p+2 > len(hello) {
		return nil, errors.New("truncated ClientHello")
	}
	csLen := int(binary.BigEndian.Uint16(hello[p : p+2]))
	p += 2 + csLen
	// compression_methods
	if p >= len(hello) {
		return nil, errors.New("truncated ClientHello")
	}
	cmLen := int(hello[p])
	p += 1 + cmLen
	// extensions
	if p+2 > len(hello) {
		return nil, nil // no extensions at all
	}
	extLen := int(binary.BigEndian.Uint16(hello[p : p+2]))
	p += 2
	if p+extLen > len(hello) {
		extLen = len(hello) - p
	}
	end := p + extLen
	for p+4 <= end {
		extType := binary.BigEndian.Uint16(hello[p : p+2])
		extBodyLen := int(binary.BigEndian.Uint16(hello[p+2 : p+4]))
		p += 4
		if p+extBodyLen > end {
			break
		}
		if extType == 16 { // ALPN
			return parseALPNBody(hello[p : p+extBodyLen]), nil
		}
		p += extBodyLen
	}
	return nil, nil
}

// parseALPNBody decodes the ALPN extension body: a list of
// length-prefixed protocol names.
func parseALPNBody(body []byte) []string {
	if len(body) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(body[:2]))
	p := 2
	end := 2 + listLen
	if end > len(body) {
		end = len(body)
	}
	var out []string
	for p < end {
		n := int(body[p])
		p++
		if p+n > end {
			break
		}
		out = append(out, string(body[p:p+n]))
		p += n
	}
	return out
}
