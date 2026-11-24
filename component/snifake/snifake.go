// Package snifake implements a Sheas-Cealer-style SNI mimic for DIRECT
// connections: when the target domain matches a mimic rule, the plaintext
// TLS ClientHello record is rewritten on the wire so that the outer SNI is
// replaced by a benign alias, while the TCP connection still goes to the real
// destination resolved from the real domain.
//
// This is the network-layer equivalent of Sheas-Cealer's Chromium flags
//   --host-rules="MAP <domain> <alias>"   (SNI -> alias)
//   --host-resolver-rules="MAP <alias> <realIP>"  (DIRECT already dials real IP)
//   --ignore-certificate-errors           (the server returns a cert that does
//                                          not match the real domain, so the
//                                          client app must still ignore the
//                                          certificate error for the target)
//
// The rewrite keeps the SNI host_name the SAME LENGTH as the original by
// padding the benign alias with trailing dots, so the ClientHello byte length
// is unchanged and no extension/record lengths have to be recomputed.
package snifake

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
)

type rule struct {
	domain string // matched suffix, e.g. "pixiv.net"
	alias  string // benign SNI alias, e.g. "fanbox.cc"
}

type mimic struct {
	sync.RWMutex
	rules []rule
}

func (m *mimic) lookup(host string) string {
	m.RLock()
	defer m.RUnlock()
	if len(m.rules) == 0 || host == "" {
		return ""
	}
	for _, r := range m.rules {
		if host == r.domain || bytes.HasSuffix([]byte(host), []byte("."+r.domain)) {
			return r.alias
		}
	}
	return ""
}

func (m *mimic) enabled() bool {
	m.RLock()
	defer m.RUnlock()
	return len(m.rules) > 0
}

var global mimic

// SetRules configures the domain -> alias SNI mimic table.
func SetRules(rules map[string]string) {
	global.Lock()
	defer global.Unlock()
	global.rules = global.rules[:0]
	for d, a := range rules {
		if d == "" || a == "" {
			continue
		}
		global.rules = append(global.rules, rule{domain: d, alias: a})
	}
}

// Enabled reports whether any mimic rule is configured.
func Enabled() bool { return global.enabled() }

// Lookup returns the alias SNI for host, or "" if no rule matches.
func Lookup(host string) string { return global.lookup(host) }

// mitmMode selects the certificate-MITM path (true) or the plaintext
// SNI-rewrite path (false). Only meaningful when rules are configured.
var mitmMode atomic.Bool

// SetMITM chooses MITM vs SNI-rewrite for DIRECT connections.
func SetMITM(v bool) { mitmMode.Store(v) }

// MITMEnabled reports whether the certificate-MITM path is selected.
func MITMEnabled() bool { return mitmMode.Load() }

// ApplyDirect wraps an already-dialed real connection for a DIRECT outbound.
// When host has a mimic rule it selects MITM or SNI-rewrite per mode;
// otherwise it returns c unchanged.
func ApplyDirect(c net.Conn, host string) net.Conn {
	if !Enabled() || host == "" || Lookup(host) == "" {
		return c
	}
	if MITMEnabled() {
		return MITMWrapIf(c, host)
	}
	return WrapIf(c, host)
}

// padDots pads s with trailing dots so that its length equals n. n must be
// greater than or equal to len(s). Dots are valid inside a DNS host_name used
// in SNI (a FQDN with a trailing dot), so the server still accepts it.
func padDots(s string, n int) []byte {
	b := []byte(s)
	if len(b) > n {
		return b[:n] // truncated; caller must ensure n >= len(s)
	}
	out := make([]byte, n)
	copy(out, b)
	for i := len(b); i < n; i++ {
		out[i] = '.'
	}
	return out
}

// RewriteClientHello replaces the first server_name in the first ClientHello
// record of p with alias. It performs an in-place, equal-length rewrite, so p
// is modified when len(alias) <= len(orig) (padding with dots when shorter).
// Returns true if an SNI was actually rewritten.
func RewriteClientHello(p []byte, alias string) bool {
	// TLS record header: 5 bytes = type(1) version(2) length(2)
	if len(p) < 5 || p[0] != 0x16 {
		return false
	}
	recLen := int(p[3])<<8 | int(p[4])
	if recLen < 1 || len(p) < 5+recLen {
		return false // record body not fully in this buffer yet
	}
	rec := p[5 : 5+recLen]

	// Handshake header: type(1) length(3)
	if len(rec) < 4 || rec[0] != 0x01 {
		return false
	}
	// ClientHello body
	v := rec[4:]
	if len(v) < 2+32+1 {
		return false
	}
	off := 2 + 32 // version + random
	sidLen := int(v[off])
	off += 1 + sidLen
	if off+2 > len(v) {
		return false
	}
	csLen := int(v[off])<<8 | int(v[off+1])
	off += 2 + csLen
	if off >= len(v) {
		return false
	}
	compLen := int(v[off])
	off += 1 + compLen
	if off+2 > len(v) {
		return false
	}
	extLen := int(v[off])<<8 | int(v[off+1])
	extBody := v[off+2:]
	if len(extBody) < extLen {
		return false
	}

	e := 0
	for e+4 <= extLen {
		et := int(extBody[e])<<8 | int(extBody[e+1])
		el := int(extBody[e+2])<<8 | int(extBody[e+3])
		d := extBody[e+4:]
		if len(d) < el || e+4+el > extLen {
			break
		}
		if et == 0x0000 && el >= 5 {
			// server_name extension
			listLen := int(d[0])<<8 | int(d[1])
			if 2+listLen > el {
				break
			}
			// first entry: nameType(1) hostLen(2) hostName
			orig := d[4:] // nameType and hostLen occupy d[2], d[3:5]
			hostLen := int(d[3])<<8 | int(d[4]) // wait: d[2]=type, d[3:5]=len
			_ = orig
			if 5+hostLen > el {
				break
			}
			origSNI := string(d[5 : 5+hostLen])
			if len(alias) > hostLen || origSNI == alias {
				// keep original when alias longer (would break length);
				// nothing to do when already the alias
				return false
			}
			nl := padDots(alias, hostLen) // equal length, trailing dots
			copy(d[5:5+hostLen], nl)
			return true
		}
		e += 4 + el
	}
	return false
}

type conn struct {
	net.Conn
	alias string
	done  bool
}

// WrapIf wraps c so that the first ClientHello record is rewritten to alias
// when the target domain has a matching mimic rule. Returns c unchanged if no
// rule matches or mimicking is disabled.
func WrapIf(c net.Conn, host string) net.Conn {
	if !Enabled() {
		return c
	}
	alias := Lookup(host)
	if alias == "" {
		return c
	}
	return &conn{Conn: c, alias: alias}
}

func (c *conn) Write(p []byte) (int, error) {
	if !c.done {
		if c.tryRewrite(p) {
			c.done = true
		}
	}
	return c.Conn.Write(p)
}

// tryRewrite attempts to mutate the first ClientHello in p when the whole TLS
// record is present in the buffer. It marks the operation as consumed once p
// is large enough to be classified, so it is never retried on a later chunk.
func (c *conn) tryRewrite(p []byte) bool {
	if len(p) < 5 || p[0] != 0x16 {
		c.done = true
		return false
	}
	recLen := int(p[3])<<8 | int(p[4])
	if recLen < 1 || len(p) < 5+recLen {
		return false // incomplete ClientHello record yet, may retry next write
	}
	return RewriteClientHello(p, c.alias)
}
