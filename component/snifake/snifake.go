// Package snifake implements a Sheas-Cealer / Cealing-Host style SNI mimic for
// DIRECT connections: when the target domain matches a rule, the plaintext TLS
// ClientHello is rewritten on the wire so that the outer SNI becomes a benign
// alias (or a fresh random name, or disappears entirely), while the TCP
// connection still goes to the destination the rule pins.
//
// A rule binds three things, exactly like a Cealing-Host JSON entry:
//
//	domain glob patterns  ->  fake SNI (alias / random / removed)  ->  target IP
//
// The certificate path is described in mitm.go: because the origin answers
// with a certificate for the ALIAS, apps would reject the connection unless we
// terminate TLS locally and re-sign the leaf with our own root CA.
package snifake

import (
	"net"
	"sync/atomic"
)

// Mode selects how the SNI on the wire is produced.
type Mode uint8

const (
	// ModeAlias installs the configured alias verbatim.
	ModeAlias Mode = iota
	// ModeRandom installs a freshly generated host name per connection.
	ModeRandom
	// ModeRemove strips the server_name extension entirely.
	ModeRemove
)

// Plan is the action to take for one host.
type Plan struct {
	SNI    string // SNI to install (empty for ModeRemove)
	Mode   Mode
	DialTo string // non-empty when the rule pins the TCP destination
}

// PlanFor returns the plan for host and whether a rule matched.
func PlanFor(host string) (Plan, bool) {
	r := lookupRule(host)
	if r == nil {
		return Plan{}, false
	}
	plan := Plan{Mode: r.mode, SNI: r.alias, DialTo: r.dst.address()}
	if r.mode == ModeRandom {
		plan.SNI = randomHost()
	}
	return plan, true
}

// LookupIP returns the pinned destination for host, if the matching rule has
// one. It is used by the DIRECT outbound to dial the rule IP instead of the
// DNS answer.
func LookupIP(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	r := lookupRule(host)
	if r == nil {
		return "", false
	}
	addr := r.dst.address()
	return addr, addr != ""
}

// Enabled reports whether any rule is configured.
func Enabled() bool { return ruleCount() > 0 }

// SetRules installs the legacy "domain -> alias" table, appended after any
// rules that were configured earlier.
func SetRules(table map[string]string) {
	for domain, alias := range table {
		AddLegacyRule(domain, alias)
	}
}

// mitmMode selects the certificate-MITM path (true) or the plaintext
// SNI-rewrite path (false). Only meaningful when rules are configured.
var mitmMode atomic.Bool

// SetMITM chooses MITM vs SNI-rewrite for DIRECT connections.
func SetMITM(v bool) { mitmMode.Store(v) }

// MITMEnabled reports whether the certificate-MITM path is selected.
func MITMEnabled() bool { return mitmMode.Load() }

// ApplyDirect wraps an already-dialed real connection for a DIRECT outbound.
// When host has a rule it selects MITM or SNI-rewrite per mode; otherwise it
// returns c unchanged.
func ApplyDirect(c net.Conn, host string) net.Conn {
	if host == "" {
		return c
	}
	plan, ok := PlanFor(host)
	if !ok {
		return c
	}
	// Without an SNI to fake there is nothing to terminate: fall back to the
	// plaintext record rewrite, which simply removes the extension.
	if MITMEnabled() && plan.Mode != ModeRemove {
		return newMITMConn(c, host, plan.SNI)
	}
	return &conn{Conn: c, plan: plan}
}

// conn rewrites the first ClientHello written through it.
type conn struct {
	net.Conn
	plan Plan
	done bool
	buf  []byte // held back until the first record is complete
}

const maxHoldback = 1 << 16

func (c *conn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	if len(c.buf) == 0 {
		if len(p) == 0 {
			return c.Conn.Write(p)
		}
		if p[0] != 0x16 {
			// not a TLS handshake record: nothing to rewrite
			c.done = true
			return c.Conn.Write(p)
		}
	}
	c.buf = append(c.buf, p...)
	if readRecordLength(c.buf) == 0 {
		// The ClientHello did not arrive in one piece; accumulate until the
		// record is complete. Past the cap we give up and pass everything
		// through untouched rather than stalling the connection.
		if len(c.buf) < maxHoldback {
			return len(p), nil
		}
		c.done = true
		held := c.buf
		c.buf = nil
		if _, err := c.Conn.Write(held); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	out, _ := rewriteFirstClientHello(c.buf, c.plan.SNI, wireMode(c.plan.Mode))
	c.done = true
	c.buf = nil
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// wireMode maps a plan mode to the hello rewriter's mode. A random SNI was
// already materialised into a concrete host name, so it is installed verbatim.
func wireMode(m Mode) Mode {
	if m == ModeRemove {
		return ModeRemove
	}
	return ModeAlias
}
