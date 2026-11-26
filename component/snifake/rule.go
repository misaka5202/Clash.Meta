package snifake

// rule.go implements the Cealing-Host rule model: a rule binds a set of domain
// glob patterns to a fake SNI (or a generated/removed one) AND to a fixed
// destination IP. Matching follows upstream semantics:
//
//	*       matches any run of characters (including '.')
//	^       excludes a pattern from a match expression
//	leading ^   the whole entry is disabled (acts as a comment)
//	leading #   browser-only rule; skipped here because mihomo is app-wide
//	leading $   global-only rule; kept
//	first match wins (rules are ordered)
//
// An empty fake SNI means "generate a random host name"; a JSON null means
// "remove the server_name extension entirely"; an empty IP means 127.0.0.1.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// destination describes where the TCP connection must actually go.
type destination struct {
	ip    netip.Addr // valid when the rule pins a literal IP
	host  string     // non-empty when the rule pins a domain name
	empty bool       // rule had an explicit empty ip -> 127.0.0.1
}

func (d destination) address() string {
	switch {
	case d.ip.IsValid():
		return d.ip.String()
	case d.host != "":
		return d.host
	case d.empty:
		return "127.0.0.1"
	}
	return ""
}

type pattern struct {
	positive  string
	negatives []string
}

func (p pattern) match(host string) bool {
	if p.positive != "" && !globMatch(p.positive, host) {
		return false
	}
	for _, n := range p.negatives {
		if globMatch(n, host) {
			return false
		}
	}
	return true
}

type rule struct {
	patterns []pattern
	alias    string
	mode     Mode
	dst      destination
}

func (r *rule) matches(host string) bool {
	for _, p := range r.patterns {
		if p.match(host) {
			return true
		}
	}
	return false
}

// desiredSNI returns the SNI to put on the wire for host.
func (r *rule) desiredSNI() string {
	switch r.mode {
	case ModeRandom:
		return randomHost()
	case ModeRemove:
		return ""
	default:
		return r.alias
	}
}

var (
	rulesMu sync.RWMutex
	rules   []rule
)

var tldPool = [...]string{"com", "net", "org"}

// globMatch reports whether pattern (where '*' matches any run of characters)
// matches s. Both arguments must already be lower case.
func globMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		if pi < len(pattern) {
			switch pattern[pi] {
			case '*':
				star = pi
				mark = si
				pi++
				continue
			case s[si]:
				pi++
				si++
				continue
			}
		}
		if star < 0 {
			return false
		}
		pi = star + 1
		mark++
		si = mark
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// parsePattern converts one Cealing domain-match token. It returns ok=false
// when the token must be skipped entirely.
func parsePattern(token string) (pattern, bool) {
	tok := strings.ToLower(strings.TrimSpace(token))
	if tok == "" {
		return pattern{}, false
	}
	if tok[0] == '^' {
		return pattern{}, false // disabled entry
	}
	if tok[0] == '#' {
		return pattern{}, false // browser-only rule
	}
	if tok[0] == '$' {
		tok = tok[1:]
	}
	if tok == "" {
		return pattern{}, false
	}
	parts := strings.Split(tok, "^")
	p := pattern{positive: strings.TrimSpace(parts[0])}
	for _, n := range parts[1:] {
		if n = strings.TrimSpace(n); n != "" {
			p.negatives = append(p.negatives, n)
		}
	}
	if p.positive == "" && len(p.negatives) == 0 {
		return pattern{}, false
	}
	return p, true
}

// googlePattern reports whether a Cealing domain token targets google.com so
// its regional redirect siblings can be added automatically.
func googlePattern(token string) bool {
	s := strings.ToLower(strings.TrimSpace(token))
	s = strings.TrimPrefix(s, "#")
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimPrefix(s, "*")
	// google.com or www.google.com (optionally with a leading dot)
	s = strings.TrimPrefix(s, ".")
	return s == "google.com" || strings.HasSuffix(s, ".google.com")
}

// regionalGoogleSuffixes are the ccTLD variants Google redirects mainland
// visitors to. google.com -> google.com.hk / google.com.tw / google.com.hk
// all carry the same content; covering them keeps the disguise intact after a
// 302 so the browser does not fall off the MITM bridge.
var regionalGoogleSuffixes = []string{
	"google.com.hk",
	"google.com.tw",
	"google.co.jp",
	"google.de",
	"google.co.uk",
}

// googleRegionalPatterns builds wildcard patterns for Google's regional
// domains. A leading '*' matches the domain itself and any subdomain.
func googleRegionalPatterns() []pattern {
	out := make([]pattern, 0, len(regionalGoogleSuffixes))
	for _, d := range regionalGoogleSuffixes {
		out = append(out, pattern{positive: "*." + d}, pattern{positive: d})
	}
	return out
}

// randomHost generates a fresh, syntactically valid host name. Every call
// returns a different value, mirroring Cealing's "non-repeating string" rule.
func randomHost() string {
	var b [6]byte
	var t [1]byte
	_, _ = rand.Read(b[:])
	_, _ = rand.Read(t[:])
	return hex.EncodeToString(b[:]) + "." + tldPool[int(t[0])%len(tldPool)]
}

// parseDestination interprets the Cealing ip element.
func parseDestination(v any) (destination, error) {
	switch t := v.(type) {
	case nil:
		return destination{empty: true}, nil
	case string:
		s := strings.TrimSpace(t)
		s = strings.TrimPrefix(s, "[")
		s = strings.TrimSuffix(s, "]")
		if s == "" {
			return destination{empty: true}, nil
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			return destination{ip: ip.Unmap()}, nil
		}
		if !strings.Contains(s, ".") && !strings.Contains(s, ":") {
			return destination{}, fmt.Errorf("invalid ip or host %q", t)
		}
		return destination{host: strings.ToLower(s)}, nil
	default:
		return destination{}, fmt.Errorf("invalid ip value %v", v)
	}
}

// parseSNI interprets the Cealing sni element.
func parseSNI(v any) (string, Mode, error) {
	switch t := v.(type) {
	case nil:
		return "", ModeRemove, nil
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "" {
			return "", ModeRandom, nil
		}
		return s, ModeAlias, nil
	default:
		return "", ModeAlias, fmt.Errorf("invalid sni value %v", v)
	}
}

// AddCealingRule ingests one Cealing rule: [domains, sni, ip].
func AddCealingRule(raw any) error {
	list, ok := raw.([]any)
	if !ok || len(list) < 3 {
		return fmt.Errorf("rule must be a 3 element array, got %T", raw)
	}
	domains, ok := list[0].([]any)
	if !ok || len(domains) == 0 {
		return fmt.Errorf("rule domains must be a non-empty array")
	}
	alias, mode, err := parseSNI(list[1])
	if err != nil {
		return err
	}
	dst, err := parseDestination(list[2])
	if err != nil {
		return err
	}
	r := rule{alias: alias, mode: mode, dst: dst}
	// Google redirects mainland visitors from google.com to google.com.hk
	// (pref=hkredirect). If the redirect target is not covered by a rule it
	// leaks the real SNI and fails to open. Extend every google pattern with
	// the regional ccTLD siblings so the disguise follows the redirect.
	var googleVariant bool
	for _, d := range domains {
		s, ok := d.(string)
		if !ok {
			continue
		}
		if p, keep := parsePattern(s); keep {
			r.patterns = append(r.patterns, p)
			if googlePattern(s) {
				googleVariant = true
			}
		}
	}
	if googleVariant {
		r.patterns = append(r.patterns, googleRegionalPatterns()...)
	}
	if len(r.patterns) == 0 {
		return nil // everything was commented out or browser-only
	}
	rulesMu.Lock()
	rules = append(rules, r)
	rulesMu.Unlock()
	return nil
}

// SetCealingRules replaces the whole table with raw Cealing rules.
func SetCealingRules(raw []any) error {
	previous := getRules()
	ResetRules()
	for _, item := range raw {
		if err := AddCealingRule(item); err != nil {
			setRules(previous)
			return err
		}
	}
	return nil
}

func getRules() []rule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	out := make([]rule, len(rules))
	copy(out, rules)
	return out
}

func setRules(r []rule) {
	rulesMu.Lock()
	rules = r
	rulesMu.Unlock()
}

// AddLegacyRule appends one "domain -> alias" entry using exact-or-suffix
// matching, which is what the original sni-mimic map did.
func AddLegacyRule(domain, alias string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	alias = strings.ToLower(strings.TrimSpace(alias))
	if domain == "" || alias == "" {
		return
	}
	r := rule{
		patterns: []pattern{{positive: domain}, {positive: "*." + domain}},
		alias:    alias,
		mode:     ModeAlias,
	}
	rulesMu.Lock()
	rules = append(rules, r)
	rulesMu.Unlock()
}

// ResetRules clears the table.
func ResetRules() {
	rulesMu.Lock()
	rules = nil
	rulesMu.Unlock()
}

// lookupRule returns a copy of the first matching rule; handing back a pointer
// into the shared slice would race with a concurrent reload.
func lookupRule(host string) (rule, bool) {
	host = strings.ToLower(host)
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	for i := range rules {
		if rules[i].matches(host) {
			return rules[i], true
		}
	}
	return rule{}, false
}

// ruleCount is used by tests and diagnostics.
func ruleCount() int {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	return len(rules)
}
