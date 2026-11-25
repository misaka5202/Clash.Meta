package snifake

import (
	"path/filepath"
	"strings"
	"testing"
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
