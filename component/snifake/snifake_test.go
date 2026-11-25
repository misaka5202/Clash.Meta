package snifake

import (
	"testing"
)

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

	for _, r := range [][]any{
		{[]any{"*pinned.test"}, "ok.test", "9.9.9.9"},
		{[]any{"*emptyip.test"}, "ok.test", ""},
		{[]any{"*v6.test"}, "ok.test", "[2001:db8::1]"},
		{[]any{"*byname.test"}, "ok.test", "cdn.example.com"},
	} {
		if err := AddCealingRule(r); err != nil {
			t.Fatal(err)
		}
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

func TestUnmatchedHostHasNoPlan(t *testing.T) {
	ResetRules()
	defer ResetRules()

	if _, ok := PlanFor("example.com"); ok {
		t.Fatal("no rules configured, nothing may match")
	}
	if Enabled() {
		t.Fatal("Enabled must be false with an empty table")
	}
}

func TestBlockUDPFollowsRules(t *testing.T) {
	ResetRules()
	defer ResetRules()

	if BlockUDP("a.quic.test") || BlockUDP("") {
		t.Fatal("an empty table must not block anything")
	}
	if err := AddCealingRule([]any{[]any{"*quic.test"}, "g.cn", "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if !BlockUDP("a.quic.test") {
		t.Fatal("a matched host must be pushed onto TCP")
	}
	if BlockUDP("unrelated.test") || BlockUDP("") {
		t.Fatal("only matched hosts are affected")
	}
}
