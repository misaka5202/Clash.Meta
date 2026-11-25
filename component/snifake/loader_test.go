package snifake

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

const cealingSample = `[
    // pixelmote fixed ip, generated SNI is empty -> random host name
    [["*pximg.net"],"","210.140.139.133"],
    [["*pinterest.com","*pinimg.com"],"","151.101.0.84"],
    [["gemini.google.com"],"g.cn","47.102.115.14"],
    [["*.googlevideo.com"],null,""],
    [["*wik*.org^*wikipedia.org"],"mirror.test","9.9.9.9"], /* block comment */
    [["^*disabled.example"],"x.test","1.1.1.1"],
]`

func TestParseCealingJSON(t *testing.T) {
	rules, err := ParseCealingJSON([]byte(cealingSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rules) != 6 {
		t.Fatalf("got %d rules want 6", len(rules))
	}
	ResetRules()
	defer ResetRules()
	for _, r := range rules {
		if err := AddCealingRule(r); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	plan, ok := PlanFor("i.pximg.net")
	if !ok || plan.Mode != ModeRandom || len(plan.SNI) < 5 {
		t.Fatalf("pximg: %+v %v", plan, ok)
	}
	if again, _ := PlanFor("i.pximg.net"); again.SNI == plan.SNI {
		t.Fatal("random SNI must differ per connection")
	}
	if ip, ok := LookupIP("i.pximg.net"); !ok || ip != "210.140.139.133" {
		t.Fatalf("pximg ip: %q %v", ip, ok)
	}
	if plan, ok := PlanFor("gemini.google.com"); !ok || plan.SNI != "g.cn" {
		t.Fatalf("google: %+v %v", plan, ok)
	}
	if plan, ok := PlanFor("r1.sn.googlevideo.com"); !ok || plan.Mode != ModeRemove {
		t.Fatalf("googlevideo: %+v %v", plan, ok)
	}
	// empty ip -> 127.0.0.1, which Cealing uses to force a local stop
	if ip, ok := LookupIP("r1.sn.googlevideo.com"); !ok || ip != "127.0.0.1" {
		t.Fatalf("googlevideo ip: %q %v", ip, ok)
	}
	if _, ok := PlanFor("disabled.example"); ok {
		t.Fatal("leading ^ must disable the rule")
	}
	if _, ok := PlanFor("wikinews.org"); !ok {
		t.Fatal("exclusion rule lost")
	}
}

func TestParseCealingJSONBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(`[[["*b64.test"],"g.cn","8.8.8.8"]]`))
	rules, err := ParseCealingJSON([]byte(enc))
	if err != nil {
		t.Fatalf("base64 parse: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d want 1", len(rules))
	}
}

func TestLoadRulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cealing-Host.json")
	if err := os.WriteFile(path, []byte(cealingSample), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRulesFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) != 6 {
		t.Fatalf("got %d want 6", len(rules))
	}
	if _, err := LoadRulesFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestParseCealingJSONRejectsGarbage(t *testing.T) {
	if _, err := ParseCealingJSON([]byte("not json at all !!")); err == nil {
		t.Fatal("garbage must error")
	}
	if _, err := ParseCealingJSON([]byte("")); err == nil {
		t.Fatal("empty must error")
	}
	if err := AddCealingRule([]any{"x"}); err == nil {
		t.Fatal("malformed rule must error")
	}
}

func TestRandomHostShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		h := randomHost()
		if len(h) < 6 || !dotSplitOK(h) {
			t.Fatalf("odd host %q", h)
		}
		if seen[h] {
			t.Fatalf("random host repeated: %q", h)
		}
		seen[h] = true
	}
}

func dotSplitOK(h string) bool {
	n := 0
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			n++
		}
	}
	return n == 1
}
