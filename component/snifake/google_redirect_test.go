package snifake

import "testing"

// TestGoogleRegionalRedirectCovered verifies that a google.com rule also
// covers google.com.hk, the target of Google's mainland hkredirect. Without
// this, the browser follows the 302 to an uncovered domain, leaks the real
// SNI and cannot open the page.
func TestGoogleRegionalRedirectCovered(t *testing.T) {
	ResetRules()
	defer ResetRules()
	if err := AddCealingRule([]any{
		[]any{"*google.com"}, "g.cn", "1.2.3.4",
	}); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{
		"www.google.com",
		"www.google.com.hk",
		"google.com.hk",
		"www.google.com.tw",
	} {
		plan, ok := PlanFor(host)
		if !ok {
			t.Errorf("%s is not covered by the google rule", host)
			continue
		}
		if plan.SNI != "g.cn" {
			t.Errorf("%s SNI = %q, want g.cn", host, plan.SNI)
		}
	}
}
