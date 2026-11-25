package executor

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/component/snifake"
	"github.com/metacubex/mihomo/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCealingRulesWiring covers the configuration surface of the Cealing-Host
// support: inline cealing-rules, cealing-files, and the legacy sni-mimic map.
// It lives here because config.Parse links against temporaryUpdateGeneral,
// which this package provides.
func TestCealingRulesWiring(t *testing.T) {
	snifake.ResetRules()
	defer snifake.ResetRules()

	_, err := config.Parse([]byte(`
mixed-port: 7890
cealing-rules:
  - [["*cealed.test"], "g.cn", "9.9.9.9"]
  - [["*.no-sni.test"], null, ""]
sni-mimic:
  legacy.test: "ok.test"
sni-mitm: true
`))
	require.NoError(t, err)

	plan, ok := snifake.PlanFor("a.cealed.test")
	require.True(t, ok)
	assert.Equal(t, "g.cn", plan.SNI)
	assert.Equal(t, "9.9.9.9", plan.DialTo)

	removed, ok := snifake.PlanFor("x.no-sni.test")
	require.True(t, ok)
	assert.Equal(t, snifake.ModeRemove, removed.Mode)
	// an empty ip means 127.0.0.1, exactly like upstream
	assert.Equal(t, "127.0.0.1", removed.DialTo)

	legacy, ok := snifake.PlanFor("sub.legacy.test")
	require.True(t, ok)
	assert.Equal(t, "ok.test", legacy.SNI)
	assert.Empty(t, legacy.DialTo)

	assert.True(t, snifake.MITMEnabled())
}

// TestCealingFilesWiring loads a rule document from disk, including the
// comments and trailing commas that published files contain.
func TestCealingFilesWiring(t *testing.T) {
	snifake.ResetRules()
	defer snifake.ResetRules()

	path := filepath.Join(t.TempDir(), "Cealing-Host.json")
	body := `[
  // a comment, allowed upstream
  [["*file.test"],"g.cn","8.8.8.8"],
]`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	_, err := config.Parse([]byte(`
mixed-port: 7890
cealing-files:
  - ` + filepath.ToSlash(path) + `
`))
	require.NoError(t, err)

	_, ok := snifake.PlanFor("x.file.test")
	require.True(t, ok)
	ip, ok := snifake.LookupIP("x.file.test")
	require.True(t, ok)
	assert.Equal(t, "8.8.8.8", ip)
}

// TestCealingRulesRelativeToHome resolves a relative cealing-files entry
// against the configured home directory.
func TestCealingRulesRelativeToHome(t *testing.T) {
	snifake.ResetRules()
	defer snifake.ResetRules()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.json"),
		[]byte(`[[["*rel.test"],"g.cn","7.7.7.7"]]`), 0o600))
	C.SetHomeDir(dir)

	_, err := config.Parse([]byte(`
mixed-port: 7890
cealing-files:
  - rules.json
`))
	require.NoError(t, err)

	ip, ok := snifake.LookupIP("a.rel.test")
	require.True(t, ok)
	assert.Equal(t, "7.7.7.7", ip)
}

// TestCealingRulesInvalidDoesNotAbortConfig keeps a broken entry from taking
// the whole configuration down.
func TestCealingRulesInvalidDoesNotAbortConfig(t *testing.T) {
	snifake.ResetRules()
	defer snifake.ResetRules()

	_, err := config.Parse([]byte(`
mixed-port: 7890
cealing-rules:
  - ["only-two"]
  - [["*good.test"],"g.cn","1.1.1.1"]
`))
	require.NoError(t, err)

	_, ok := snifake.PlanFor("nope.test")
	assert.False(t, ok, "malformed rule must not match anything")
	assert.True(t, snifake.Enabled())
}
