package modsecurity

import (
	"os"
	"path/filepath"
	"testing"
)

// A customer serving from OpenLiteSpeed with ols-modsecurity, OWASP CRS and thousands of
// 403s in their error log was told ModSecurity was "not installed", because detection
// only ever asked apachectl.
func TestLiteSpeedModSecurityDetection(t *testing.T) {
	// The block shape OpenLiteSpeed writes in httpd_config.conf.
	enabled := `
serverName                OLS
module mod_security {
  modsecurity  on
  modsecurity_rules ` + "`" + `
    SecRuleEngine On
  ` + "`" + `
  ls_enabled              1
}
`
	disabled := `
module mod_security {
  modsecurity  off
  ls_enabled              0
}
`
	absent := `
serverName                OLS
module cache {
  ls_enabled              1
}
`

	cases := []struct {
		name        string
		config      string
		writeModule bool
		want        bool
	}{
		{"module present and switched on", enabled, true, true},
		{"module present but switched off", disabled, true, false},
		{"no mod_security block at all", absent, true, false},
		// The .so missing means OpenLiteSpeed cannot load it whatever the config says.
		{"config says on but module is not installed", enabled, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "httpd_config.conf")
			if err := os.WriteFile(cfg, []byte(tc.config), 0o600); err != nil {
				t.Fatal(err)
			}

			so := filepath.Join(dir, "mod_security.so")
			if tc.writeModule {
				if err := os.WriteFile(so, []byte("ELF"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if got := liteSpeedModSecurityAt([]string{so}, cfg); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLiteSpeedDetectionIsSafeWhenNothingIsInstalled(t *testing.T) {
	dir := t.TempDir()
	if liteSpeedModSecurityAt(
		[]string{filepath.Join(dir, "nope.so")},
		filepath.Join(dir, "nope.conf"),
	) {
		t.Error("reported ModSecurity on a box with no OpenLiteSpeed at all")
	}
}
