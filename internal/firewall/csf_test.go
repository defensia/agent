package firewall

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// withCSFDir points csfDir at dir for the duration of the test and restores
// the production default afterwards. Tests using this helper are NOT
// t.Parallel because csfDir is a package-level variable.
func withCSFDir(t *testing.T, dir string) {
	t.Helper()
	prev := csfDir
	csfDir = dir
	t.Cleanup(func() { csfDir = prev })
}

func TestCSFSeamDefaults(t *testing.T) {
	if csfDir != "/etc/csf" {
		t.Fatalf("csfDir default = %q, want /etc/csf", csfDir)
	}
	if got := csfPath("csf.conf"); got != "/etc/csf/csf.conf" {
		t.Fatalf("csfPath(%q) = %q, want /etc/csf/csf.conf", "csf.conf", got)
	}
}

func TestParseCSFVersion(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "original 15.00",
			out:  "csf: v15.00 (generic)",
			want: "15.00",
		},
		{
			name: "missing LWP warning then version line",
			out:  "*WARNING* URLGET set to use LWP but perl module is not installed, reverting to HTTP::Tiny\ncsf: v15.00 (generic)",
			want: "15.00",
		},
		{
			name: "aetherinox multi-line",
			out:  "ConfigServer Security & Firewall\nv15.10 (generic)\nLicense: None\nChannel: Stable Channel",
			want: "15.10",
		},
		{
			name: "sentinel 15.11",
			out:  "csf: v15.11 (generic)",
			want: "15.11",
		},
		{
			name: "da-csf directadmin",
			out:  "csf: v15.12 (DirectAdmin)",
			want: "15.12",
		},
		{
			name: "legacy short form",
			out:  "csf: v14.20",
			want: "14.20",
		},
		{
			name: "empty output",
			out:  "",
			want: "",
		},
		{
			name: "garbage output",
			out:  "garbage\n",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCSFVersion([]byte(tc.out))
			if got != tc.want {
				t.Errorf("parseCSFVersion(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}

func TestCSFConfigValue(t *testing.T) {
	dir := t.TempDir()
	withCSFDir(t, dir)

	conf := "# TCP_IN = \"1\"\n" +
		"TCP_IN = \"20,21,22\"\n" +
		"TCP_OUT = \"80,443\"\n" +
		"TESTING = \"0\"\n"
	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("write csf.conf: %v", err)
	}

	if got := csfConfigValue("TCP_IN"); got != "20,21,22" {
		t.Errorf("csfConfigValue(TCP_IN) = %q, want 20,21,22", got)
	}
	if got := csfConfigValue("TCP_OUT"); got != "80,443" {
		t.Errorf("csfConfigValue(TCP_OUT) = %q, want 80,443", got)
	}
	if got := csfConfigValue("TESTING"); got != "0" {
		t.Errorf("csfConfigValue(TESTING) = %q, want 0", got)
	}
	if got := csfConfigValue("MISSING"); got != "" {
		t.Errorf("csfConfigValue(MISSING) = %q, want empty", got)
	}
}

func TestCSFConfigValueNoFile(t *testing.T) {
	withCSFDir(t, t.TempDir())
	if got := csfConfigValue("TCP_IN"); got != "" {
		t.Errorf("csfConfigValue with no file = %q, want empty", got)
	}
}

func TestCSFListEntries(t *testing.T) {
	dir := t.TempDir()
	content := "# header comment\n" +
		"\n" +
		"1.2.3.4 # reason x\n" +
		"5.6.7.0/24\n" +
		"  9.9.9.9  \n"
	path := filepath.Join(dir, "csf.deny")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write csf.deny: %v", err)
	}

	got := csfListEntries(path)
	want := []CSFDenyEntry{
		{IP: "1.2.3.4", Kind: "ip", Comment: "reason x"},
		{IP: "5.6.7.0/24", Kind: "cidr", Comment: ""},
		{IP: "9.9.9.9", Kind: "ip", Comment: ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("csfListEntries() = %#v, want %#v", got, want)
	}
}

func TestCSFListEntriesMissingFile(t *testing.T) {
	got := csfListEntries(filepath.Join(t.TempDir(), "does-not-exist"))
	if got != nil {
		t.Errorf("csfListEntries(missing) = %#v, want nil", got)
	}
}

func TestCSFListEntriesCommentOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csf.deny")
	content := "# only comments\n# nothing else\n\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write csf.deny: %v", err)
	}
	got := csfListEntries(path)
	if len(got) != 0 {
		t.Errorf("csfListEntries(comment-only) len = %d, want 0", len(got))
	}
	if got != nil {
		t.Errorf("csfListEntries(comment-only) = %#v, want nil", got)
	}
}

func TestCSFDenyAllowListUseCSFDir(t *testing.T) {
	dir := t.TempDir()
	withCSFDir(t, dir)

	denyContent := "1.1.1.1\n2.2.2.2\n"
	allowContent := "3.3.3.3\n"
	if err := os.WriteFile(filepath.Join(dir, "csf.deny"), []byte(denyContent), 0o644); err != nil {
		t.Fatalf("write csf.deny: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "csf.allow"), []byte(allowContent), 0o644); err != nil {
		t.Fatalf("write csf.allow: %v", err)
	}

	deny := CSFDenyList()
	if len(deny) != 2 {
		t.Fatalf("CSFDenyList() len = %d, want 2 (%#v)", len(deny), deny)
	}
	allow := CSFAllowList()
	if len(allow) != 1 {
		t.Fatalf("CSFAllowList() len = %d, want 1 (%#v)", len(allow), allow)
	}
}

func TestCSFInfoFrom(t *testing.T) {
	dir := t.TempDir()
	withCSFDir(t, dir)

	conf := "TCP_IN = \"20,21,22\"\nTCP_OUT = \"80,443\"\n"
	if err := os.WriteFile(filepath.Join(dir, "csf.conf"), []byte(conf), 0o644); err != nil {
		t.Fatalf("write csf.conf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "csf.deny"), []byte("1.1.1.1\n2.2.2.2\n"), 0o644); err != nil {
		t.Fatalf("write csf.deny: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "csf.allow"), []byte("3.3.3.3\n"), 0o644); err != nil {
		t.Fatalf("write csf.allow: %v", err)
	}

	got := csfInfoFrom([]byte("csf: v15.00 (generic)"))
	want := CSFStatus{
		Installed:  true,
		Version:    "15.00",
		PortsIn:    "20,21,22",
		PortsOut:   "80,443",
		DenyCount:  2,
		AllowCount: 1,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("csfInfoFrom(valid out) = %#v, want %#v", got, want)
	}

	gotNil := csfInfoFrom(nil)
	if gotNil.Version != "" {
		t.Errorf("csfInfoFrom(nil).Version = %q, want empty", gotNil.Version)
	}
}
