package remediation

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Fixer is a function that applies a fix and returns (output, error).
type Fixer func() (string, error)

// Fixers maps check IDs to their remediation functions.
var Fixers = map[string]Fixer{
	"PERM_SHADOW":             fixPermShadow,
	"PERM_PASSWD":             fixPermPasswd,
	"PERM_SSHD_CONFIG":        fixPermSshdConfig,
	"PERM_AUTH_KEYS":          fixAuthKeys,
	"SSH_X11_FORWARDING":      func() (string, error) { return setSshdOption("X11Forwarding", "no") },
	"SSH_MAX_AUTH_TRIES":      func() (string, error) { return setSshdOption("MaxAuthTries", "3") },
	"WS_SERVER_TOKENS":        fixNginxServerTokens,
	"WS_SERVER_TOKENS_APACHE": fixApacheServerTokens,
	"WS_SERVER_SIGNATURE":     fixApacheServerSignature,
	"WS_SEC_HEADERS":          fixNginxSecHeaders,
	"WS_DIRECTORY_LISTING":    fixApacheDirectoryListing,
	"WS_TRACE_METHOD":         fixApacheTraceMethod,
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// ─── File permission fixers ───

func fixPermShadow() (string, error) {
	return run("chmod", "640", "/etc/shadow")
}

func fixPermPasswd() (string, error) {
	return run("chmod", "644", "/etc/passwd")
}

func fixPermSshdConfig() (string, error) {
	return run("chmod", "600", "/etc/ssh/sshd_config")
}

func fixAuthKeys() (string, error) {
	// Fix permissions on all ~/.ssh/authorized_keys files for non-root users
	entries, err := os.ReadDir("/home")
	if err != nil {
		return "", fmt.Errorf("cannot read /home: %w", err)
	}

	var sb strings.Builder
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		keyPath := fmt.Sprintf("/home/%s/.ssh/authorized_keys", e.Name())
		if _, err := os.Stat(keyPath); err != nil {
			continue
		}
		out, err := exec.Command("chmod", "600", keyPath).CombinedOutput()
		sb.WriteString(fmt.Sprintf("chmod 600 %s: %s\n", keyPath, string(out)))
		if err != nil {
			return sb.String(), err
		}
	}

	if sb.Len() == 0 {
		return "no authorized_keys files found", nil
	}
	return sb.String(), nil
}

// ─── SSH config fixers ───

// setSshdOption sets (or adds) a key=value directive in sshd_config and restarts sshd.
func setSshdOption(key, value string) (string, error) {
	const path = "/etc/ssh/sshd_config"

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	content := string(data)
	re := regexp.MustCompile(`(?im)^#?\s*` + regexp.QuoteMeta(key) + `\s.*$`)

	replacement := fmt.Sprintf("%s %s", key, value)
	if re.MatchString(content) {
		content = re.ReplaceAllString(content, replacement)
	} else {
		content = content + "\n" + replacement + "\n"
	}

	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}

	out, err := exec.Command("systemctl", "restart", "sshd").CombinedOutput()
	return fmt.Sprintf("set %s %s in sshd_config; restart: %s", key, value, string(out)), err
}

// ─── Nginx fixers ───

func fixNginxServerTokens() (string, error) {
	const path = "/etc/nginx/nginx.conf"

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	content := string(data)
	re := regexp.MustCompile(`(?im)^(\s*)#?\s*server_tokens\s+\S+;`)

	if re.MatchString(content) {
		content = re.ReplaceAllString(content, "${1}server_tokens off;")
	} else {
		// Insert inside http { block
		content = insertInHTTPBlock(content, "    server_tokens off;")
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}

	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	return fmt.Sprintf("set server_tokens off; reload: %s", string(out)), err
}

func fixNginxSecHeaders() (string, error) {
	const path = "/etc/nginx/nginx.conf"

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	content := string(data)
	var added []string

	if !strings.Contains(content, "X-Content-Type-Options") {
		content = insertInHTTPBlock(content, "    add_header X-Content-Type-Options nosniff;")
		added = append(added, "X-Content-Type-Options")
	}
	if !strings.Contains(content, "X-Frame-Options") {
		content = insertInHTTPBlock(content, "    add_header X-Frame-Options SAMEORIGIN;")
		added = append(added, "X-Frame-Options")
	}

	if len(added) == 0 {
		return "headers already present", nil
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}

	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	return fmt.Sprintf("added headers %v; reload: %s", added, string(out)), err
}

// insertInHTTPBlock inserts a line after the first `http {` line.
func insertInHTTPBlock(content, line string) string {
	re := regexp.MustCompile(`(?m)^(http\s*\{)`)
	return re.ReplaceAllStringFunc(content, func(m string) string {
		return m + "\n" + line
	})
}

// ─── Apache fixers ───

func fixApacheServerTokens() (string, error) {
	return setApacheDirective("ServerTokens", "Prod")
}

func fixApacheServerSignature() (string, error) {
	return setApacheDirective("ServerSignature", "Off")
}

func fixApacheDirectoryListing() (string, error) {
	return setApacheDirective("Options", "-Indexes")
}

func fixApacheTraceMethod() (string, error) {
	return setApacheDirective("TraceEnable", "Off")
}

// setApacheDirective sets (or adds) a directive in the main Apache config and restarts Apache.
func setApacheDirective(key, value string) (string, error) {
	path := "/etc/apache2/apache2.conf"
	if _, err := os.Stat(path); err != nil {
		path = "/etc/httpd/conf/httpd.conf"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	content := string(data)
	re := regexp.MustCompile(`(?im)^#?\s*` + regexp.QuoteMeta(key) + `\s.*$`)
	replacement := fmt.Sprintf("%s %s", key, value)

	if re.MatchString(content) {
		content = re.ReplaceAllString(content, replacement)
	} else {
		content = content + "\n" + replacement + "\n"
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("cannot write %s: %w", path, err)
	}

	// Try apache2 (Debian) then httpd (RHEL)
	restartCmd := "apache2"
	if _, err := exec.LookPath("apache2"); err != nil {
		restartCmd = "httpd"
	}

	out, err := exec.Command("systemctl", "restart", restartCmd).CombinedOutput()
	return fmt.Sprintf("set %s %s; restart: %s", key, value, string(out)), err
}
