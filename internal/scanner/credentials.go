package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkCredentialExposure scans web roots for exposed secrets (.env, .git, SSH keys).
func checkCredentialExposure() []Finding {
	var findings []Finding

	webRoots := detectWebRoots()

	envCount := 0
	gitCount := 0

	for _, root := range webRoots {
		// Check .env files with world-readable permissions
		envPath := filepath.Join(root, ".env")
		if info, err := os.Stat(envPath); err == nil {
			if info.Mode()&0004 != 0 {
				content, _ := os.ReadFile(envPath)
				if containsSensitiveKeys(string(content)) {
					envCount++
					findings = append(findings, Finding{
						Category:       "credentials",
						Severity:       "critical",
						CheckID:        "CRED_ENV_WORLD_READABLE",
						Title:          "World-readable .env with secrets",
						Description:    fmt.Sprintf("%s is world-readable and contains sensitive keys", envPath),
						Recommendation: fmt.Sprintf("Run: chmod 640 %s", envPath),
						Details:        map[string]string{"path": envPath},
						Passed:         false,
					})
				}
			}
		}

		// Check .git directory exposed in web root
		gitConfig := filepath.Join(root, ".git/config")
		if fileExists(gitConfig) {
			// Skip if web root is under public/ (Laravel/Symfony — .git is above web root)
			if !strings.HasSuffix(root, "/public") && !strings.HasSuffix(root, "/public_html") {
				gitCount++
				findings = append(findings, Finding{
					Category:       "credentials",
					Severity:       "high",
					CheckID:        "CRED_GIT_EXPOSED",
					Title:          ".git directory in web root",
					Description:    fmt.Sprintf("%s/.git is accessible — source code and history may be exposed", root),
					Recommendation: "Add a deny rule in your web server config for .git directories",
					Details:        map[string]string{"path": root},
					Passed:         false,
				})
			}
		}
	}

	// Check SSH directory permissions
	sshDir := "/root/.ssh"
	if info, err := os.Stat(sshDir); err == nil {
		passed := info.Mode()&0077 == 0
		findings = append(findings, Finding{
			Category:       "credentials",
			Severity:       "high",
			CheckID:        "CRED_SSH_DIR_PERMS",
			Title:          ".ssh directory permissions",
			Description:    fmt.Sprintf("%s has permissions %04o", sshDir, info.Mode().Perm()),
			Recommendation: "Run: chmod 700 /root/.ssh",
			Details:        map[string]string{"current": fmt.Sprintf("%04o", info.Mode().Perm())},
			Passed:         passed,
		})
	}

	// If no credential issues found, report clean
	if envCount == 0 && gitCount == 0 {
		findings = append(findings, Finding{
			Category:    "credentials",
			Severity:    "info",
			CheckID:     "CRED_CLEAN",
			Title:       "No exposed credentials found",
			Description: "No world-readable .env files or exposed .git directories detected",
			Passed:      true,
		})
	}

	return findings
}

// detectWebRoots finds common web root directories.
func detectWebRoots() []string {
	var roots []string

	// Scan /var/www for subdirectories
	entries, err := os.ReadDir("/var/www")
	if err != nil {
		return roots
	}

	for _, entry := range entries {
		if entry.IsDir() {
			roots = append(roots, filepath.Join("/var/www", entry.Name()))
		}
	}

	// Also check common standalone roots
	for _, dir := range []string{"/usr/share/nginx/html", "/var/www/html"} {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			// Avoid duplicates
			found := false
			for _, r := range roots {
				if r == dir {
					found = true
					break
				}
			}
			if !found {
				roots = append(roots, dir)
			}
		}
	}

	return roots
}

func containsSensitiveKeys(content string) bool {
	keys := []string{"DB_PASSWORD=", "DATABASE_URL=", "SECRET_KEY=", "API_KEY=", "AWS_SECRET=", "STRIPE_SECRET=", "APP_KEY="}
	for _, key := range keys {
		if strings.Contains(content, key) {
			return true
		}
	}
	return false
}

// fileExists is defined in webserver.go
