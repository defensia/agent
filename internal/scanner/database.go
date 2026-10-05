package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// checkDatabaseConfig performs security audits on MySQL, PostgreSQL, Redis,
// and MongoDB configurations. Checks for common misconfigurations that leave
// databases vulnerable to unauthorized access.
func checkDatabaseConfig() []Finding {
	var findings []Finding
	findings = append(findings, checkMySQLConfig()...)
	findings = append(findings, checkPostgreSQLConfig()...)
	findings = append(findings, checkRedisConfig()...)
	findings = append(findings, checkMongoDBConfig()...)
	return findings
}

// ── MySQL / MariaDB ──────────────────────────────────────────────────────────

func checkMySQLConfig() []Finding {
	// Only run if MySQL/MariaDB is installed
	if !serviceExists("mysql") && !serviceExists("mysqld") && !serviceExists("mariadb") {
		return nil
	}

	var findings []Finding

	// 1. Check bind-address in config
	bindAddr := mysqlConfigValue("bind-address")
	if bindAddr == "0.0.0.0" || bindAddr == "*" || bindAddr == "" {
		findings = append(findings, Finding{
			Category:       "database",
			Severity:       "critical",
			CheckID:        "DB_MYSQL_BIND_ALL",
			Title:          "MySQL bound to all interfaces",
			Description:    "MySQL is listening on all network interfaces (bind-address=" + bindAddr + "). This allows remote connections from any IP.",
			Recommendation: "Set bind-address=127.0.0.1 in /etc/mysql/my.cnf or /etc/my.cnf to restrict to local connections only.",
			Passed:         false,
		})
	} else {
		findings = append(findings, Finding{
			Category: "database", Severity: "info", CheckID: "DB_MYSQL_BIND_ALL",
			Title: "MySQL bind-address restricted", Description: "MySQL is bound to " + bindAddr, Passed: true,
		})
	}

	// 2. Check for anonymous users (try without credentials)
	out, err := exec.Command("mysql", "-u", "", "-e", "SELECT 1", "--batch", "--skip-column-names").CombinedOutput()
	if err == nil && strings.Contains(string(out), "1") {
		findings = append(findings, Finding{
			Category:       "database",
			Severity:       "critical",
			CheckID:        "DB_MYSQL_ANON_USER",
			Title:          "MySQL allows anonymous login",
			Description:    "MySQL accepts connections without a username or password. This is a critical security risk.",
			Recommendation: "Run: DROP USER ''@'localhost'; DROP USER ''@'%'; FLUSH PRIVILEGES;",
			Passed:         false,
		})
	}

	// 3. Check for root without password
	out, err = exec.Command("mysql", "-u", "root", "--password=", "-e", "SELECT 1", "--batch", "--skip-column-names").CombinedOutput()
	if err == nil && strings.Contains(string(out), "1") {
		findings = append(findings, Finding{
			Category:       "database",
			Severity:       "critical",
			CheckID:        "DB_MYSQL_ROOT_NOPASS",
			Title:          "MySQL root has no password",
			Description:    "The MySQL root account can be accessed without a password.",
			Recommendation: "Set a strong root password: ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_password';",
			Passed:         false,
		})
	}

	// 4. Check for remote root access
	out, err = exec.Command("mysql", "-u", "root", "-e",
		"SELECT Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1')",
		"--batch", "--skip-column-names").CombinedOutput()
	if err == nil {
		hosts := strings.TrimSpace(string(out))
		if hosts != "" {
			findings = append(findings, Finding{
				Category:       "database",
				Severity:       "high",
				CheckID:        "DB_MYSQL_ROOT_REMOTE",
				Title:          "MySQL root allows remote login",
				Description:    "The root user can connect from: " + hosts + ". This enables remote root access to the database.",
				Recommendation: "Remove remote root access: DROP USER 'root'@'%'; or restrict to specific IPs.",
				Passed:         false,
			})
		}
	}

	// 5. Check for test database
	out, err = exec.Command("mysql", "-u", "root", "-e",
		"SHOW DATABASES LIKE 'test'", "--batch", "--skip-column-names").CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		findings = append(findings, Finding{
			Category:       "database",
			Severity:       "medium",
			CheckID:        "DB_MYSQL_TEST_DB",
			Title:          "MySQL test database exists",
			Description:    "The default 'test' database exists. It is accessible to anonymous users by default.",
			Recommendation: "Remove it: DROP DATABASE test;",
			Passed:         false,
		})
	}

	// 6. Check SSL enabled
	out, err = exec.Command("mysql", "-u", "root", "-e",
		"SHOW VARIABLES LIKE 'have_ssl'", "--batch", "--skip-column-names").CombinedOutput()
	if err == nil {
		if strings.Contains(string(out), "DISABLED") {
			findings = append(findings, Finding{
				Category:       "database",
				Severity:       "medium",
				CheckID:        "DB_MYSQL_SSL_OFF",
				Title:          "MySQL SSL is disabled",
				Description:    "SSL/TLS encryption for MySQL connections is not enabled.",
				Recommendation: "Enable SSL in my.cnf: ssl-ca, ssl-cert, ssl-key directives, then FLUSH PRIVILEGES.",
				Passed:         false,
			})
		} else if strings.Contains(string(out), "YES") {
			findings = append(findings, Finding{
				Category: "database", Severity: "info", CheckID: "DB_MYSQL_SSL_OFF",
				Title: "MySQL SSL enabled", Passed: true,
			})
		}
	}

	return findings
}

// ── PostgreSQL ───────────────────────────────────────────────────────────────

func checkPostgreSQLConfig() []Finding {
	if !serviceExists("postgresql") {
		return nil
	}

	var findings []Finding

	// 1. Check pg_hba.conf for trust authentication (no password required)
	pgHbaPath := findFile([]string{
		"/etc/postgresql/*/main/pg_hba.conf",
		"/var/lib/pgsql/data/pg_hba.conf",
		"/var/lib/postgresql/data/pg_hba.conf",
	})
	if pgHbaPath != "" {
		data, err := os.ReadFile(pgHbaPath)
		if err == nil {
			trustLines := 0
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					method := fields[len(fields)-1]
					if method == "trust" {
						trustLines++
					}
				}
			}
			if trustLines > 0 {
				findings = append(findings, Finding{
					Category:       "database",
					Severity:       "critical",
					CheckID:        "DB_PG_TRUST_AUTH",
					Title:          "PostgreSQL uses trust authentication",
					Description:    fmt.Sprintf("pg_hba.conf has %d trust entries — connections are accepted without password verification.", trustLines),
					Recommendation: "Change 'trust' to 'scram-sha-256' or 'md5' in " + pgHbaPath + " and reload PostgreSQL.",
					Passed:         false,
				})
			} else {
				findings = append(findings, Finding{
					Category: "database", Severity: "info", CheckID: "DB_PG_TRUST_AUTH",
					Title: "PostgreSQL requires authentication", Passed: true,
				})
			}
		}
	}

	// 2. Check listen_addresses in postgresql.conf
	pgConfPath := findFile([]string{
		"/etc/postgresql/*/main/postgresql.conf",
		"/var/lib/pgsql/data/postgresql.conf",
		"/var/lib/postgresql/data/postgresql.conf",
	})
	if pgConfPath != "" {
		data, err := os.ReadFile(pgConfPath)
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "listen_addresses") {
					if strings.Contains(line, "'*'") || strings.Contains(line, "0.0.0.0") {
						findings = append(findings, Finding{
							Category:       "database",
							Severity:       "high",
							CheckID:        "DB_PG_LISTEN_ALL",
							Title:          "PostgreSQL listening on all interfaces",
							Description:    "listen_addresses is set to '*' or '0.0.0.0' — the database accepts connections from any IP.",
							Recommendation: "Set listen_addresses='localhost' in " + pgConfPath + " unless remote access is required.",
							Passed:         false,
						})
					}
					break
				}
			}
		}
	}

	// 3. Check SSL
	if pgConfPath != "" {
		data, err := os.ReadFile(pgConfPath)
		if err == nil {
			sslEnabled := false
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ssl") && !strings.HasPrefix(line, "ssl_") && strings.Contains(line, "on") {
					sslEnabled = true
					break
				}
			}
			if !sslEnabled {
				findings = append(findings, Finding{
					Category:       "database",
					Severity:       "medium",
					CheckID:        "DB_PG_SSL_OFF",
					Title:          "PostgreSQL SSL disabled",
					Description:    "SSL is not enabled in postgresql.conf.",
					Recommendation: "Set ssl=on in " + pgConfPath + " and configure ssl_cert_file and ssl_key_file.",
					Passed:         false,
				})
			}
		}
	}

	return findings
}

// ── Redis ────────────────────────────────────────────────────────────────────

func checkRedisConfig() []Finding {
	if !serviceExists("redis") && !serviceExists("redis-server") {
		return nil
	}

	var findings []Finding

	confPath := findFile([]string{
		"/etc/redis/redis.conf",
		"/etc/redis.conf",
		"/etc/redis/6379.conf",
	})
	if confPath == "" {
		return nil
	}

	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil
	}
	lines := string(data)

	// 1. Check requirepass
	hasPassword := false
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "requirepass") && !strings.HasPrefix(line, "#") {
			hasPassword = true
			break
		}
	}
	if !hasPassword {
		findings = append(findings, Finding{
			Category:       "database",
			Severity:       "critical",
			CheckID:        "DB_REDIS_NO_PASS",
			Title:          "Redis has no password",
			Description:    "Redis does not require authentication. Anyone with network access can read/write all data.",
			Recommendation: "Add requirepass <strong_password> to " + confPath,
			Passed:         false,
		})
	} else {
		findings = append(findings, Finding{
			Category: "database", Severity: "info", CheckID: "DB_REDIS_NO_PASS",
			Title: "Redis password set", Passed: true,
		})
	}

	// 2. Check bind address
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "bind") && !strings.HasPrefix(line, "#") {
			if strings.Contains(line, "0.0.0.0") || !strings.Contains(line, "127.0.0.1") {
				findings = append(findings, Finding{
					Category:       "database",
					Severity:       "high",
					CheckID:        "DB_REDIS_BIND_ALL",
					Title:          "Redis bound to all interfaces",
					Description:    "Redis is listening on external interfaces without bind restriction.",
					Recommendation: "Set bind 127.0.0.1 in " + confPath,
					Passed:         false,
				})
			}
			break
		}
	}

	// 3. Check protected-mode
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "protected-mode") && !strings.HasPrefix(line, "#") {
			if strings.Contains(line, "no") {
				findings = append(findings, Finding{
					Category:       "database",
					Severity:       "high",
					CheckID:        "DB_REDIS_PROTECTED_OFF",
					Title:          "Redis protected-mode disabled",
					Description:    "Redis protected-mode is off. Combined with no password, this allows unauthenticated access from any IP.",
					Recommendation: "Set protected-mode yes in " + confPath,
					Passed:         false,
				})
			}
			break
		}
	}

	return findings
}

// ── MongoDB ──────────────────────────────────────────────────────────────────

func checkMongoDBConfig() []Finding {
	if !serviceExists("mongod") && !serviceExists("mongos") {
		return nil
	}

	var findings []Finding

	confPath := findFile([]string{
		"/etc/mongod.conf",
		"/etc/mongodb.conf",
	})
	if confPath == "" {
		return nil
	}

	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil
	}
	lines := string(data)

	// 1. Check authorization enabled
	authEnabled := false
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "authorization") && strings.Contains(line, "enabled") {
			authEnabled = true
			break
		}
	}
	if !authEnabled {
		findings = append(findings, Finding{
			Category:       "database",
			Severity:       "critical",
			CheckID:        "DB_MONGO_NO_AUTH",
			Title:          "MongoDB authentication disabled",
			Description:    "MongoDB does not require authentication. Any connection can read/write all databases.",
			Recommendation: "Add security.authorization: enabled to " + confPath + " and create admin user.",
			Passed:         false,
		})
	} else {
		findings = append(findings, Finding{
			Category: "database", Severity: "info", CheckID: "DB_MONGO_NO_AUTH",
			Title: "MongoDB authentication enabled", Passed: true,
		})
	}

	// 2. Check bindIp
	for _, line := range strings.Split(lines, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "bindIp") || strings.HasPrefix(line, "bind_ip") {
			if strings.Contains(line, "0.0.0.0") {
				findings = append(findings, Finding{
					Category:       "database",
					Severity:       "high",
					CheckID:        "DB_MONGO_BIND_ALL",
					Title:          "MongoDB bound to all interfaces",
					Description:    "MongoDB is listening on all network interfaces.",
					Recommendation: "Set bindIp: 127.0.0.1 in " + confPath,
					Passed:         false,
				})
			}
			break
		}
	}

	return findings
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func serviceExists(name string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", name).Run()
	return err == nil
}

func mysqlConfigValue(key string) string {
	paths := []string{"/etc/mysql/my.cnf", "/etc/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf"}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, key) {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	}
	return ""
}

func findFile(globs []string) string {
	for _, pattern := range globs {
		if strings.Contains(pattern, "*") {
			matches, _ := filepath.Glob(pattern)
			if len(matches) > 0 {
				return matches[0]
			}
		} else {
			if _, err := os.Stat(pattern); err == nil {
				return pattern
			}
		}
	}
	return ""
}

// Ensure fmt is used (referenced in PostgreSQL trust auth check).
var _ = fmt.Sprintf
