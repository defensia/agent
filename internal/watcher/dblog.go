package watcher

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DBPattern pairs a compiled regex with the event reason.
type DBPattern struct {
	Re     *regexp.Regexp
	Reason string
}

// dbPatterns contains all database auth detection patterns.
// Each regex must have a capture group for the IP address.
//
// MySQL / MariaDB:
//   - "Access denied for user 'root'@'X.X.X.X'"
//   - "Host 'X.X.X.X' is blocked because of many connection errors"
//   - "Aborted connection ... (Got an error reading communication packets) host: 'X.X.X.X'"
//
// PostgreSQL:
//   - "FATAL: password authentication failed for user ... connection ... host=X.X.X.X"
//   - "FATAL: no pg_hba.conf entry for host \"X.X.X.X\""
//   - "LOG: could not receive data from client: Connection reset by peer ... host=X.X.X.X"
//
// MongoDB:
//   - "Failed to authenticate ... client: X.X.X.X"
//   - "Unauthorized ... client: X.X.X.X"
var dbPatterns = []DBPattern{
	// ── MySQL / MariaDB ───────────────────────────────────────────────
	{Re: regexp.MustCompile(`Access denied for user '\S+'@'([\d.]+)'`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`Host '([\d.]+)' is blocked because of many connection errors`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`Aborted connection.*host:\s*'([\d.]+)'`), Reason: "db_suspicious"},

	// ── PostgreSQL ────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`FATAL:\s+password authentication failed for user.*host[= ]+"?([\d.]+)`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`FATAL:\s+no pg_hba\.conf entry for host "?([\d.]+)`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`could not receive data from client.*host[= ]+"?([\d.]+)`), Reason: "db_suspicious"},

	// ── MongoDB ───────────────────────────────────────────────────────
	{Re: regexp.MustCompile(`(?:Failed to authenticate|Authentication failed).*client:\s*([\d.]+)`), Reason: "db_brute_force"},
	{Re: regexp.MustCompile(`Unauthorized.*client:\s*([\d.]+)`), Reason: "db_brute_force"},
}

// DBLogPath holds a detected database log path and its type.
type DBLogPath struct {
	Path   string
	DBType string // "mysql", "postgresql", "mongodb"
}

// DBWatcher tails database logs and calls onBan when an IP exceeds the threshold.
type DBWatcher struct {
	logPaths []DBLogPath
	onBan    BanFunc
	onEvent  EventFunc
	checkIP  CheckIPFunc

	mu          sync.Mutex
	threshold   int
	window      time.Duration
	attempts    map[string][]time.Time
	banned      map[string]bool
	whitelist   map[string]bool
	wlNets      []*net.IPNet
	monitorMode bool
}

// detectDBLogPaths returns all detected database log paths.
func detectDBLogPaths() []DBLogPath {
	if p := os.Getenv("DB_LOG_PATH"); p != "" {
		return []DBLogPath{{Path: p, DBType: "custom"}}
	}

	var paths []DBLogPath

	// MySQL / MariaDB
	mysqlPaths := []string{
		"/var/log/mysql/error.log",
		"/var/log/mysqld.log",
		"/var/log/mariadb/mariadb.log",
		"/var/log/mysql/mysql-error.log",
	}
	for _, p := range mysqlPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, DBLogPath{Path: p, DBType: "mysql"})
			break // one MySQL log is enough
		}
	}

	// PostgreSQL
	pgPaths := []string{
		"/var/log/postgresql/postgresql-main.log",
		"/var/log/postgresql/postgresql.log",
	}
	for _, p := range pgPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, DBLogPath{Path: p, DBType: "postgresql"})
			break
		}
	}
	// Also check pg_log directories (version-specific)
	pgDirs := []string{"/var/lib/pgsql/data/pg_log", "/var/lib/pgsql/data/log"}
	for _, dir := range pgDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
				paths = append(paths, DBLogPath{Path: dir + "/" + e.Name(), DBType: "postgresql"})
				break
			}
		}
		break
	}

	// MongoDB
	mongoPaths := []string{
		"/var/log/mongodb/mongod.log",
		"/var/log/mongod.log",
	}
	for _, p := range mongoPaths {
		if _, err := os.Stat(p); err == nil {
			paths = append(paths, DBLogPath{Path: p, DBType: "mongodb"})
			break
		}
	}

	return paths
}

// HasDBService returns true if a database server is detected.
func HasDBService() bool {
	for _, svc := range []string{"mysql", "mysqld", "mariadb", "postgresql", "mongod"} {
		if out, err := exec.Command("systemctl", "is-active", svc).Output(); err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return true
			}
		}
	}
	return len(detectDBLogPaths()) > 0
}

// ExposedDBPorts checks if database ports are publicly accessible and returns warnings.
func ExposedDBPorts() []string {
	dbPorts := map[int]string{
		3306:  "MySQL/MariaDB",
		5432:  "PostgreSQL",
		27017: "MongoDB",
		6379:  "Redis",
	}

	var warnings []string
	for port, name := range dbPorts {
		// Check if port is listening
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("0.0.0.0:%d", port), 2*time.Second)
		if err != nil {
			continue
		}
		conn.Close()

		// Port is listening — check if it's bound to 0.0.0.0 (all interfaces)
		out, err := exec.Command("ss", "-tlnp", fmt.Sprintf("sport = %d", port)).Output()
		if err != nil {
			continue
		}
		output := string(out)
		if strings.Contains(output, "0.0.0.0:"+fmt.Sprintf("%d", port)) || strings.Contains(output, "*:"+fmt.Sprintf("%d", port)) {
			warnings = append(warnings, fmt.Sprintf("%s is exposed publicly on port %d", name, port))
		}
	}

	return warnings
}

// NewDBWatcher creates a watcher for database logs.
// Returns nil if no database logs are found.
func NewDBWatcher(onBan BanFunc) *DBWatcher {
	paths := detectDBLogPaths()
	if len(paths) == 0 {
		return nil
	}

	return &DBWatcher{
		logPaths:  paths,
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     onBan,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

func (w *DBWatcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

func (w *DBWatcher) SetOnEvent(fn EventFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onEvent = fn
}

func (w *DBWatcher) SetMonitorMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.monitorMode = enabled
}

func (w *DBWatcher) UpdateConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if cfg.Threshold > 0 {
		w.threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		w.window = cfg.Window
	}
}

func (w *DBWatcher) UpdateWhitelist(ips []string, cidrs []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.whitelist = make(map[string]bool, len(ips))
	for _, ip := range ips {
		w.whitelist[ip] = true
	}
	w.wlNets = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			w.wlNets = append(w.wlNets, ipNet)
		}
	}
}

func (w *DBWatcher) isWhitelisted(ip string) bool {
	if w.whitelist[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range w.wlNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Run starts tailing all detected database log files. Blocks indefinitely.
func (w *DBWatcher) Run() {
	for _, lp := range w.logPaths {
		log.Printf("[dbwatcher] watching %s (%s) (threshold: %d in %s)", lp.Path, lp.DBType, w.threshold, w.window)
		go w.tailFile(lp.Path)
	}
	// Block forever
	select {}
}

func (w *DBWatcher) tailFile(path string) {
	for {
		if err := w.tail(path); err != nil {
			log.Printf("[dbwatcher] error tailing %s: %v — retrying in 5s", path, err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *DBWatcher) tail(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		fi, err = os.Stat(path)
		if err != nil {
			return err
		}
		size := fi.Size()
		if size <= offset {
			if size < offset {
				offset = 0
			}
			continue
		}

		readF, err := os.Open(path)
		if err != nil {
			return err
		}
		readF.Seek(offset, io.SeekStart)
		buf := make([]byte, size-offset)
		n, err := io.ReadFull(readF, buf)
		readF.Close()

		if n > 0 {
			partial += string(buf[:n])
			offset += int64(n)
			for {
				idx := strings.IndexByte(partial, '\n')
				if idx < 0 {
					break
				}
				w.processLine(partial[:idx])
				partial = partial[idx+1:]
			}
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
	}
	return nil
}

func (w *DBWatcher) processLine(line string) {
	var ip, reason string
	for _, p := range dbPatterns {
		m := p.Re.FindStringSubmatch(line)
		if len(m) >= 2 {
			ip = m[1]
			reason = p.Reason
			break
		}
	}
	if ip == "" {
		return
	}
	if isPrivateIP(ip) {
		return
	}
	w.recordAttempt(ip, reason)
}

func (w *DBWatcher) recordAttempt(ip, reason string) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}
	if w.isWhitelisted(ip) {
		return
	}

	// Geoblocking
	if w.checkIP != nil {
		if banReason := w.checkIP(ip); banReason != "" {
			w.banned[ip] = true
			if w.monitorMode {
				if w.onEvent != nil {
					go w.onEvent(ip, reason, "critical", map[string]string{"reason": banReason})
				}
			} else {
				go w.onBan(ip, banReason, 1)
			}
			return
		}
	}

	// Report event
	if w.onEvent != nil {
		severity := "warning"
		if reason == "db_brute_force" {
			severity = "critical"
		}
		go w.onEvent(ip, reason, severity, map[string]string{})
	}

	// Threshold
	var recent []time.Time
	for _, t := range w.attempts[ip] {
		if now.Sub(t) <= w.window {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	w.attempts[ip] = recent

	if len(recent) >= w.threshold {
		w.banned[ip] = true
		count := len(recent)
		if !w.monitorMode {
			go w.onBan(ip, reason, count)
		}
	}
}
