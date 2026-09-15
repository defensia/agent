package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Change represents a detected file integrity change.
type Change struct {
	Path       string `json:"path"`
	ChangeType string `json:"change_type"` // "modified", "created", "deleted", "permissions", "owner"
	OldHash    string `json:"old_hash,omitempty"`
	NewHash    string `json:"new_hash,omitempty"`
	OldPerms   string `json:"old_perms,omitempty"`
	NewPerms   string `json:"new_perms,omitempty"`
	OldOwner   string `json:"old_owner,omitempty"`
	NewOwner   string `json:"new_owner,omitempty"`
	Severity   string `json:"severity"`
	Domain     string `json:"domain,omitempty"`
}

// FileEntry stores the baseline state of a monitored file.
type FileEntry struct {
	Hash    string `json:"hash"`
	Mode    string `json:"mode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
}

// Baseline holds the full snapshot of monitored files.
type Baseline struct {
	Version   int                  `json:"version"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
	Files     map[string]FileEntry `json:"files"`
}

// WebRoot represents a web directory to monitor.
type WebRoot struct {
	Path   string
	Domain string
}

// Monitor is the FIM engine that manages baselines and detects changes.
type Monitor struct {
	mu           sync.Mutex
	baseline     *Baseline
	baselinePath string
	webRoots     []WebRoot
	onChange     func(Change)
	stopCh       chan struct{}
	running      bool
	interval     time.Duration
}

// Critical system paths to always monitor (small, high-value files).
var systemPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/crontab",
	"/etc/hosts",
	"/etc/hosts.allow",
	"/etc/hosts.deny",
	"/etc/ld.so.preload",
	"/etc/ld.so.conf",
	"/etc/resolv.conf",
	"/etc/rsyslog.conf",
	"/etc/pam.d/sshd",
	"/etc/pam.d/su",
	"/etc/pam.d/sudo",
	"/etc/security/access.conf",
}

// Directories where we monitor all files (configs that change = suspicious).
var systemDirs = []string{
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/etc/sudoers.d",
	"/etc/ssh",
	"/etc/pam.d",
	"/etc/security",
}

// Severity mapping by path prefix.
var severityMap = map[string]string{
	"/etc/shadow":       "critical",
	"/etc/sudoers":      "critical",
	"/etc/ld.so.preload": "critical",
	"/etc/pam.d/":       "critical",
	"/etc/ssh/":         "high",
	"/etc/passwd":       "high",
	"/etc/cron":         "high",
	"/etc/hosts":        "medium",
	"/etc/resolv.conf":  "low",
}

const (
	baselineVersion  = 1
	maxFileSize      = 10 * 1024 * 1024 // 10MB max per file
	defaultInterval  = 5 * time.Minute
	baselineFilename = "fim-baseline.json"
)

// New creates a new FIM monitor.
// onChange is called for each detected change.
func New(onChange func(Change)) *Monitor {
	baseDir := "/etc/defensia"
	if d := os.Getenv("DEFENSIA_DATA_DIR"); d != "" {
		baseDir = d
	}

	return &Monitor{
		baselinePath: filepath.Join(baseDir, baselineFilename),
		onChange:     onChange,
		interval:     defaultInterval,
	}
}

// SetWebRoots configures web directories to monitor for PHP/config changes.
func (m *Monitor) SetWebRoots(roots []WebRoot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webRoots = roots
}

// Start begins the FIM monitoring loop.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.stopCh = make(chan struct{})
	m.running = true
	m.mu.Unlock()

	// Load or create baseline
	if err := m.loadBaseline(); err != nil {
		log.Printf("[fim] no baseline found, creating initial snapshot...")
		m.createBaseline()
	} else {
		log.Printf("[fim] loaded baseline: %d files (created %s)",
			len(m.baseline.Files), m.baseline.CreatedAt.Format("2006-01-02 15:04"))
	}

	go m.loop()
}

// Stop stops the monitoring loop.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.running = false
	}
}

// RebuildBaseline forces a new baseline (e.g., after legitimate changes).
func (m *Monitor) RebuildBaseline() {
	m.createBaseline()
	log.Printf("[fim] baseline rebuilt: %d files", len(m.baseline.Files))
}

func (m *Monitor) loop() {
	// First check after 1 minute (give agent time to settle)
	timer := time.NewTimer(1 * time.Minute)
	select {
	case <-m.stopCh:
		timer.Stop()
		return
	case <-timer.C:
	}

	m.check()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *Monitor) check() {
	m.mu.Lock()
	bl := m.baseline
	roots := make([]WebRoot, len(m.webRoots))
	copy(roots, m.webRoots)
	m.mu.Unlock()

	if bl == nil {
		return
	}

	current := m.snapshot(roots)
	var changes []Change

	// Check for modified and deleted files
	for path, oldEntry := range bl.Files {
		newEntry, exists := current[path]
		if !exists {
			changes = append(changes, Change{
				Path:       path,
				ChangeType: "deleted",
				OldHash:    oldEntry.Hash,
				Severity:   m.severity(path),
				Domain:     m.domainForPath(path, roots),
			})
			continue
		}

		// Content changed
		if oldEntry.Hash != newEntry.Hash {
			changes = append(changes, Change{
				Path:       path,
				ChangeType: "modified",
				OldHash:    oldEntry.Hash,
				NewHash:    newEntry.Hash,
				Severity:   m.severity(path),
				Domain:     m.domainForPath(path, roots),
			})
		}

		// Permissions changed
		if oldEntry.Mode != newEntry.Mode {
			changes = append(changes, Change{
				Path:       path,
				ChangeType: "permissions",
				OldPerms:   oldEntry.Mode,
				NewPerms:   newEntry.Mode,
				Severity:   m.severity(path),
				Domain:     m.domainForPath(path, roots),
			})
		}

		// Owner changed
		if oldEntry.UID != newEntry.UID || oldEntry.GID != newEntry.GID {
			changes = append(changes, Change{
				Path:       path,
				ChangeType: "owner",
				OldOwner:   formatOwner(oldEntry.UID, oldEntry.GID),
				NewOwner:   formatOwner(newEntry.UID, newEntry.GID),
				Severity:   m.severity(path),
				Domain:     m.domainForPath(path, roots),
			})
		}
	}

	// Check for new files (not in baseline)
	for path := range current {
		if _, exists := bl.Files[path]; !exists {
			changes = append(changes, Change{
				Path:       path,
				ChangeType: "created",
				NewHash:    current[path].Hash,
				Severity:   m.severity(path),
				Domain:     m.domainForPath(path, roots),
			})
		}
	}

	if len(changes) > 0 {
		log.Printf("[fim] detected %d changes", len(changes))

		// Cap to avoid flooding
		if len(changes) > 50 {
			log.Printf("[fim] too many changes (%d), reporting first 50", len(changes))
			changes = changes[:50]
		}

		for _, c := range changes {
			if m.onChange != nil {
				m.onChange(c)
			}
		}

		// Update baseline with current state (changes are now the new normal)
		m.mu.Lock()
		m.baseline.Files = current
		m.baseline.UpdatedAt = time.Now().UTC()
		m.mu.Unlock()
		m.saveBaseline()
	}
}

// snapshot captures the current state of all monitored files.
func (m *Monitor) snapshot(roots []WebRoot) map[string]FileEntry {
	files := make(map[string]FileEntry)

	// System files (individual paths)
	for _, path := range systemPaths {
		if entry, err := m.hashFile(path); err == nil {
			files[path] = entry
		}
	}

	// System directories (all files within)
	for _, dir := range systemDirs {
		m.walkDir(dir, files, 1) // depth 1 (no deep recursion)
	}

	// Web roots: monitor critical files (PHP in root, wp-config, .htaccess, etc.)
	for _, root := range roots {
		m.walkWebRoot(root.Path, files)
	}

	return files
}

// walkDir adds all regular files in a directory (up to maxDepth levels).
func (m *Monitor) walkDir(dir string, files map[string]FileEntry, maxDepth int) {
	m.walkDirDepth(dir, files, 0, maxDepth)
}

func (m *Monitor) walkDirDepth(dir string, files map[string]FileEntry, depth, maxDepth int) {
	if depth > maxDepth {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			m.walkDirDepth(path, files, depth+1, maxDepth)
			continue
		}
		if entry, err := m.hashFile(path); err == nil {
			files[path] = entry
		}
	}
}

// walkWebRoot monitors key files in a web root without scanning everything.
func (m *Monitor) walkWebRoot(root string, files map[string]FileEntry) {
	// Critical web files in root directory only (not recursive — malware scan handles deep files)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())

		// Monitor config files and PHP entry points
		monitor := false
		switch {
		case name == "wp-config.php":
			monitor = true
		case name == ".htaccess":
			monitor = true
		case name == "configuration.php": // Joomla
			monitor = true
		case name == ".env":
			monitor = true
		case name == "index.php":
			monitor = true
		case name == "web.config": // IIS
			monitor = true
		case strings.HasSuffix(name, ".conf"):
			monitor = true
		}

		if monitor {
			path := filepath.Join(root, e.Name())
			if entry, err := m.hashFile(path); err == nil {
				files[path] = entry
			}
		}
	}

	// Also monitor .user.ini (PHP config override, often used by attackers)
	for _, special := range []string{".user.ini", "php.ini", ".htpasswd"} {
		path := filepath.Join(root, special)
		if entry, err := m.hashFile(path); err == nil {
			files[path] = entry
		}
	}
}

// hashFile computes SHA256 and captures metadata for a single file.
func (m *Monitor) hashFile(path string) (FileEntry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileEntry{}, err
	}

	// Skip symlinks, directories, devices
	if !info.Mode().IsRegular() {
		return FileEntry{}, os.ErrInvalid
	}

	// Skip files too large
	if info.Size() > maxFileSize {
		return FileEntry{}, os.ErrInvalid
	}

	var uid, gid uint32
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = stat.Uid
		gid = stat.Gid
	}

	// Compute SHA256
	f, err := os.Open(path)
	if err != nil {
		return FileEntry{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileEntry{}, err
	}

	return FileEntry{
		Hash:    hex.EncodeToString(h.Sum(nil)),
		Mode:    info.Mode().String(),
		UID:     uid,
		GID:     gid,
		Size:    info.Size(),
		ModTime: info.ModTime().Unix(),
	}, nil
}

func (m *Monitor) severity(path string) string {
	for prefix, sev := range severityMap {
		if strings.HasPrefix(path, prefix) {
			return sev
		}
	}
	// Web root files
	if strings.Contains(path, "wp-config") || strings.Contains(path, ".htaccess") {
		return "high"
	}
	if strings.HasSuffix(path, ".php") || strings.HasSuffix(path, ".conf") {
		return "medium"
	}
	return "medium"
}

func (m *Monitor) domainForPath(path string, roots []WebRoot) string {
	for _, root := range roots {
		if strings.HasPrefix(path, root.Path) {
			return root.Domain
		}
	}
	return ""
}

func formatOwner(uid, gid uint32) string {
	return fmt.Sprintf("%d:%d", uid, gid)
}

// Baseline persistence

func (m *Monitor) loadBaseline() error {
	data, err := os.ReadFile(m.baselinePath)
	if err != nil {
		return err
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return err
	}
	if bl.Version != baselineVersion {
		return os.ErrInvalid
	}
	m.mu.Lock()
	m.baseline = &bl
	m.mu.Unlock()
	return nil
}

func (m *Monitor) createBaseline() {
	m.mu.Lock()
	roots := make([]WebRoot, len(m.webRoots))
	copy(roots, m.webRoots)
	m.mu.Unlock()

	files := m.snapshot(roots)

	bl := &Baseline{
		Version:   baselineVersion,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Files:     files,
	}

	m.mu.Lock()
	m.baseline = bl
	m.mu.Unlock()

	m.saveBaseline()
	log.Printf("[fim] baseline created: %d files monitored", len(files))
}

func (m *Monitor) saveBaseline() {
	m.mu.Lock()
	bl := m.baseline
	m.mu.Unlock()

	data, err := json.Marshal(bl)
	if err != nil {
		log.Printf("[fim] error marshaling baseline: %v", err)
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(m.baselinePath)
	os.MkdirAll(dir, 0700)

	// Write atomically (temp file + rename)
	tmp := m.baselinePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("[fim] error saving baseline: %v", err)
		return
	}
	if err := os.Rename(tmp, m.baselinePath); err != nil {
		log.Printf("[fim] error renaming baseline: %v", err)
	}
}
