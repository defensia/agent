package watcher

import (
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultLogPath = "/var/log/auth.log"

var failedPattern = regexp.MustCompile(
	`Failed password for (?:invalid user )?\S+ from ([\d.]+)`,
)

// BanFunc is called when an IP exceeds the threshold.
type BanFunc func(ip, reason string, count int)

// CheckIPFunc is called for every detected IP. If it returns a non-empty reason,
// the IP is banned immediately (used for geoblocking).
type CheckIPFunc func(ip string) (banReason string)

// Config holds the watcher's tunable parameters.
type Config struct {
	Threshold int
	Window    time.Duration
}

// Watcher tails auth.log and calls onBan when an IP exceeds the threshold.
type Watcher struct {
	logPath string
	onBan   BanFunc
	checkIP CheckIPFunc

	mu        sync.Mutex
	threshold int
	window    time.Duration
	attempts  map[string][]time.Time
	banned    map[string]bool
	whitelist map[string]bool // IPs or CIDRs that are never banned
	wlNets    []*net.IPNet    // parsed CIDR whitelists
}

// detectLogPath returns the auth log path, checking the environment variable
// first, then auto-detecting between Debian/Ubuntu and RHEL/CentOS paths.
func detectLogPath() string {
	if p := os.Getenv("AUTH_LOG_PATH"); p != "" {
		return p
	}
	if _, err := os.Stat("/var/log/auth.log"); err == nil {
		return "/var/log/auth.log"
	}
	if _, err := os.Stat("/var/log/secure"); err == nil {
		return "/var/log/secure"
	}
	return defaultLogPath
}

func New(onBan BanFunc) *Watcher {
	path := detectLogPath()

	return &Watcher{
		logPath:   path,
		threshold: 5,
		window:    5 * time.Minute,
		onBan:     onBan,
		attempts:  make(map[string][]time.Time),
		banned:    make(map[string]bool),
		whitelist: make(map[string]bool),
	}
}

// SetCheckIP sets a callback that is invoked for every unique IP seen.
// If it returns a non-empty string, the IP is banned immediately.
func (w *Watcher) SetCheckIP(fn CheckIPFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.checkIP = fn
}

// UpdateConfig reconfigures threshold and window at runtime.
func (w *Watcher) UpdateConfig(cfg Config) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if cfg.Threshold > 0 {
		w.threshold = cfg.Threshold
	}
	if cfg.Window > 0 {
		w.window = cfg.Window
	}

	log.Printf("[watcher] config updated: threshold=%d window=%s", w.threshold, w.window)
}

// UpdateWhitelist replaces the whitelist with a new set of IPs/CIDRs.
func (w *Watcher) UpdateWhitelist(ips []string, cidrs []string) {
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

	log.Printf("[watcher] whitelist updated: %d IPs, %d CIDRs", len(ips), len(w.wlNets))
}

// isWhitelisted checks if an IP is in the whitelist. Caller must hold w.mu.
func (w *Watcher) isWhitelisted(ip string) bool {
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

// Run starts tailing the log file. Blocks indefinitely.
func (w *Watcher) Run() {
	log.Printf("[watcher] watching %s (threshold: %d in %s)", w.logPath, w.threshold, w.window)

	for {
		if err := w.tail(); err != nil {
			log.Printf("[watcher] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func (w *Watcher) tail() error {
	f, err := os.Open(w.logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Get initial file size so we only process new lines
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	offset := fi.Size()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var partial string

	for range ticker.C {
		// Check if file has grown
		fi, err = os.Stat(w.logPath)
		if err != nil {
			return err
		}

		size := fi.Size()
		if size <= offset {
			if size < offset {
				// File was truncated/rotated — reset
				offset = 0
			}
			continue
		}

		// Read the new data
		readF, err := os.Open(w.logPath)
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

			// Process all complete lines
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

func (w *Watcher) processLine(line string) {
	matches := failedPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return
	}

	ip := matches[1]
	now := time.Now()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.banned[ip] {
		return
	}

	if w.isWhitelisted(ip) {
		return
	}

	// Check geoblocking callback first — immediate ban
	if w.checkIP != nil {
		if reason := w.checkIP(ip); reason != "" {
			w.banned[ip] = true
			go w.onBan(ip, reason, 1)
			return
		}
	}

	// Keep only attempts within the window
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
		go w.onBan(ip, "brute_force_ssh", count)
	}
}
