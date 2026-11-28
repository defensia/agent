package firewall

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// csfVarDir is the directory csf.tempban lives in. Test seam: production
// value is /var/lib/csf.
var csfVarDir = "/var/lib/csf"

// ErrTempBanBusy means csf.tempban could not be read because another process
// held an exclusive lock on it for the whole retry window — this is reported
// as an error, NEVER as an empty successful read (an empty read could look
// exactly like "every temp ban vanished").
var ErrTempBanBusy = errors.New("csf.tempban locked")

// TempBanEntry is one parsed line of /var/lib/csf/csf.tempban.
type TempBanEntry struct {
	Added     int64
	IP        string
	Port      string
	Dir       string
	TTL       time.Duration
	Comment   string
	Ours      bool // comment starts with "defensia:"
	ExpiresAt time.Time
}

// TempBanList is the result of reading and parsing csf.tempban.
type TempBanList struct {
	Entries   []TempBanEntry
	Malformed int
	Exists    bool
}

// parseTempBans parses csf.tempban's `time|ip|port|inout|ttl|comment` lines.
// A comment containing "|" is kept whole (SplitN with max 6 fields).
func parseTempBans(r io.Reader) TempBanList {
	var list TempBanList

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.SplitN(line, "|", 6)
		if len(fields) != 6 {
			list.Malformed++
			continue
		}

		added, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			list.Malformed++
			continue
		}

		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			list.Malformed++
			continue
		}

		ttlSec, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			list.Malformed++
			continue
		}

		comment := fields[5]
		ttl := time.Duration(ttlSec) * time.Second

		list.Entries = append(list.Entries, TempBanEntry{
			Added:     added,
			IP:        addr.String(),
			Port:      fields[2],
			Dir:       fields[3],
			TTL:       ttl,
			Comment:   comment,
			Ours:      strings.HasPrefix(comment, "defensia:"),
			ExpiresAt: time.Unix(added, 0).Add(ttl),
		})
	}

	list.Exists = true

	return list
}

// readTempBans reads and parses csf.tempban from the csfVarDir seam. The
// actual file-open-and-lock strategy is platform-specific (see
// csf_tempban_linux.go / csf_tempban_other.go): on Linux it is read under
// flock(LOCK_SH) with retry so a concurrent CSF/lfd rewrite is never
// observed as a torn or empty file.
func readTempBans() (TempBanList, error) {
	data, exists, err := readTempBanFile()
	if err != nil {
		return TempBanList{}, err
	}
	if !exists {
		return TempBanList{Exists: false}, nil
	}

	return parseTempBans(strings.NewReader(string(data))), nil
}
