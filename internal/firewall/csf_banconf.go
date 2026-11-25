package firewall

import "strconv"

// csfBanConf is the subset of csf.conf keys the ban executor needs. A thin
// adapter over the Phase 15 parseCSFConf/readCSFConf reader (csf_conf.go),
// which already tolerates both `KEY = "value"` and `KEY="value"` forms
// across every CSF fork measured in 18-02's lab benchmark.
type csfBanConf struct {
	// TempLimit is DENY_TEMP_IP_LIMIT. -1 means the key was absent (unknown
	// limit), 0 means explicitly unlimited.
	TempLimit int
	IPv6      bool
	Testing   bool
	LFDaemon  bool
	// Found records which of the 4 keys were actually present in csf.conf.
	Found map[string]bool
}

func readCSFBanConf() (csfBanConf, error) {
	vals, _, err := readCSFConf()
	if err != nil {
		return csfBanConf{}, err
	}

	conf := csfBanConf{TempLimit: -1, Found: map[string]bool{}}

	if v, ok := vals["DENY_TEMP_IP_LIMIT"]; ok {
		conf.Found["DENY_TEMP_IP_LIMIT"] = true
		if n, err := strconv.Atoi(v); err == nil {
			conf.TempLimit = n
		}
	}
	if v, ok := vals["IPV6"]; ok {
		conf.Found["IPV6"] = true
		conf.IPv6 = v == "1"
	}
	if v, ok := vals["TESTING"]; ok {
		conf.Found["TESTING"] = true
		conf.Testing = v == "1"
	}
	if v, ok := vals["LF_DAEMON"]; ok {
		conf.Found["LF_DAEMON"] = true
		conf.LFDaemon = v == "1"
	}

	return conf, nil
}
