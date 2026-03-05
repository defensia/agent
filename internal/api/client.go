package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// RegisterRequest holds the data sent during agent registration.
type RegisterRequest struct {
	InstallToken string `json:"install_token"`
	Name         string `json:"name"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Version      string `json:"version"`
}

// RegisterResponse is what the server returns after registration.
type RegisterResponse struct {
	Token string `json:"token"`
	Agent struct {
		ID int64 `json:"id"`
	} `json:"agent"`
	Reverb struct {
		URL          string `json:"url"`
		AppKey       string `json:"app_key"`
		AuthEndpoint string `json:"auth_endpoint"`
	} `json:"reverb"`
}

// SystemMetrics holds server performance data.
type SystemMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryTotal   uint64  `json:"memory_total"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskTotal     uint64  `json:"disk_total"`
	DiskUsed      uint64  `json:"disk_used"`
	DiskPercent   float64 `json:"disk_percent"`
	LoadAvg1      float64 `json:"load_avg_1"`
	LoadAvg5      float64 `json:"load_avg_5"`
	LoadAvg15     float64 `json:"load_avg_15"`
	NetBytesIn    uint64  `json:"net_bytes_in"`
	NetBytesOut   uint64  `json:"net_bytes_out"`
}

// DockerContainer holds info about a running Docker container.
type DockerContainer struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Image  string `json:"image"`
	Status string `json:"status"`
	Ports  string `json:"ports"`
	IsWeb  bool   `json:"is_web"`
}

// HeartbeatRequest is sent every 60s.
type HeartbeatRequest struct {
	Status            string             `json:"status"`
	Version           string             `json:"version"`
	Timestamp         string             `json:"timestamp"`
	IPAddress         string             `json:"ip_address,omitempty"`
	ZombieCount       int                `json:"zombie_count"`
	WebServer         string             `json:"web_server,omitempty"`
	WebServerVersion  string             `json:"web_server_version,omitempty"`
	Metrics           *SystemMetrics     `json:"metrics,omitempty"`
	MonitoredDomains  []string           `json:"monitored_domains,omitempty"`
	MonitoredLogPaths []string           `json:"monitored_log_paths,omitempty"`
	DockerVersion     string             `json:"docker_version,omitempty"`
	DockerContainers  []DockerContainer  `json:"docker_containers,omitempty"`
}

// HeartbeatResponse is the server's reply to a heartbeat.
type HeartbeatResponse struct {
	Status              string  `json:"status"`
	LastSeenAt          string  `json:"last_seen_at"`
	LatestAgentVersion  *string `json:"latest_agent_version,omitempty"`
	AgentDownloadBaseURL *string `json:"agent_download_base_url,omitempty"`
}

// BanRequest reports a newly banned IP to the server.
type BanRequest struct {
	IPAddress string  `json:"ip_address"`
	Reason    string  `json:"reason"`
	BanCount  int     `json:"ban_count"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

// AgentUpdateInfo contains version information for auto-updates.
type AgentUpdateInfo struct {
	LatestVersion  string `json:"latest_version"`
	DownloadBaseURL string `json:"download_base_url"`
}

// SyncResponse is the initial state fetched at startup.
type SyncResponse struct {
	Config      SyncConfig       `json:"config"`
	Rules       []Rule           `json:"rules"`
	Bans        []Ban            `json:"bans"`
	Whitelists  []WhitelistEntry `json:"whitelists"`
	AgentUpdate *AgentUpdateInfo `json:"agent_update,omitempty"`
}

type SyncConfig struct {
	BlockedCountries []string   `json:"blocked_countries"`
	WAFConfig        *WAFConfig `json:"waf_config"`
	BFThreshold   int  `json:"bf_threshold"`
	BFWindow      int  `json:"bf_window"`
	BFBanDuration *int `json:"bf_ban_duration"`
}

type WAFConfig struct {
	EnabledTypes    []string       `json:"enabled_types"`
	DetectOnlyTypes []string       `json:"detect_only_types"`
	Thresholds      map[string]int `json:"thresholds"`
}

type Rule struct {
	ID          int64   `json:"id"`
	Type        string  `json:"type"`
	Protocol    string  `json:"protocol"`
	IPAddress   *string `json:"ip_address"`
	IPRange     *string `json:"ip_range"`
	CountryCode *string `json:"country_code"`
	Port        *int    `json:"port"`
	Status      string  `json:"status"`
	Reason      *string `json:"reason"`
	Priority    int     `json:"priority"`
}

type WhitelistEntry struct {
	ID        int64   `json:"id"`
	IPAddress *string `json:"ip_address"`
	IPRange   *string `json:"ip_range"`
}

// RuleAckRequest is sent by the agent after applying (or failing) a rule.
type RuleAckRequest struct {
	Status       string  `json:"status"`
	ErrorMessage *string `json:"error_message,omitempty"`
}

type Ban struct {
	ID        int64   `json:"id"`
	IPAddress string  `json:"ip_address"`
	ExpiresAt *string `json:"expires_at"`
}

func (c *Client) Register(req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := c.post("/api/v1/agents/register", "", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Heartbeat(req HeartbeatRequest) (*HeartbeatResponse, error) {
	var resp HeartbeatResponse
	if err := c.post("/api/v1/agent/heartbeat", c.token, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Sync() (*SyncResponse, error) {
	var resp SyncResponse
	if err := c.get("/api/v1/agent/sync", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) ReportBan(req BanRequest) error {
	return c.post("/api/v1/agent/bans", c.token, req, nil)
}

func (c *Client) AckRule(ruleID int64, req RuleAckRequest) error {
	path := fmt.Sprintf("/api/v1/agent/rules/%d/ack", ruleID)
	return c.post(path, c.token, req, nil)
}

// ScanResultRequest sends vulnerability scan findings to the server.
type ScanResultRequest struct {
	ScanID   int64         `json:"scan_id"`
	Findings []ScanFinding `json:"findings"`
}

type ScanFinding struct {
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	CheckID        string            `json:"check_id"`
	Title          string            `json:"title"`
	Description    string            `json:"description"`
	Recommendation string            `json:"recommendation,omitempty"`
	Details        map[string]string `json:"details,omitempty"`
	Passed         bool              `json:"passed"`
}

func (c *Client) SubmitScanResults(req ScanResultRequest) error {
	return c.post("/api/v1/agent/scan-results", c.token, req, nil)
}

// ImportedRule represents a single iptables rule to import.
type ImportedRule struct {
	RawRule   string `json:"raw_rule"`
	Type      string `json:"type"`
	Protocol  string `json:"protocol"`
	Source    string `json:"source,omitempty"`
	Port      int    `json:"port,omitempty"`
}

// ImportRulesRequest sends discovered iptables rules to the server.
type ImportRulesRequest struct {
	Rules []ImportedRule `json:"rules"`
}

// ImportRulesResponse is the server's reply after importing rules.
type ImportRulesResponse struct {
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
	Total    int `json:"total"`
}

// ImportRules sends discovered iptables rules to the server for import.
func (c *Client) ImportRules(req ImportRulesRequest) (*ImportRulesResponse, error) {
	var resp ImportRulesResponse
	if err := c.post("/api/v1/agent/rules/import", c.token, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EventRequest represents a security event to report to the server.
type EventRequest struct {
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	SourceIP   string            `json:"source_ip,omitempty"`
	SourcePort *int              `json:"source_port,omitempty"`
	TargetPort *int              `json:"target_port,omitempty"`
	Protocol   string            `json:"protocol,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	OccurredAt string            `json:"occurred_at"`
}

// ReportEvents sends security events to the server.
func (c *Client) ReportEvents(events []EventRequest) error {
	return c.post("/api/v1/agent/events", c.token, map[string]any{"events": events}, nil)
}

// SoftwareAuditRequest sends software audit results to the server.
type SoftwareAuditRequest struct {
	AuditID     int64       `json:"audit_id"`
	Summary     interface{} `json:"summary"`
	KeySoftware interface{} `json:"key_software"`
	Packages    interface{} `json:"packages,omitempty"`
}

// SubmitSoftwareAudit sends software audit results to the server.
func (c *Client) SubmitSoftwareAudit(req SoftwareAuditRequest) error {
	return c.post("/api/v1/agent/software-audit-results", c.token, req, nil)
}

// ReportRemediationResult reports the outcome of a remediation job to the server.
func (c *Client) ReportRemediationResult(jobID int64, status, output string) error {
	return c.post("/api/v1/agent/remediation-results", c.token, map[string]any{
		"job_id": jobID,
		"status": status,
		"output": output,
	}, nil)
}

func (c *Client) post(path, token string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}

	return nil
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
