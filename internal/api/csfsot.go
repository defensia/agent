package api

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/defensia/agent/internal/csfsotwire"
)

// PostCSFSotSnapshot sends the agent's read-only observed-scope snapshot
// (CONTRACT §4). Unlike post(), a non-2xx response here is not itself an
// error: 409 "not_requested" is an expected, silent outcome (the panel's
// pending-snapshot window already closed) and still needs its body
// decoded so the caller knows to stop resending. Only a transport-level
// failure or an undecodable body returns a non-nil error.
func (c *Client) PostCSFSotSnapshot(req csfsotwire.SnapshotRequest) (csfsotwire.SnapshotResponse, int, error) {
	var out csfsotwire.SnapshotResponse

	data, err := json.Marshal(req)
	if err != nil {
		return out, 0, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/agent/csf/sot/snapshot", bytes.NewReader(data))
	if err != nil {
		return out, 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, 0, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, resp.StatusCode, err
	}

	return out, resp.StatusCode, nil
}
