package monitor

import "github.com/defensia/agent/internal/api"

// ScanResult holds the outcome of a single monitor scan cycle.
type ScanResult struct {
	Events  []api.EventRequest
	Summary map[string]string // key-value pairs describing what was checked
}
