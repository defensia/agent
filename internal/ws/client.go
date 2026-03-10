package ws

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Pusher protocol message structure.
type message struct {
	Event   string          `json:"event"`
	Data    json.RawMessage `json:"data,omitempty"`
	Channel string          `json:"channel,omitempty"`
}

// BanCreatedPayload matches the broadcastWith() from BanCreated event.
type BanCreatedPayload struct {
	ID        int64   `json:"id"`
	IPAddress string  `json:"ip_address"`
	Reason    string  `json:"reason"`
	AgentID   *int64  `json:"agent_id"`
	ExpiresAt *string `json:"expires_at"`
}

// BanRemovedPayload matches the broadcastWith() from BanRemoved event.
type BanRemovedPayload struct {
	ID        int64   `json:"id"`
	IPAddress string  `json:"ip_address"`
	AgentID   *int64  `json:"agent_id"`
}

// RuleCreatedPayload matches the broadcastWith() from RuleCreated event.
type RuleCreatedPayload struct {
	ID        int64   `json:"id"`
	Type      string  `json:"type"`
	Protocol  string  `json:"protocol"`
	IPAddress *string `json:"ip_address"`
	IPRange   *string `json:"ip_range"`
	Port      *int    `json:"port"`
	Status    string  `json:"status"`
	AgentID   *int64  `json:"agent_id"`
}

// RuleRemovedPayload matches the broadcastWith() from RuleRemoved event.
type RuleRemovedPayload struct {
	ID      int64  `json:"id"`
	AgentID *int64 `json:"agent_id"`
}

// ScanRequestedPayload matches the broadcastWith() from ScanRequested event.
type ScanRequestedPayload struct {
	ScanID int64 `json:"scan_id"`
}

// ImportRequestedPayload matches the broadcastWith() from ImportRequested event.
type ImportRequestedPayload struct {
	AgentID int64 `json:"agent_id"`
}

// AuditRequestedPayload matches the broadcastWith() from AuditRequested event.
type AuditRequestedPayload struct {
	AuditID int64 `json:"audit_id"`
}

// SyncRequestedPayload matches the broadcastWith() from SyncRequested event.
type SyncRequestedPayload struct {
	AgentID int64 `json:"agent_id"`
}

// UpdateRequestedPayload matches the broadcastWith() from UpdateRequested event.
type UpdateRequestedPayload struct {
	AgentID int64 `json:"agent_id"`
}

// Handlers called when events are received from the server.
type Handlers struct {
	OnBanCreated       func(BanCreatedPayload)
	OnBanRemoved       func(BanRemovedPayload)
	OnRuleCreated      func(RuleCreatedPayload)
	OnRuleRemoved      func(RuleRemovedPayload)
	OnScanRequested    func(ScanRequestedPayload)
	OnImportRequested  func(ImportRequestedPayload)
	OnAuditRequested   func(AuditRequestedPayload)
	OnSyncRequested    func(SyncRequestedPayload)
	OnUpdateRequested  func(UpdateRequestedPayload)
}

// Client manages the WebSocket connection to Reverb.
type Client struct {
	reverbURL    string
	appKey       string
	authEndpoint string
	agentToken   string
	agentID      int64
	handlers     Handlers

	mu   sync.Mutex
	conn *websocket.Conn
}

func New(reverbURL, appKey, authEndpoint, agentToken string, agentID int64, h Handlers) *Client {
	return &Client{
		reverbURL:    reverbURL,
		appKey:       appKey,
		authEndpoint: authEndpoint,
		agentToken:   agentToken,
		agentID:      agentID,
		handlers:     h,
	}
}

// Run connects and reconnects with exponential backoff. Blocks indefinitely.
func (c *Client) Run() {
	attempt := 0

	for {
		if err := c.connect(); err != nil {
			wait := time.Duration(math.Min(float64(30*time.Second), float64(time.Second)*math.Pow(2, float64(attempt))))
			log.Printf("[ws] disconnected (%v) — reconnecting in %s", err, wait)
			time.Sleep(wait)
			attempt++
		} else {
			attempt = 0
		}
	}
}

func (c *Client) connect() error {
	// Append Pusher protocol query params
	wsURL := fmt.Sprintf("%s?protocol=7&client=defensia-agent&version=0.1.0", c.reverbURL)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	log.Printf("[ws] connected to %s", c.reverbURL)

	// Proactive keepalive: send pusher:ping every 30s to prevent nginx
	// proxy_read_timeout from closing the connection.
	done := make(chan struct{})
	defer close(done)
	go c.keepalive(conn, done)

	var socketID string

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}

		var msg message
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		switch msg.Event {
		case "pusher:connection_established":
			socketID, err = c.handleConnectionEstablished(conn, msg.Data)
			if err != nil {
				return fmt.Errorf("subscribe: %w", err)
			}
			_ = socketID

		case "pusher:ping":
			c.sendPong(conn)

		case "pusher:pong":
			// Response to our keepalive ping — nothing to do.

		case "pusher_internal:subscription_succeeded":
			log.Printf("[ws] subscribed to %s", msg.Channel)

		case "pusher:error":
			log.Printf("[ws] server error: %s", string(msg.Data))

		default:
			if msg.Channel == fmt.Sprintf("private-agent.%d", c.agentID) {
				c.dispatch(msg.Event, msg.Data)
			}
		}
	}
}

// keepalive sends pusher:ping every 30 seconds until the connection closes.
func (c *Client) keepalive(conn *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			c.mu.Lock()
			_ = conn.WriteJSON(message{Event: "pusher:ping"})
			c.mu.Unlock()
		}
	}
}

func (c *Client) handleConnectionEstablished(conn *websocket.Conn, data json.RawMessage) (string, error) {
	// data is a JSON string containing {"socket_id":"...","activity_timeout":120}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", err
	}

	var payload struct {
		SocketID string `json:"socket_id"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return "", err
	}

	log.Printf("[ws] connection established, socket_id=%s", payload.SocketID)

	channelName := fmt.Sprintf("private-agent.%d", c.agentID)

	auth, err := c.getAuth(payload.SocketID, channelName)
	if err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}

	return payload.SocketID, c.subscribe(conn, channelName, auth)
}

func (c *Client) getAuth(socketID, channelName string) (string, error) {
	form := url.Values{
		"socket_id":    {socketID},
		"channel_name": {channelName},
	}

	req, err := http.NewRequest(http.MethodPost, c.authEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+c.agentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth returned %d: %s", resp.StatusCode, string(b))
	}

	var result struct {
		Auth string `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Auth, nil
}

func (c *Client) subscribe(conn *websocket.Conn, channel, auth string) error {
	type subscribeData struct {
		Auth    string `json:"auth"`
		Channel string `json:"channel"`
	}

	data, _ := json.Marshal(subscribeData{Auth: auth, Channel: channel})

	c.mu.Lock()
	defer c.mu.Unlock()
	return conn.WriteJSON(message{
		Event: "pusher:subscribe",
		Data:  data,
	})
}

func (c *Client) sendPong(conn *websocket.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = conn.WriteJSON(message{Event: "pusher:pong"})
}

func (c *Client) dispatch(event string, rawData json.RawMessage) {
	// Pusher wraps data as a JSON string — unwrap it
	var dataStr string
	if err := json.Unmarshal(rawData, &dataStr); err != nil {
		// Already an object, use as-is
		dataStr = string(rawData)
	}

	switch event {
	case "ban.created":
		if c.handlers.OnBanCreated != nil {
			var p BanCreatedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnBanCreated(p)
			}
		}

	case "ban.removed":
		if c.handlers.OnBanRemoved != nil {
			var p BanRemovedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnBanRemoved(p)
			}
		}

	case "rule.created":
		if c.handlers.OnRuleCreated != nil {
			var p RuleCreatedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnRuleCreated(p)
			}
		}

	case "rule.removed":
		if c.handlers.OnRuleRemoved != nil {
			var p RuleRemovedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnRuleRemoved(p)
			}
		}

	case "scan.requested":
		if c.handlers.OnScanRequested != nil {
			var p ScanRequestedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnScanRequested(p)
			}
		}

	case "import.requested":
		if c.handlers.OnImportRequested != nil {
			var p ImportRequestedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnImportRequested(p)
			}
		}

	case "audit.requested":
		if c.handlers.OnAuditRequested != nil {
			var p AuditRequestedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnAuditRequested(p)
			}
		}

	case "sync.requested":
		if c.handlers.OnSyncRequested != nil {
			var p SyncRequestedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnSyncRequested(p)
			}
		}

	case "update.requested":
		if c.handlers.OnUpdateRequested != nil {
			var p UpdateRequestedPayload
			if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
				c.handlers.OnUpdateRequested(p)
			}
		}
	}
}
