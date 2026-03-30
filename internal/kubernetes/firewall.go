//go:build kubernetes

package kubernetes

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	defaultIngressNamespace = "ingress-nginx"

	// nginx-ingress controller's own ConfigMap — it watches this and auto-reloads
	ingressConfigMapName = "ingress-nginx-controller"

	// Key in the ConfigMap that nginx-ingress reads for global server-level config
	serverSnippetKey = "server-snippet"

	// Markers so we only modify our section, not user's existing snippets
	markerStart = "# -- defensia-blocked-ips-start --"
	markerEnd   = "# -- defensia-blocked-ips-end --"
)

// K8sFirewall manages blocked IPs by injecting deny rules into the nginx-ingress
// controller's ConfigMap server-snippet. nginx-ingress auto-reloads on ConfigMap changes.
type K8sFirewall struct {
	client    *Client
	namespace string
	mu        sync.Mutex
	blocked   map[string]bool
}

// NewK8sFirewall creates a K8s-native firewall.
func NewK8sFirewall(client *Client) *K8sFirewall {
	if client == nil {
		return nil
	}

	ns := defaultIngressNamespace

	fw := &K8sFirewall{
		client:    client,
		namespace: ns,
		blocked:   make(map[string]bool),
	}

	// Load existing bans from the ConfigMap on startup
	fw.loadExisting()

	log.Printf("[k8s-firewall] initialized, namespace: %s, existing bans: %d", ns, len(fw.blocked))
	return fw
}

// BanIP adds an IP to the ingress deny list.
func (fw *K8sFirewall) BanIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.blocked[ip] {
		return nil
	}

	fw.blocked[ip] = true
	return fw.syncToIngress()
}

// UnbanIP removes an IP from the ingress deny list.
func (fw *K8sFirewall) UnbanIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.blocked[ip] {
		return nil
	}

	delete(fw.blocked, ip)
	return fw.syncToIngress()
}

// syncToIngress patches the nginx-ingress controller ConfigMap's server-snippet
// with deny rules. nginx-ingress detects the change and auto-reloads.
func (fw *K8sFirewall) syncToIngress() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the existing ingress controller ConfigMap
	cm, err := fw.client.clientset.CoreV1().ConfigMaps(fw.namespace).Get(ctx, ingressConfigMapName, metav1.GetOptions{})
	if err != nil {
		log.Printf("[k8s-firewall] ingress ConfigMap %s/%s not found: %v", fw.namespace, ingressConfigMapName, err)
		return err
	}

	// Build our deny block
	var denyLines []string
	for ip := range fw.blocked {
		denyLines = append(denyLines, fmt.Sprintf("deny %s;", ip))
	}
	defBlock := markerStart + "\n"
	if len(denyLines) > 0 {
		defBlock += strings.Join(denyLines, "\n") + "\n"
		defBlock += "allow all;\n"
	}
	defBlock += markerEnd

	// Get existing server-snippet (may have user's own rules)
	existing := ""
	if cm.Data != nil {
		existing = cm.Data[serverSnippetKey]
	}

	// Replace our section, or append if not present
	var newSnippet string
	startIdx := strings.Index(existing, markerStart)
	endIdx := strings.Index(existing, markerEnd)

	if startIdx >= 0 && endIdx >= 0 {
		// Replace existing defensia block
		newSnippet = existing[:startIdx] + defBlock + existing[endIdx+len(markerEnd):]
	} else {
		// Append our block
		if existing != "" && !strings.HasSuffix(existing, "\n") {
			existing += "\n"
		}
		newSnippet = existing + defBlock
	}

	// Clean up: if no blocked IPs and no other snippet content, remove the key entirely
	cleanSnippet := strings.TrimSpace(strings.Replace(strings.Replace(newSnippet, markerStart, "", 1), markerEnd, "", 1))
	if cleanSnippet == "" {
		delete(cm.Data, serverSnippetKey)
	} else {
		if cm.Data == nil {
			cm.Data = make(map[string]string)
		}
		cm.Data[serverSnippetKey] = strings.TrimSpace(newSnippet) + "\n"
	}

	// Update the ConfigMap — nginx-ingress watches it and auto-reloads
	_, err = fw.client.clientset.CoreV1().ConfigMaps(fw.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		log.Printf("[k8s-firewall] failed to update ingress ConfigMap: %v", err)
		return err
	}

	log.Printf("[k8s-firewall] synced %d blocked IPs to %s/%s server-snippet", len(fw.blocked), fw.namespace, ingressConfigMapName)
	return nil
}

// loadExisting reads blocked IPs from the existing ingress ConfigMap on startup.
func (fw *K8sFirewall) loadExisting() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cm, err := fw.client.clientset.CoreV1().ConfigMaps(fw.namespace).Get(ctx, ingressConfigMapName, metav1.GetOptions{})
	if err != nil {
		return
	}

	snippet := cm.Data[serverSnippetKey]
	if snippet == "" {
		return
	}

	// Only parse between our markers
	startIdx := strings.Index(snippet, markerStart)
	endIdx := strings.Index(snippet, markerEnd)
	if startIdx < 0 || endIdx < 0 {
		return
	}

	block := snippet[startIdx+len(markerStart) : endIdx]
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "deny ") && strings.HasSuffix(line, ";") {
			ip := strings.TrimSuffix(strings.TrimPrefix(line, "deny "), ";")
			ip = strings.TrimSpace(ip)
			if ip != "" {
				fw.blocked[ip] = true
			}
		}
	}
}

// BlockedCount returns the number of currently blocked IPs.
func (fw *K8sFirewall) BlockedCount() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return len(fw.blocked)
}
