//go:build kubernetes

package kubernetes

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// ConfigMap name and namespace for blocked IPs
	banConfigMapName = "defensia-blocked-ips"
	banDataKey       = "blocked-ips.conf"

	// Namespace where the ingress controller runs
	defaultIngressNamespace = "ingress-nginx"
)

// K8sFirewall manages a ConfigMap with nginx deny directives for ingress-level blocking.
type K8sFirewall struct {
	client    *Client
	namespace string
	mu        sync.Mutex
	blocked   map[string]bool
}

// NewK8sFirewall creates a K8s-native firewall that writes banned IPs to a ConfigMap.
// The nginx-ingress controller reads this ConfigMap for deny rules.
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

	// Load existing bans from ConfigMap on startup
	fw.loadExisting()

	log.Printf("[k8s-firewall] initialized, namespace: %s, existing bans: %d", ns, len(fw.blocked))
	return fw
}

// BanIP adds an IP to the ConfigMap deny list.
func (fw *K8sFirewall) BanIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.blocked[ip] {
		return nil
	}

	fw.blocked[ip] = true
	return fw.syncConfigMap()
}

// UnbanIP removes an IP from the ConfigMap deny list.
func (fw *K8sFirewall) UnbanIP(ip string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !fw.blocked[ip] {
		return nil
	}

	delete(fw.blocked, ip)
	return fw.syncConfigMap()
}

// syncConfigMap writes the current blocked IPs to the ConfigMap.
func (fw *K8sFirewall) syncConfigMap() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build nginx deny directives
	var lines []string
	for ip := range fw.blocked {
		lines = append(lines, fmt.Sprintf("deny %s;", ip))
	}
	// Always end with empty line for clean nginx include
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      banConfigMapName,
			Namespace: fw.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "defensia-agent",
				"app.kubernetes.io/component":  "firewall",
			},
		},
		Data: map[string]string{
			banDataKey: content,
		},
	}

	// Try update first, create if doesn't exist
	_, err := fw.client.clientset.CoreV1().ConfigMaps(fw.namespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = fw.client.clientset.CoreV1().ConfigMaps(fw.namespace).Create(ctx, cm, metav1.CreateOptions{})
		}
	}

	if err != nil {
		log.Printf("[k8s-firewall] failed to sync ConfigMap: %v", err)
		return err
	}

	log.Printf("[k8s-firewall] synced %d blocked IPs to ConfigMap %s/%s", len(fw.blocked), fw.namespace, banConfigMapName)
	return nil
}

// loadExisting reads the current ConfigMap to restore state on startup.
func (fw *K8sFirewall) loadExisting() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cm, err := fw.client.clientset.CoreV1().ConfigMaps(fw.namespace).Get(ctx, banConfigMapName, metav1.GetOptions{})
	if err != nil {
		return // ConfigMap doesn't exist yet — that's fine
	}

	content := cm.Data[banDataKey]
	for _, line := range strings.Split(content, "\n") {
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
