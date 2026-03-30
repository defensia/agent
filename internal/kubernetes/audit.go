//go:build kubernetes

package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuditNetworkPolicies checks for namespaces without NetworkPolicy.
// Returns a list of warning strings.
func (c *Client) AuditNetworkPolicies() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	policies, err := c.clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	// Build set of namespaces that have at least one NetworkPolicy
	nsWithPolicy := make(map[string]bool)
	for _, p := range policies.Items {
		nsWithPolicy[p.Namespace] = true
	}

	// System namespaces to skip
	skip := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	var warnings []string
	for _, ns := range namespaces.Items {
		if skip[ns.Name] {
			continue
		}
		if !nsWithPolicy[ns.Name] {
			warnings = append(warnings, fmt.Sprintf("namespace '%s' has no NetworkPolicy", ns.Name))
		}
	}

	return warnings
}
