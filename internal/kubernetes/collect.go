//go:build kubernetes

package kubernetes

import "log"

// CollectInfo gathers all K8s information for the heartbeat payload.
// Called once per heartbeat cycle (every 60s).
func (c *Client) CollectInfo() *KubernetesInfo {
	if c == nil {
		return nil
	}

	pods := c.ListPodsOnNode()
	ingressHosts := c.ListIngressHosts()
	warnings := c.AuditNetworkPolicies()

	info := &KubernetesInfo{
		ClusterName:    c.ClusterName(),
		NodeName:       c.nodeName,
		KubeletVersion: c.KubeletVersion(),
		PodCount:       len(pods),
		NamespaceCount: c.CountNamespaces(),
		IngressHosts:   ingressHosts,
		Pods:           pods,
		Warnings:       warnings,
	}

	log.Printf("[kubernetes] collected: %d pods, %d ingress hosts, %d warnings",
		info.PodCount, len(ingressHosts), len(warnings))

	return info
}
