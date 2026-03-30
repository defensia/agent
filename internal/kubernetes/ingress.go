//go:build kubernetes

package kubernetes

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ListIngressHosts returns all hostnames from Ingress resources cluster-wide.
func (c *Client) ListIngressHosts() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ingresses, err := c.clientset.NetworkingV1().Ingresses("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("[kubernetes] failed to list ingresses: %v", err)
		return nil
	}

	hostSet := make(map[string]bool)
	for _, ing := range ingresses.Items {
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" {
				hostSet[rule.Host] = true
			}
		}
		for _, tls := range ing.Spec.TLS {
			for _, host := range tls.Hosts {
				hostSet[host] = true
			}
		}
	}

	hosts := make([]string, 0, len(hostSet))
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	return hosts
}

// FindIngressLogPaths discovers ingress controller log paths on this node.
// Searches /var/log/pods/ for nginx-ingress or traefik container logs.
func (c *Client) FindIngressLogPaths() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find ingress controller pods on this node
	pods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + c.nodeName,
	})
	if err != nil {
		return nil
	}

	var logPaths []string

	for _, pod := range pods.Items {
		// Match common ingress controller images
		ingressContainer := ""
		for _, container := range pod.Spec.Containers {
			img := strings.ToLower(container.Image)
			if strings.Contains(img, "ingress-nginx") ||
				strings.Contains(img, "nginx-ingress") ||
				strings.Contains(img, "traefik") {
				ingressContainer = container.Name
				break
			}
		}
		if ingressContainer == "" {
			continue
		}

		// Search /var/log/pods/<namespace>_<podname>_<uid>/<container>/0.log
		// The UID is in the pod metadata
		uid := string(pod.UID)
		podLogDir := filepath.Join("/var/log/pods",
			pod.Namespace+"_"+pod.Name+"_"+uid,
			ingressContainer)

		logFile := filepath.Join(podLogDir, "0.log")
		if _, err := os.Stat(logFile); err == nil {
			logPaths = append(logPaths, logFile)
			log.Printf("[kubernetes] found ingress log: %s", logFile)
			continue
		}

		// Fallback: glob for rotated logs in the same dir
		matches, _ := filepath.Glob(filepath.Join(podLogDir, "*.log"))
		if len(matches) > 0 {
			logPaths = append(logPaths, matches[0])
			log.Printf("[kubernetes] found ingress log (glob): %s", matches[0])
		}
	}

	return logPaths
}
