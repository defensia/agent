//go:build kubernetes

package kubernetes

import (
	"context"
	"fmt"
	"log"
	"os"
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

// FindIngressLogPaths discovers nginx-ingress controller log paths.
// The killer feature: WAF on ingress logs protects ALL cluster services.
func (c *Client) FindIngressLogPaths() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Find nginx-ingress controller pods on this node
	pods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + c.nodeName,
	})
	if err != nil {
		return nil
	}

	var logPaths []string

	for _, pod := range pods.Items {
		// Match common ingress controller patterns
		isIngress := false
		for _, c := range pod.Spec.Containers {
			img := strings.ToLower(c.Image)
			if strings.Contains(img, "ingress-nginx") ||
				strings.Contains(img, "nginx-ingress") ||
				strings.Contains(img, "traefik") {
				isIngress = true
				break
			}
		}
		if !isIngress {
			continue
		}

		// Ingress controller logs go to stdout → Docker/containerd captures them.
		// The log file is at /var/log/pods/<namespace>_<pod>_<uid>/<container>/0.log
		// Or /var/log/containers/<pod>_<namespace>_<container>-<id>.log
		logDir := fmt.Sprintf("/var/log/pods/%s_%s_*", pod.Namespace, pod.Name)

		// Also check if there's a volume mount for access logs
		for _, c := range pod.Spec.Containers {
			for _, vm := range c.VolumeMounts {
				if strings.Contains(vm.MountPath, "log") {
					logPaths = append(logPaths, vm.MountPath)
				}
			}
		}

		// Try the standard container log path
		containerLogPattern := fmt.Sprintf("/var/log/containers/%s_%s_*.log", pod.Name, pod.Namespace)
		if matches, _ := findGlobPaths(containerLogPattern); len(matches) > 0 {
			logPaths = append(logPaths, matches...)
		} else if matches, _ := findGlobPaths(logDir + "/*/0.log"); len(matches) > 0 {
			logPaths = append(logPaths, matches...)
		}

		if len(logPaths) > 0 {
			log.Printf("[kubernetes] found ingress controller logs: %v", logPaths)
		}
	}

	return logPaths
}

// findGlobPaths matches a glob pattern on the filesystem.
func findGlobPaths(pattern string) ([]string, error) {
	// Use filepath.Glob but we import os for PathSeparator
	entries, err := os.ReadDir("/var/log/containers")
	if err != nil {
		return nil, err
	}

	var matches []string
	prefix := strings.TrimSuffix(strings.TrimPrefix(pattern, "/var/log/containers/"), "*.log")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".log") {
			matches = append(matches, "/var/log/containers/"+e.Name())
		}
	}
	return matches, nil
}
