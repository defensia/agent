//go:build kubernetes

package kubernetes

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Client wraps the Kubernetes API client and provides security-relevant queries.
type Client struct {
	clientset *kubernetes.Clientset
	nodeName  string
}

// IsRunningInK8s returns true if the agent is running inside a Kubernetes pod.
func IsRunningInK8s() bool {
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// NewClient creates a K8s client using in-cluster config.
// Returns nil if not running in K8s or if the client can't be created.
func NewClient() *Client {
	if !IsRunningInK8s() {
		return nil
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("[kubernetes] failed to get in-cluster config: %v", err)
		return nil
	}

	// Short timeouts — K8s API calls should not block heartbeats.
	config.Timeout = 10 * time.Second

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("[kubernetes] failed to create clientset: %v", err)
		return nil
	}

	nodeName := os.Getenv("NODE_NAME") // Set via Downward API in DaemonSet spec
	if nodeName == "" {
		nodeName = os.Getenv("HOSTNAME")
	}

	log.Printf("[kubernetes] detected cluster, node: %s", nodeName)

	return &Client{
		clientset: clientset,
		nodeName:  nodeName,
	}
}

// NodeName returns the name of the node this agent is running on.
func (c *Client) NodeName() string {
	return c.nodeName
}

// ClusterName attempts to detect the cluster name.
// K8s doesn't expose this natively; we try common conventions.
func (c *Client) ClusterName() string {
	// Check env var (can be set in Helm values)
	if name := os.Getenv("CLUSTER_NAME"); name != "" {
		return name
	}

	// Try to read from kubeadm configmap
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cm, err := c.clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "kubeadm-config", metav1.GetOptions{})
	if err == nil {
		if data, ok := cm.Data["ClusterConfiguration"]; ok {
			for _, line := range strings.Split(data, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "clusterName:") {
					return strings.TrimSpace(strings.TrimPrefix(line, "clusterName:"))
				}
			}
		}
	}

	return ""
}

// KubeletVersion returns the kubelet version of this node.
func (c *Client) KubeletVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, err := c.clientset.CoreV1().Nodes().Get(ctx, c.nodeName, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return node.Status.NodeInfo.KubeletVersion
}
