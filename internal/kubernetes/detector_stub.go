//go:build !kubernetes

package kubernetes

// Stub implementations for non-K8s builds.
// These ensure the agent compiles without client-go dependency.

type Client struct{}

func IsRunningInK8s() bool    { return false }
func NewClient() *Client      { return nil }
func (c *Client) NodeName() string    { return "" }
func (c *Client) ClusterName() string { return "" }
func (c *Client) KubeletVersion() string { return "" }
func (c *Client) CollectInfo() *KubernetesInfo { return nil }
func (c *Client) WatchEvents(callback func(K8sEvent)) {}
func (c *Client) FindIngressLogPaths() []string { return nil }
