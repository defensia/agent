//go:build !kubernetes

package kubernetes

type K8sFirewall struct{}

func NewK8sFirewall(client *Client) *K8sFirewall { return nil }
func (fw *K8sFirewall) BanIP(ip string) error    { return nil }
func (fw *K8sFirewall) UnbanIP(ip string) error   { return nil }
func (fw *K8sFirewall) BlockedCount() int         { return 0 }
