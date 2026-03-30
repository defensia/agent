package kubernetes

// KubernetesInfo is included in heartbeat when running in K8s mode.
type KubernetesInfo struct {
	ClusterName    string        `json:"cluster_name,omitempty"`
	NodeName       string        `json:"node_name"`
	KubeletVersion string        `json:"kubelet_version,omitempty"`
	PodCount       int           `json:"pod_count"`
	NamespaceCount int           `json:"namespace_count"`
	IngressHosts   []string      `json:"ingress_hosts,omitempty"`
	Pods           []PodInfo     `json:"pods,omitempty"`
	Warnings       []string      `json:"warnings,omitempty"`
}

// PodInfo describes a pod running on the current node.
type PodInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Status    string `json:"status"`
	Image     string `json:"image"`
	Restarts  int32  `json:"restarts"`
}

// K8sEvent represents a Kubernetes-native security event.
type K8sEvent struct {
	Type      string            // k8s_crashloop, k8s_oomkill, k8s_no_networkpolicy
	Severity  string            // warning, critical
	Details   map[string]string
}
