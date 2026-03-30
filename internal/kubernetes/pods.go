//go:build kubernetes

package kubernetes

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ListPodsOnNode returns all pods scheduled on this node.
func (c *Client) ListPodsOnNode() []PodInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + c.nodeName,
	})
	if err != nil {
		return nil
	}

	result := make([]PodInfo, 0, len(pods.Items))
	for _, pod := range pods.Items {
		image := ""
		if len(pod.Spec.Containers) > 0 {
			image = pod.Spec.Containers[0].Image
		}

		var restarts int32
		for _, cs := range pod.Status.ContainerStatuses {
			restarts += cs.RestartCount
		}

		result = append(result, PodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			Status:    string(pod.Status.Phase),
			Image:     image,
			Restarts:  restarts,
		})
	}

	return result
}

// CountNamespaces returns the total number of namespaces in the cluster.
func (c *Client) CountNamespaces() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ns, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	return len(ns.Items)
}
