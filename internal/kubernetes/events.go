//go:build kubernetes

package kubernetes

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
)

// WatchEvents watches for security-relevant K8s events and calls the callback.
// Runs as a long-lived goroutine. Reconnects on failure.
func (c *Client) WatchEvents(callback func(K8sEvent)) {
	for {
		c.watchOnce(callback)
		log.Println("[kubernetes] event watcher disconnected, reconnecting in 10s...")
		time.Sleep(10 * time.Second)
	}
}

func (c *Client) watchOnce(callback func(K8sEvent)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher, err := c.clientset.CoreV1().Events("").Watch(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.kind=Pod",
	})
	if err != nil {
		log.Printf("[kubernetes] failed to watch events: %v", err)
		return
	}
	defer watcher.Stop()

	for event := range watcher.ResultChan() {
		if event.Type != watch.Added && event.Type != watch.Modified {
			continue
		}

		k8sEvent, ok := event.Object.(*corev1.Event)
		if !ok {
			continue
		}

		// Only process events on this node
		if k8sEvent.Source.Host != c.nodeName && k8sEvent.ReportingInstance != c.nodeName {
			// Check via pod's nodeName
			if !c.isPodOnThisNode(k8sEvent.InvolvedObject.Namespace, k8sEvent.InvolvedObject.Name) {
				continue
			}
		}

		secEvent := c.classifyEvent(k8sEvent)
		if secEvent != nil {
			callback(*secEvent)
		}
	}
}

func (c *Client) classifyEvent(event *corev1.Event) *K8sEvent {
	reason := strings.ToLower(event.Reason)
	msg := strings.ToLower(event.Message)

	switch {
	case reason == "backoff" && strings.Contains(msg, "back-off restarting failed container"):
		return &K8sEvent{
			Type:     "k8s_crashloop",
			Severity: "critical",
			Details: map[string]string{
				"pod":       event.InvolvedObject.Name,
				"namespace": event.InvolvedObject.Namespace,
				"message":   event.Message,
				"count":     fmt.Sprintf("%d", event.Count),
			},
		}

	case reason == "oomkilling" || strings.Contains(msg, "oomkill"):
		return &K8sEvent{
			Type:     "k8s_oomkill",
			Severity: "critical",
			Details: map[string]string{
				"pod":       event.InvolvedObject.Name,
				"namespace": event.InvolvedObject.Namespace,
				"message":   event.Message,
			},
		}

	case reason == "failed" && strings.Contains(msg, "image"):
		return &K8sEvent{
			Type:     "k8s_image_pull_failed",
			Severity: "warning",
			Details: map[string]string{
				"pod":       event.InvolvedObject.Name,
				"namespace": event.InvolvedObject.Namespace,
				"message":   event.Message,
			},
		}

	case reason == "evicted":
		return &K8sEvent{
			Type:     "k8s_pod_evicted",
			Severity: "warning",
			Details: map[string]string{
				"pod":       event.InvolvedObject.Name,
				"namespace": event.InvolvedObject.Namespace,
				"message":   event.Message,
			},
		}
	}

	return nil
}

func (c *Client) isPodOnThisNode(namespace, name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return false
	}
	return pod.Spec.NodeName == c.nodeName
}
