package updater

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// IsKubernetes returns true if the agent is running inside a Kubernetes pod.
func IsKubernetes() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil
}

// K8sRollingUpdate patches the agent's own DaemonSet to trigger a rolling update.
// It adds/updates an annotation that forces K8s to recreate all pods with the
// latest image (imagePullPolicy: Always ensures the new version is pulled).
func K8sRollingUpdate(currentVersion, latestVersion string, reportEvent EventReporter) {
	namespace := os.Getenv("POD_NAMESPACE")
	daemonsetName := os.Getenv("DAEMONSET_NAME")

	if namespace == "" || daemonsetName == "" {
		log.Printf("[updater] K8s rolling update skipped: POD_NAMESPACE or DAEMONSET_NAME not set")
		return
	}

	// Don't re-patch if we already triggered this version
	if data, err := os.ReadFile(updateAttemptMarker); err == nil {
		if markerVersion := string(data); markerVersion == latestVersion {
			return
		}
	}

	log.Printf("[updater] K8s mode: triggering rolling update %s -> %s (daemonset %s/%s)",
		currentVersion, latestVersion, namespace, daemonsetName)

	reportEvent("update_started", "info", map[string]string{
		"current_version": currentVersion,
		"target_version":  latestVersion,
		"method":          "k8s_rolling_update",
		"daemonset":       fmt.Sprintf("%s/%s", namespace, daemonsetName),
	})

	// Build the JSON patch
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"metadata": map[string]interface{}{
					"annotations": map[string]string{
						"defensia.cloud/updated-at":     time.Now().UTC().Format(time.RFC3339),
						"defensia.cloud/target-version": latestVersion,
					},
				},
			},
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		log.Printf("[updater] K8s patch marshal error: %v", err)
		return
	}

	// Read in-cluster credentials
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Printf("[updater] K8s token read error: %v", err)
		return
	}

	caCert, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		log.Printf("[updater] K8s CA cert read error: %v", err)
		return
	}

	apiHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	apiPort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if apiHost == "" || apiPort == "" {
		log.Printf("[updater] K8s API host/port not found in env")
		return
	}

	// Build HTTPS client with cluster CA
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	url := fmt.Sprintf("https://%s:%s/apis/apps/v1/namespaces/%s/daemonsets/%s",
		apiHost, apiPort, namespace, daemonsetName)

	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(patchBytes))
	if err != nil {
		log.Printf("[updater] K8s request error: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[updater] K8s patch request failed: %v", err)
		reportEvent("update_failed", "high", map[string]string{
			"current_version": currentVersion,
			"target_version":  latestVersion,
			"reason":          "k8s_patch_failed",
			"error":           err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[updater] K8s API returned %d: %s", resp.StatusCode, string(body))
		reportEvent("update_failed", "high", map[string]string{
			"current_version": currentVersion,
			"target_version":  latestVersion,
			"reason":          "k8s_api_error",
			"error":           fmt.Sprintf("HTTP %d", resp.StatusCode),
		})
		return
	}

	log.Printf("[updater] K8s rolling update triggered — pods will restart with new image")
	reportEvent("update_completed", "info", map[string]string{
		"current_version": currentVersion,
		"target_version":  latestVersion,
		"method":          "k8s_rolling_update",
	})

	// Write marker so we don't keep patching every heartbeat
	os.WriteFile(updateAttemptMarker, []byte(latestVersion), 0644)
}
