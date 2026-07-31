# Defensia Agent — Helm Chart

Deploy the [Defensia](https://defensia.cloud) security agent as a DaemonSet on your Kubernetes cluster. Each node gets an agent that provides brute-force protection, WAF, bot detection, vulnerability scanning, malware scanning, and real-time firewall management.

## Prerequisites

- Kubernetes 1.22+
- Helm 3+
- A Defensia account with an install token from [defensia.cloud](https://defensia.cloud)

## Install

```bash
helm install defensia-agent oci://ghcr.io/defensia/charts/defensia-agent \
  --set apiKey="YOUR_API_KEY"
```

## Upgrade

```bash
helm upgrade defensia-agent oci://ghcr.io/defensia/charts/defensia-agent \
  --version 0.6.0
```

## Uninstall

```bash
helm uninstall defensia-agent
```

## Configuration

| Parameter | Description | Default |
|---|---|---|
| `apiKey` | API key from Defensia panel | `""` (required) |
| `serverUrl` | Defensia panel URL | `https://defensia.cloud` |
| `clusterName` | Cluster name (auto-detected if not set) | `""` |
| `image.repository` | Container image | `ghcr.io/defensia/agent` |
| `image.tag` | Image tag (defaults to chart `appVersion`) | `""` |
| `image.pullPolicy` | Image pull policy | `Always` |
| `autoUpdate.enabled` | Agent patches its own DaemonSet for rolling updates. **Disable if using GitOps (ArgoCD, Flux).** | `true` |
| `ingressFirewall.enabled` | Create nginx-ingress RBAC for ConfigMap-level IP blocking. **Disable if not using nginx-ingress.** | `false` |
| `ingressFirewall.namespace` | Namespace where nginx-ingress runs | `ingress-nginx` |
| `ingressFirewall.configMapName` | nginx-ingress ConfigMap name | `ingress-nginx-controller` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `256Mi` |
| `resources.requests.cpu` | CPU request | `50m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `tolerations` | Node tolerations | `[{operator: Exists}]` (all nodes) |
| `nodeSelector` | Node selector | `{}` |
| `priorityClassName` | Priority class | `""` |
| `extraEnv` | Additional environment variables | `[]` |
| `serviceAccount.create` | Create service account | `true` |
| `serviceAccount.name` | Service account name override | `""` |
| `serviceAccount.annotations` | Service account annotations | `{}` |

### GitOps / ArgoCD setup

If you manage deployments via ArgoCD or Flux, disable the built-in auto-update to avoid conflicts:

```yaml
autoUpdate:
  enabled: false
```

The agent will not modify K8s resources. You control updates by bumping the image tag in your GitOps repo.

### Traefik / non-nginx ingress

The chart works with any ingress controller. By default, no nginx-specific RBAC is created. IP blocking works at the **iptables/host level** regardless of ingress controller.

If you use Traefik, enable access logs so the agent can detect web attacks:

```yaml
# In your Traefik Helm values
logs:
  access:
    enabled: true
```

### Extra environment variables

```yaml
extraEnv:
  - name: WEB_LOG_PATH
    value: "/var/log/nginx/access.log"
  - name: GEOIP_DB_PATH
    value: "/usr/share/GeoIP/GeoLite2-Country.mmdb"
  - name: DISABLE_K8S_AUTO_UPDATE
    value: "true"
```

## What gets deployed

- **DaemonSet**: One agent pod per node (including control-plane via tolerations)
- **ServiceAccount + ClusterRole + ClusterRoleBinding**: Read-only K8s API access (pods, nodes, events, ingresses, networkpolicies) + DaemonSet patch for auto-updates
- **Secret**: Stores the API key
- **Role + RoleBinding** (optional): Only when `ingressFirewall.enabled: true` — grants ConfigMap write access in the ingress namespace

### Host mounts

| Mount | Path | Mode |
|---|---|---|
| Logs | `/var/log` | read-only |
| Docker socket | `/var/run/docker.sock` | read-only |
| Containerd socket | `/run/containerd/containerd.sock` | read-only |
| Agent config | `/etc/defensia` | read-write |

## Agent capabilities

- SSH brute-force detection and auto-banning via iptables/ipset
- Web attack detection (SQL injection, XSS, path traversal, RCE, SSRF)
- Log parsing: **nginx, Apache, Traefik (JSON), Caddy, LiteSpeed, uvicorn, gunicorn**
- Country-based geoblocking (MaxMind GeoLite2)
- Bot fingerprint detection with configurable actions
- Malware scanning with real-time progress (YARA, signature matching, heuristics)
- CVE advisory matching (NVD, CISA KEV, Exploit-DB)
- System metrics (CPU, memory, disk, load, network I/O)
- Kubernetes: pod inventory, NetworkPolicy audit, event monitoring
- Real-time firewall rule management via WebSocket
- Auto-update with SHA256 verification and crash-loop recovery

## Links

- [Defensia Dashboard](https://defensia.cloud)
- [Agent Documentation](https://github.com/defensia/agent#readme)
- [Report Issues](https://github.com/defensia/agent/issues)
