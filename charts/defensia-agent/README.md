# Defensia Agent — Helm Chart

Deploy the [Defensia](https://defensia.cloud) security agent as a DaemonSet on your Kubernetes cluster. Each node gets an agent that provides brute-force protection, WAF, geoblocking, bot detection, vulnerability scanning, and real-time firewall management.

## Prerequisites

- Kubernetes 1.22+
- Helm 3+
- A Defensia account with an install token from [defensia.cloud](https://defensia.cloud)

## Install

```bash
helm install defensia-agent oci://ghcr.io/defensia/charts/defensia-agent \
  --set token="YOUR_INSTALL_TOKEN"
```

Or using an existing Kubernetes Secret:

```bash
kubectl create secret generic defensia-token --from-literal=token=YOUR_INSTALL_TOKEN

helm install defensia-agent oci://ghcr.io/defensia/charts/defensia-agent \
  --set existingSecret=defensia-token
```

## Uninstall

```bash
helm uninstall defensia-agent
```

## Configuration

| Parameter | Description | Default |
|---|---|---|
| `token` | Install token from Defensia panel | `""` |
| `existingSecret` | Name of existing Secret containing `token` key | `""` |
| `serverUrl` | Defensia panel URL | `https://defensia.cloud` |
| `agentName` | Agent name override (default: node hostname) | `""` |
| `image.repository` | Container image | `ghcr.io/defensia/agent` |
| `image.tag` | Image tag (defaults to chart `appVersion`) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `50m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `tolerations` | Node tolerations | `[{operator: Exists}]` |
| `nodeSelector` | Node selector | `{}` |
| `affinity` | Affinity rules | `{}` |
| `hostPaths.log` | Host log path to mount | `/var/log` |
| `hostPaths.dockerSocket` | Docker socket path | `/var/run/docker.sock` |
| `extraEnv` | Additional environment variables | `[]` |

### Extra environment variables

```yaml
extraEnv:
  - name: WEB_LOG_PATH
    value: "/var/log/nginx/access.log"
  - name: GEOIP_DB_PATH
    value: "/usr/share/GeoIP/GeoLite2-Country.mmdb"
  - name: AUTH_LOG_PATH
    value: "/var/log/auth.log"
```

## What gets deployed

- **DaemonSet**: One agent pod per node (including control-plane nodes via tolerations)
- **Secret**: Stores the install token (unless using `existingSecret`)
- Host paths `/var/log` and `/var/run/docker.sock` are mounted read-only

## Agent capabilities

- SSH brute-force detection and auto-banning via iptables
- Web attack detection (SQL injection, XSS, path traversal, RCE)
- Country-based geoblocking (MaxMind GeoLite2)
- Bot fingerprint detection with configurable actions
- On-demand vulnerability scanning
- Software inventory collection
- System metrics (CPU, memory, disk, load, network I/O)
- Real-time firewall rule management via WebSocket
- Auto-update with SHA256 verification and crash-loop recovery

## Docker labels

Configure monitoring per container without agent restart:

```yaml
services:
  nginx:
    labels:
      defensia.monitor: "true"
      defensia.log-path: "/var/log/nginx/access.log"
      defensia.domain: "example.com"
```

| Label | Description |
|-------|-------------|
| `defensia.monitor` | Force-include (`true`) or exclude (`false`) a container |
| `defensia.log-path` | Explicit host log path(s), comma-separated |
| `defensia.domain` | Associate domain(s) with this container's logs |
| `defensia.waf` | Informational — WAF config is controlled from the dashboard |

## Links

- [Defensia Dashboard](https://defensia.cloud)
- [Agent Documentation](https://github.com/defensia/agent#readme)
- [Docker Hub](https://hub.docker.com/r/defensiacloud/agent)
- [Report Issues](https://github.com/defensia/agent/issues)
