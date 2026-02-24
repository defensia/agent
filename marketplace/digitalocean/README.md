# Defensia — DigitalOcean Marketplace

Pre-built Droplet image with the Defensia security agent pre-installed.

## What's included

- Ubuntu 22.04 LTS
- Defensia Agent (latest release from [github.com/defensia/agent](https://github.com/defensia/agent))
- UFW firewall (deny incoming, allow SSH + outbound)
- systemd service (enabled, not started until configured)

## Build the image

### Prerequisites

- [Packer](https://www.packer.io/downloads) 1.9+
- [DigitalOcean API token](https://cloud.digitalocean.com/account/api/tokens)

### Build

```bash
cd packer

export DIGITALOCEAN_API_TOKEN="your-api-token"

packer init defensia.pkr.hcl
packer build defensia.pkr.hcl
```

This will:
1. Create a temporary $6 Droplet in Frankfurt (fra1)
2. Install Defensia agent + dependencies
3. Configure UFW firewall
4. Clean up the image (logs, history, SSH keys)
5. Run validation checks (12 checks)
6. Snapshot the Droplet → available in your DO account
7. Destroy the temporary Droplet

Build time: ~3-5 minutes. Cost: ~$0.01.

### Update the image

When a new Defensia version is released, rebuild:

```bash
packer build defensia.pkr.hcl
```

Then update the listing in the [Vendor Portal](https://marketplace.digitalocean.com/vendors) with the new snapshot ID.

## Vendor Portal submission

Submit through the Vendor Portal with:

| Field | Value |
|---|---|
| App name | Defensia |
| Summary | Open-source security agent that monitors auth.log, blocks brute force attacks via iptables, and syncs threat intelligence from the cloud. |
| OS | Ubuntu 22.04 |
| Software | Defensia Agent (latest), MIT License |
| Category | Security |
| Support URL | https://github.com/defensia/agent/issues |
| Docs URL | https://github.com/defensia/agent |

## User flow

```
1. User creates Droplet from Marketplace listing
2. SSH into Droplet → sees MOTD with setup instructions
3. Signs up at https://defensia.cloud (if new)
4. Dashboard → "Add Server" → copies install token
5. Runs: defensia-agent register https://defensia.cloud my-server TOKEN
6. Runs: systemctl start defensia-agent
7. Server appears in dashboard — protected
```
