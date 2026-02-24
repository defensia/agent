# Getting Started with Defensia on DigitalOcean

Defensia is an open-source security agent that protects your Linux server from brute force attacks. It monitors `auth.log`, automatically blocks attackers via `iptables`, and syncs threat intelligence across all your servers.

## Step 1: Create your Droplet

Click **Create Defensia Droplet** from the DigitalOcean Marketplace. Choose your preferred size and region.

## Step 2: Get your Defensia token

1. Go to [defensia.cloud](https://defensia.cloud) and create a free account
2. In the dashboard, click **Add Server**
3. Copy the install token that appears

## Step 3: Connect your server

SSH into your new Droplet:

```bash
ssh root@your-droplet-ip
```

Register the agent with your token:

```bash
defensia-agent register https://defensia.cloud my-server YOUR_TOKEN
```

Start the agent:

```bash
systemctl start defensia-agent
```

## Step 4: Verify

Check that the agent is running:

```bash
systemctl status defensia-agent
```

Your server should now appear in your [Defensia dashboard](https://defensia.cloud/dashboard).

## What Defensia does

- **Brute force protection**: Monitors SSH login attempts and auto-bans IPs after 5 failed attempts
- **Firewall management**: Applies iptables rules in real-time
- **Threat intelligence**: Shares attack data across all your servers via the DEFENSIA Network
- **Vulnerability scanning**: On-demand security audits from the dashboard
- **Real-time dashboard**: See events, bans, and server status at defensia.cloud

## Useful commands

```bash
# Check agent status
systemctl status defensia-agent

# View real-time logs
journalctl -u defensia-agent -f

# Stop the agent
systemctl stop defensia-agent

# Uninstall completely
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --uninstall
```

## Pricing

| Plan | Price | Servers |
|---|---|---|
| Free | $0 | 1 server |
| Pro | €9/server/month | Unlimited |

Free includes brute force protection, threat intel, and the dashboard. Pro adds geoblocking, vulnerability scanning, the DEFENSIA Network, alerts, and webhooks.

## Support

- Documentation: [github.com/defensia/agent](https://github.com/defensia/agent)
- Issues: [github.com/defensia/agent/issues](https://github.com/defensia/agent/issues)
- Website: [defensia.cloud](https://defensia.cloud)
