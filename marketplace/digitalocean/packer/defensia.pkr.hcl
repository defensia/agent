packer {
  required_plugins {
    digitalocean = {
      version = ">= 1.1.1"
      source  = "github.com/digitalocean/digitalocean"
    }
  }
}

variable "do_api_token" {
  type      = string
  sensitive = true
  default   = env("DIGITALOCEAN_API_TOKEN")
}

variable "image_name" {
  type    = string
  default = "defensia-agent"
}

variable "agent_version" {
  type    = string
  default = "latest"
}

source "digitalocean" "defensia" {
  api_token     = var.do_api_token
  image         = "ubuntu-22-04-x64"
  region        = "fra1"
  size          = "s-1vcpu-1gb"
  ssh_username  = "root"
  snapshot_name = "${var.image_name}-${formatdate("YYYYMMDD-hhmm", timestamp())}"
  snapshot_regions = [
    "nyc1", "nyc3", "sfo3", "ams3", "sgp1",
    "lon1", "fra1", "tor1", "blr1", "syd1"
  ]
  tags = ["defensia", "security"]
}

build {
  sources = ["source.digitalocean.defensia"]

  # Wait for cloud-init to finish
  provisioner "shell" {
    inline = ["cloud-init status --wait"]
  }

  # Copy first-boot script + MOTD
  provisioner "file" {
    source      = "files/var/"
    destination = "/var/"
  }

  provisioner "file" {
    source      = "files/etc/"
    destination = "/etc/"
  }

  # Make scripts executable
  provisioner "shell" {
    inline = [
      "chmod +x /var/lib/cloud/scripts/per-instance/01-defensia-firstboot.sh",
      "chmod +x /etc/update-motd.d/99-defensia"
    ]
  }

  # Install Defensia agent
  provisioner "shell" {
    script = "scripts/01-install-defensia.sh"
  }

  # Configure firewall
  provisioner "shell" {
    script = "scripts/02-configure-ufw.sh"
  }

  # Clean up for image
  provisioner "shell" {
    script = "scripts/90-cleanup.sh"
  }

  # Validate image meets DO requirements
  provisioner "shell" {
    script = "scripts/99-img-check.sh"
  }
}
