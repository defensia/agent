# Defensia — Marketplace Roadmap

## Estado actual

### DigitalOcean Marketplace — EN PROGRESO

**Archivos técnicos creados:**
- `install.sh` — nuevo flag `--install-only` (instala binario + systemd, no registra)
- `marketplace/digitalocean/packer/defensia.pkr.hcl` — template Packer HCL
- `marketplace/digitalocean/packer/scripts/01-install-defensia.sh` — instala agente
- `marketplace/digitalocean/packer/scripts/02-configure-ufw.sh` — configura UFW
- `marketplace/digitalocean/packer/scripts/90-cleanup.sh` — limpieza imagen
- `marketplace/digitalocean/packer/scripts/99-img-check.sh` — 12 validaciones DO
- `marketplace/digitalocean/packer/files/etc/update-motd.d/99-defensia` — MOTD
- `marketplace/digitalocean/packer/files/var/lib/cloud/scripts/per-instance/01-defensia-firstboot.sh`
- `marketplace/digitalocean/GETTING_STARTED.md` — guía para usuarios DO
- `marketplace/digitalocean/README.md` — docs del proceso build + submission

**Pendiente (manual):**
- [ ] Aplicar como vendor: https://marketplace.digitalocean.com/vendors
- [ ] Preparar W-8BEN-E (formulario fiscal non-US)
- [ ] Generar API token de DO: https://cloud.digitalocean.com/account/api/tokens
- [ ] Ejecutar `packer build defensia.pkr.hcl` para crear snapshot
- [ ] Submittear snapshot + metadata en Vendor Portal
- [ ] Esperar review de DO (1-2 semanas)

**Cómo construir la imagen:**
```bash
export DIGITALOCEAN_API_TOKEN="tu-token"
cd agent/marketplace/digitalocean/packer
packer init defensia.pkr.hcl
packer build defensia.pkr.hcl
```

**Flujo del usuario en DO:**
```
1. Crea Droplet "Defensia" desde DO Marketplace
2. SSH al Droplet → ve MOTD con instrucciones
3. Va a defensia.cloud → crea cuenta → Dashboard → Add Server → copia token
4. defensia-agent register https://defensia.cloud mi-server TOKEN
5. systemctl start defensia-agent
6. Servidor aparece en el dashboard
```

---

## Pendiente — Otros marketplaces (por orden de prioridad)

### Quick wins (30min cada uno)
- [ ] **Awesome Self-Hosted** — PR a https://github.com/awesome-selfhosted/awesome-selfhosted (200K+ stars)
- [ ] **Awesome Security** — PR a https://github.com/sbilly/awesome-security
- [ ] **AlternativeTo** — Registro en https://alternativeto.net/manage/submit-application/ (como alternativa a fail2ban, CrowdSec, UFW)

### Semana 2 — Marketplaces cloud (sin comisión)
- [ ] **Vultr Marketplace** — snapshot + cloud-init script. Vendor: https://www.vultr.com/marketplace/become-a-verified-vendor/
- [ ] **Linode/Akamai** — Ansible playbook + StackScript (PR a https://github.com/akamai-compute-marketplace/marketplace-apps)
- [ ] **Hetzner Community** — Tutorial "How to secure your Hetzner Cloud server with Defensia" en https://community.hetzner.com/

### Semana 3 — Lanzamiento
- [ ] **Product Hunt** — Launch day (una sola vez, todo pulido)
- [ ] **Docker Hub** — Imagen Docker para demos/testing

### Mes 2-3 — Expansión
- [ ] **OVHcloud** — Partner: https://partner.ovhcloud.com/en/
- [ ] **AWS Marketplace** — AMI listing (12-20% comisión)
- [ ] **GitHub Action** — Auto-deploy Defensia via SSH en CI/CD

### Solo si hay tracción
- [ ] Google Cloud Marketplace (3-20% comisión, proceso largo)
- [ ] Azure Marketplace (3% comisión, burocrático)

---

## Costes

| Canal | Comisión |
|---|---|
| DigitalOcean | 0% |
| Vultr | 0% |
| Linode/Akamai | 0% |
| Hetzner | 0% (no hay marketplace formal) |
| OVHcloud | 0% |
| Product Hunt | Gratis |
| AlternativeTo | Gratis |
| GitHub lists | Gratis |
| Docker Hub | Gratis |
| AWS | 12-20% |
| GCP | 3-20% |
| Azure | 3% |
