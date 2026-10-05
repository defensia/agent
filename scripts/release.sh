#!/bin/bash
#
# Defensia Agent Release Script
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 1.4.75
#
# Does ALL steps in order:
# 1. Updates version string in main.go
# 2. Builds amd64 + arm64 binaries
# 3. Generates SHA256 checksums
# 4. Commits + tags + pushes
# 5. Creates GitHub release with binaries + SHA256 files
# 6. Uploads to mirror (defensia.cloud/downloads)
# 7. Updates mirror SHA256 files
# 8. Updates latest_agent_version + download URL in panel
#
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.4.75"
    exit 1
fi

REMOTE_HOST="185.7.81.107"
REMOTE_PASS="DatingSlaverMelterDecerp"
MIRROR_DIR="/var/lib/docker/volumes/defensia_app-public/_data/downloads"

echo "=== Defensia Agent Release v${VERSION} ==="

# 1. Update version in main.go
echo "[1/8] Updating version..."
CURRENT=$(grep 'var version = ' cmd/defensia-agent/main.go | grep -o '"[^"]*"' | tr -d '"')
sed -i '' "s/var version = \"${CURRENT}\"/var version = \"${VERSION}\"/" cmd/defensia-agent/main.go
echo "  ${CURRENT} → ${VERSION}"

# 2. Build binaries
echo "[2/8] Building binaries..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o defensia-agent ./cmd/defensia-agent/
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o defensia-agent-linux-arm64 ./cmd/defensia-agent/
echo "  amd64: $(ls -lh defensia-agent | awk '{print $5}')"
echo "  arm64: $(ls -lh defensia-agent-linux-arm64 | awk '{print $5}')"

# 3. Generate SHA256
echo "[3/8] Generating SHA256 checksums..."
sha256sum defensia-agent | sed 's/defensia-agent/defensia-agent-linux-amd64/' > defensia-agent-linux-amd64.sha256
sha256sum defensia-agent-linux-arm64 > defensia-agent-linux-arm64.sha256
cat defensia-agent-linux-amd64.sha256
cat defensia-agent-linux-arm64.sha256

# 4. Commit + tag + push
echo "[4/8] Committing and pushing..."
git add cmd/defensia-agent/main.go
git -c user.name="defensia-bot" -c user.email="defensia-bot@users.noreply.github.com" \
    commit -m "release: v${VERSION}" --allow-empty
git tag "v${VERSION}"
git push origin main --tags

# 5. GitHub release with ALL assets
echo "[5/8] Creating GitHub release..."
gh release create "v${VERSION}" \
    defensia-agent \
    defensia-agent-linux-arm64 \
    defensia-agent-linux-amd64.sha256 \
    defensia-agent-linux-arm64.sha256 \
    --title "v${VERSION}" \
    --generate-notes

# 6. Upload to mirror
echo "[6/8] Uploading to mirror..."
sshpass -p "${REMOTE_PASS}" scp -o PubkeyAuthentication=no -o StrictHostKeyChecking=no \
    defensia-agent defensia-agent-linux-arm64 \
    "root@${REMOTE_HOST}:/tmp/"
sshpass -p "${REMOTE_PASS}" ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no \
    "root@${REMOTE_HOST}" \
    "cp /tmp/defensia-agent ${MIRROR_DIR}/defensia-agent && \
     cp /tmp/defensia-agent-linux-arm64 ${MIRROR_DIR}/defensia-agent-linux-arm64 && \
     chmod 755 ${MIRROR_DIR}/defensia-agent*"

# 7. Update mirror SHA256
echo "[7/8] Updating mirror SHA256..."
sshpass -p "${REMOTE_PASS}" ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no \
    "root@${REMOTE_HOST}" \
    "cd ${MIRROR_DIR} && \
     sha256sum defensia-agent | sed 's/defensia-agent/defensia-agent-linux-amd64/' > defensia-agent-linux-amd64.sha256 && \
     sha256sum defensia-agent-linux-arm64 > defensia-agent-linux-arm64.sha256"

# 8. Update panel version
echo "[8/8] Updating panel version..."
sshpass -p "${REMOTE_PASS}" ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no \
    "root@${REMOTE_HOST}" \
    "docker exec defensia-app-1 php artisan tinker --execute=\"\\\$s = app(\App\Services\SettingsService::class); \\\$s->set('latest_agent_version', '${VERSION}'); \\\$s->set('agent_download_base_url', 'https://github.com/defensia/agent/releases/download/v${VERSION}'); echo 'OK: ${VERSION}';\""

echo ""
echo "=== Release v${VERSION} complete ==="
echo "  GitHub: https://github.com/defensia/agent/releases/tag/v${VERSION}"
echo "  Mirror: https://defensia.cloud/downloads/defensia-agent"
echo "  Panel:  latest_agent_version = ${VERSION}"

# Cleanup local SHA256 files
rm -f defensia-agent-linux-amd64.sha256 defensia-agent-linux-arm64.sha256
