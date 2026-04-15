#!/usr/bin/env bash
# Deploy the authz components to a PiKVM device over SSH/SCP.
#
# Usage: ./deploy-authz.sh [user@]<host>
#   e.g. ./deploy-authz.sh pikvm.local
#        ./deploy-authz.sh root@192.168.1.50
#
# What this does:
#   1. Detects Python version and device architecture.
#   2. Remounts the root filesystem rw.
#   3. Uploads changed Python source files into site-packages.
#   4. Installs the OPA binary if not already present (downloads for the
#      correct architecture from GitHub releases).
#   5. Deploys the authz bundle to /etc/kvmd/authz/bundle/.
#   6. Deploys opa-config.yaml to /etc/kvmd/authz/.
#   7. Installs the kvmd-authz.service systemd unit.
#   8. Clears Python bytecode caches for changed packages.
#   9. Enables and (re)starts kvmd-authz.service, then restarts kvmd.
#  10. Remounts the root filesystem ro (even on failure).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 [user@]<host>"
    exit 1
fi

[[ "$TARGET" != *@* ]] && TARGET="root@${TARGET}"

SSH=("ssh" "$TARGET")
HOST_ONLY="${TARGET#*@}"

OPA_VERSION="${OPA_VERSION:-1.4.2}"

# ── Preflight ─────────────────────────────────────────────────────────────────
REQUIRED_FILES=(
    kvmd/apps/_scheme.py
    kvmd/apps/kvmd/__init__.py
    kvmd/apps/kvmd/authz.py
    kvmd/apps/kvmd/server.py
    kvmd/apps/kvmd/api/auth.py
    kvmd/apps/kvmd/api/switch.py
    kvmd/apps/kvmd/switch/__init__.py
    kvmd/apps/kvmd/switch/state.py
    kvmd/htserver.py
    configs/kvmd/authz/bundle/policy/authz.rego
    configs/kvmd/authz/bundle/data.json
    configs/kvmd/authz/opa-config.yaml
    configs/os/services/kvmd-authz.service
)
for f in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "${REPO_ROOT}/${f}" ]]; then
        echo "ERROR: Expected file not found in repo: ${f}"
        exit 1
    fi
done

# ── Detect remote environment ─────────────────────────────────────────────────
echo "==> Connecting to ${HOST_ONLY} ..."

PYTHON_VER=$("${SSH[@]}" "python3 -c \"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"")
SITE_PKG="/usr/lib/python${PYTHON_VER}/site-packages"
echo "    Python ${PYTHON_VER}  ->  ${SITE_PKG}"

ARCH=$("${SSH[@]}" "uname -m")
echo "    Architecture: ${ARCH}"

case "$ARCH" in
    aarch64|arm64) OPA_ARCH="linux_arm64_static" ;;
    armv7l|armv6l) OPA_ARCH="linux_arm_static"   ;;
    x86_64)        OPA_ARCH="linux_amd64_static"  ;;
    *)
        echo "ERROR: Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

# ── Remount rw ────────────────────────────────────────────────────────────────
echo "==> Remounting root filesystem rw ..."
"${SSH[@]}" "mount -o remount,rw /"

remount_ro() {
    echo "==> Remounting root filesystem ro ..."
    "${SSH[@]}" "mount -o remount,ro /" || true
}
trap remount_ro EXIT

# ── Python source files ───────────────────────────────────────────────────────
echo "==> Uploading Python source files ..."

declare -a PY_FILES=(
    "kvmd/apps/_scheme.py:${SITE_PKG}/kvmd/apps/_scheme.py"
    "kvmd/apps/kvmd/__init__.py:${SITE_PKG}/kvmd/apps/kvmd/__init__.py"
    "kvmd/apps/kvmd/authz.py:${SITE_PKG}/kvmd/apps/kvmd/authz.py"
    "kvmd/apps/kvmd/server.py:${SITE_PKG}/kvmd/apps/kvmd/server.py"
    "kvmd/apps/kvmd/api/auth.py:${SITE_PKG}/kvmd/apps/kvmd/api/auth.py"
    "kvmd/apps/kvmd/api/switch.py:${SITE_PKG}/kvmd/apps/kvmd/api/switch.py"
    "kvmd/apps/kvmd/switch/__init__.py:${SITE_PKG}/kvmd/apps/kvmd/switch/__init__.py"
    "kvmd/apps/kvmd/switch/state.py:${SITE_PKG}/kvmd/apps/kvmd/switch/state.py"
    "kvmd/htserver.py:${SITE_PKG}/kvmd/htserver.py"
)

for entry in "${PY_FILES[@]}"; do
    src="${REPO_ROOT}/${entry%%:*}"
    dst="${entry##*:}"
    echo "    ${entry%%:*}"
    scp "$src" "${TARGET}:${dst}"
done

# ── OPA binary ────────────────────────────────────────────────────────────────
OPA_INSTALLED=$("${SSH[@]}" "command -v opa && opa version 2>/dev/null | head -1 || echo missing")
echo "==> OPA on device: ${OPA_INSTALLED}"

if echo "$OPA_INSTALLED" | grep -q "missing"; then
    echo "==> OPA not found — downloading v${OPA_VERSION} for ${OPA_ARCH} ..."
    OPA_URL="https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_${OPA_ARCH}"
    OPA_TMP="$(mktemp /tmp/opa-XXXXXX)"
    curl -fsSL -o "$OPA_TMP" "$OPA_URL"
    scp "$OPA_TMP" "${TARGET}:/usr/bin/opa"
    rm -f "$OPA_TMP"
    "${SSH[@]}" "chmod 755 /usr/bin/opa"
    echo "    OPA installed: $("${SSH[@]}" "opa version 2>/dev/null | head -1")"
else
    echo "    OPA already installed — skipping download."
fi

# ── Authz bundle ──────────────────────────────────────────────────────────────
echo "==> Deploying authz bundle to /etc/kvmd/authz/bundle/ ..."
"${SSH[@]}" "mkdir -p /etc/kvmd/authz/bundle/policy /etc/kvmd/authz/bundle/devices"

scp "${REPO_ROOT}/configs/kvmd/authz/bundle/policy/authz.rego" \
    "${TARGET}:/etc/kvmd/authz/bundle/policy/authz.rego"
scp "${REPO_ROOT}/configs/kvmd/authz/bundle/data.json" \
    "${TARGET}:/etc/kvmd/authz/bundle/data.json"

# Copy any per-device data directories from the bundle.
if [[ -d "${REPO_ROOT}/configs/kvmd/authz/bundle/devices" ]]; then
    for device_dir in "${REPO_ROOT}/configs/kvmd/authz/bundle/devices"/*/; do
        device_id="$(basename "$device_dir")"
        echo "    device: ${device_id}"
        "${SSH[@]}" "mkdir -p /etc/kvmd/authz/bundle/devices/${device_id}"
        scp "${device_dir}data.json" \
            "${TARGET}:/etc/kvmd/authz/bundle/devices/${device_id}/data.json"
    done
fi

# The bundle manifest (tells OPA what files are in the bundle).
if [[ -f "${REPO_ROOT}/configs/kvmd/authz/bundle/.manifest" ]]; then
    scp "${REPO_ROOT}/configs/kvmd/authz/bundle/.manifest" \
        "${TARGET}:/etc/kvmd/authz/bundle/.manifest"
fi

echo "==> Deploying opa-config.yaml ..."
scp "${REPO_ROOT}/configs/kvmd/authz/opa-config.yaml" \
    "${TARGET}:/etc/kvmd/authz/opa-config.yaml"

# ── Systemd service ───────────────────────────────────────────────────────────
echo "==> Installing kvmd-authz.service ..."
scp "${REPO_ROOT}/configs/os/services/kvmd-authz.service" \
    "${TARGET}:/etc/systemd/system/kvmd-authz.service"

# ── Bytecode caches ───────────────────────────────────────────────────────────
echo "==> Clearing Python bytecode caches ..."
"${SSH[@]}" "rm -rf \
    ${SITE_PKG}/kvmd/apps/__pycache__ \
    ${SITE_PKG}/kvmd/apps/kvmd/__pycache__ \
    ${SITE_PKG}/kvmd/apps/kvmd/api/__pycache__ \
    ${SITE_PKG}/kvmd/apps/kvmd/switch/__pycache__ \
    ${SITE_PKG}/kvmd/__pycache__"

# ── Start / restart services ──────────────────────────────────────────────────
echo "==> Enabling and starting kvmd-authz ..."
"${SSH[@]}" "systemctl daemon-reload && systemctl enable kvmd-authz && systemctl restart kvmd-authz"

echo "==> Restarting kvmd ..."
"${SSH[@]}" "systemctl restart kvmd"

echo ""
echo "Done. Authz deployed to ${HOST_ONLY}."
echo ""
echo "Next steps:"
echo ""
echo "1. Enable authz in /etc/kvmd/override.yaml (device must be in rw mode):"
echo "   ssh ${TARGET} 'mount -o remount,rw /'"
echo "   # Add to /etc/kvmd/override.yaml under the kvmd: section:"
echo "   #   kvmd:"
echo "   #     authz:"
echo "   #       enabled: true"
echo "   #       device_id: \$(hostname)   # must match directory under /etc/kvmd/authz/bundle/devices/"
echo ""
echo "2. Create the per-device bundle entry (replace 'pikvm' with the device's hostname):"
echo "   ssh ${TARGET} 'mkdir -p /etc/kvmd/authz/bundle/devices/pikvm && echo {\\\"standalone\\\":true} > /etc/kvmd/authz/bundle/devices/pikvm/data.json'"
echo "   # Omit standalone:true if a KVM switch is connected."
echo ""
echo "3. Add users to htpasswd AND to /etc/kvmd/authz/bundle/data.json:"
echo "   ssh ${TARGET} 'kvmd-htpasswd set <OP_USER>     <OP_PASS>'"
echo "   ssh ${TARGET} 'kvmd-htpasswd set <VIEWER_USER> <VIEWER_PASS>'"
echo "   # In /etc/kvmd/authz/bundle/data.json add each user under \"users\":"
echo "   #   \"<OP_USER>\":     { \"roles\": [\"operator\"] },"
echo "   #   \"<VIEWER_USER>\": { \"roles\": [\"viewer\"] }"
echo ""
echo "4. Restart services and remount ro:"
echo "   ssh ${TARGET} 'systemctl restart kvmd-authz kvmd && mount -o remount,ro /'"
