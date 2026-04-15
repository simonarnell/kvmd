#!/usr/bin/env bash
# Deploy the cert API to a PiKVM device over SSH/SCP.
#
# Usage: ./deploy-cert-api.sh [user@]<host>
#   e.g. ./deploy-cert-api.sh pikvm.local
#        ./deploy-cert-api.sh root@192.168.1.50
#
# What this does:
#   1. Detects the Python version on the device.
#   2. Remounts the root filesystem rw.
#   3. Copies the cert API Python files into site-packages.
#   4. Installs /usr/bin/kvmd-helper-certssl-commit.
#   5. Adds the sudo rule to /etc/sudoers.d/99_kvmd (idempotent).
#   6. Clears Python bytecode caches for the changed packages.
#   7. Restarts kvmd to pick up the new code.
#   8. Remounts the root filesystem ro (even on failure).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 [user@]<host>"
    exit 1
fi

# Prepend root@ if no user was given.
if [[ "$TARGET" != *@* ]]; then
    TARGET="root@${TARGET}"
fi

SSH=("ssh" "$TARGET")
HOST_ONLY="${TARGET#*@}"

# ── Preflight ─────────────────────────────────────────────────────────────────
for f in \
    kvmd/helpers/certssl/__init__.py \
    kvmd/apps/kvmd/api/cert.py
do
    if [[ ! -f "${REPO_ROOT}/${f}" ]]; then
        echo "ERROR: Expected file not found in repo: ${f}"
        exit 1
    fi
done

# ── Detect Python version ─────────────────────────────────────────────────────
echo "==> Connecting to ${HOST_ONLY} ..."
PYTHON_VER=$("${SSH[@]}" "python3 -c \"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')\"")
SITE_PKG="/usr/lib/python${PYTHON_VER}/site-packages"
echo "    Python ${PYTHON_VER}  ->  ${SITE_PKG}"

# ── Remount rw ────────────────────────────────────────────────────────────────
echo "==> Remounting root filesystem rw ..."
"${SSH[@]}" "mount -o remount,rw /"

# Always remount ro on exit, even on error.
remount_ro() {
    echo "==> Remounting root filesystem ro ..."
    "${SSH[@]}" "mount -o remount,ro /" || true
}
trap remount_ro EXIT

# ── Python files ──────────────────────────────────────────────────────────────
echo "==> Creating kvmd.helpers.certssl package directory ..."
"${SSH[@]}" "mkdir -p ${SITE_PKG}/kvmd/helpers/certssl"

echo "==> Uploading cert API source files ..."
scp "${REPO_ROOT}/kvmd/helpers/certssl/__init__.py" \
    "${TARGET}:${SITE_PKG}/kvmd/helpers/certssl/__init__.py"
scp "${REPO_ROOT}/kvmd/apps/kvmd/api/cert.py" \
    "${TARGET}:${SITE_PKG}/kvmd/apps/kvmd/api/cert.py"

# ── Entry point script ────────────────────────────────────────────────────────
echo "==> Installing /usr/bin/kvmd-helper-certssl-commit ..."
TMPSCRIPT="$(mktemp /tmp/kvmd-certssl-entry-XXXXXX.py)"
cat > "$TMPSCRIPT" << 'PYEOF'
#!/usr/bin/python3
from kvmd.helpers.certssl import main
if __name__ == '__main__':
    main()
PYEOF
scp "$TMPSCRIPT" "${TARGET}:/usr/bin/kvmd-helper-certssl-commit"
rm -f "$TMPSCRIPT"
"${SSH[@]}" "chmod 755 /usr/bin/kvmd-helper-certssl-commit"

# ── Sudo rule ─────────────────────────────────────────────────────────────────
echo "==> Adding sudo rule to /etc/sudoers.d/99_kvmd (idempotent) ..."
SUDO_RULE="kvmd ALL=(ALL) NOPASSWD: /usr/bin/kvmd-helper-certssl-commit"
"${SSH[@]}" "grep -qxF '${SUDO_RULE}' /etc/sudoers.d/99_kvmd \
    || echo '${SUDO_RULE}' >> /etc/sudoers.d/99_kvmd"

# ── Bytecode cache ────────────────────────────────────────────────────────────
echo "==> Clearing Python bytecode caches ..."
"${SSH[@]}" "rm -rf \
    ${SITE_PKG}/kvmd/helpers/certssl/__pycache__ \
    ${SITE_PKG}/kvmd/apps/kvmd/api/__pycache__"

# ── Restart kvmd ──────────────────────────────────────────────────────────────
echo "==> Restarting kvmd ..."
"${SSH[@]}" "systemctl restart kvmd"

echo ""
echo "Done. Cert API deployed to ${HOST_ONLY}."
