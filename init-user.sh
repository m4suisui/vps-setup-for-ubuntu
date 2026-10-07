#!/usr/bin/env bash
# ============================================================
#  User Initialization Script
#  Creates a sudo user with SSH public key authentication
#
#  Usage:
#    sudo bash init-user.sh USERNAME "ssh-ed25519 AAAA..."
#
#  Idempotent: safe to re-run (updates key if user exists)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/ssh-keys.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then warn "Must be run as root"; exit 1; fi
if [[ ! -f /etc/os-release ]] || ! grep -qi 'ID=ubuntu' /etc/os-release; then warn "Ubuntu only"; exit 1; fi

USERNAME="${1:-}"
PUBKEY="${2:-}"

if [[ -z "${USERNAME}" ]] || [[ -z "${PUBKEY}" ]]; then
  warn "Usage: sudo bash init-user.sh USERNAME \"ssh-ed25519 AAAA...\""
  exit 1
fi

# Validate username (lowercase alphanumeric + hyphen/underscore, 1-32 chars)
if [[ ! "${USERNAME}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
  warn "Invalid username: ${USERNAME}"
  warn "Must be lowercase, start with a letter or _, max 32 chars"
  exit 1
fi

# Validate before creating users or touching authorized_keys.
if ! PUBKEY_FINGERPRINT=$(ssh_key_fingerprint "${PUBKEY}"); then
  warn "Invalid SSH public key (OpenSSH could not parse it; ssh-keygen is required)"
  exit 1
fi

# ─── 1. Create User ──────────────────────────────────────
if id "${USERNAME}" &>/dev/null; then
  info "User ${USERNAME} already exists"
else
  # --disabled-password: no password login (SSH key only)
  adduser --disabled-password --gecos "" "${USERNAME}"
  log "User ${USERNAME} created"
fi

# ─── 2. Add to sudo Group ────────────────────────────────
if groups "${USERNAME}" | grep -q "\bsudo\b"; then
  info "User ${USERNAME} already in sudo group"
else
  usermod -aG sudo "${USERNAME}"
  log "User ${USERNAME} added to sudo group"
fi

# ─── 3. Deploy SSH Public Key ────────────────────────────
USER_HOME=$(getent passwd "${USERNAME}" | cut -d: -f6)
SSH_DIR="${USER_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
chown "${USERNAME}:${USERNAME}" "${SSH_DIR}"

# Add key if not already present (idempotent)
if ssh_keys_contains_fingerprint "${AUTH_KEYS}" "${PUBKEY_FINGERPRINT}"; then
  info "SSH key already present for ${USERNAME}"
else
  # Keep the new key on its own line even if the existing file lacks a newline.
  if [[ -s "${AUTH_KEYS}" ]] && [[ $(tail -c 1 "${AUTH_KEYS}" | wc -l) -eq 0 ]]; then
    printf '\n' >> "${AUTH_KEYS}"
  fi
  printf '%s\n' "${PUBKEY}" >> "${AUTH_KEYS}"
  log "SSH key deployed for ${USERNAME}"
fi

chmod 600 "${AUTH_KEYS}"
chown "${USERNAME}:${USERNAME}" "${AUTH_KEYS}"

# ─── Done ─────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "${GREEN} User ${USERNAME} Ready${NC}"
echo "=============================================="
echo ""
echo "  User     : ${USERNAME}"
echo "  Groups   : $(groups "${USERNAME}" | cut -d: -f2)"
echo "  SSH key  : ${AUTH_KEYS}"
echo ""
echo "  Test login from your local machine:"
echo "    ssh ${USERNAME}@$(hostname -I | awk '{print $1}' || echo 'YOUR_SERVER_IP')"
echo ""
echo "  Then run hardening:"
echo "    sudo bash setup.sh"
echo "=============================================="
