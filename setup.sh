#!/usr/bin/env bash
# ============================================================
#  VPS Setup Orchestrator
#  One command: user creation -> hardening -> verification
#
#  Usage:
#    sudo bash setup.sh --user deploy --pubkey "ssh-ed25519 AAAA..."
#    sudo bash setup.sh --user deploy --pubkey "ssh-ed25519 AAAA..." --nginx
#
#  If user already exists with the key, the user step is a no-op.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

if [[ $EUID -ne 0 ]]; then echo -e "${RED}[!]${NC} Must be run as root"; exit 1; fi
if [[ ! -f /etc/os-release ]] || ! grep -qi 'ID=ubuntu' /etc/os-release; then echo -e "${RED}[!]${NC} Ubuntu only"; exit 1; fi

# Ubuntu バージョン検証
UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | tr -d '"' | cut -d= -f2)
case "${UBUNTU_VERSION}" in
  22.04|24.04|26.04) ;;
  20.04)
    echo -e "${RED}[!]${NC} Ubuntu 20.04: standard support ended (2025-04). ESM requires Ubuntu Pro"
    echo -n "    Continue at your own risk? [y/N] "
    read -r REPLY
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then exit 1; fi
    ;;
  *)
    echo -e "${RED}[!]${NC} Unsupported Ubuntu version: ${UBUNTU_VERSION}"
    echo -e "${RED}[!]${NC} This script is tested on Ubuntu 22.04 / 24.04 / 26.04 LTS"
    echo -n "    Continue anyway? [y/N] "
    read -r REPLY
    if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then exit 1; fi
    ;;
esac

# ─── Parse Arguments ──────────────────────────────────────
USERNAME=""
PUBKEY=""
WITH_NGINX=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)    USERNAME="$2"; shift 2 ;;
    --pubkey)  PUBKEY="$2"; shift 2 ;;
    --nginx)   WITH_NGINX=true; shift ;;
    *)         echo -e "${RED}[!]${NC} Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "${USERNAME}" ]] || [[ -z "${PUBKEY}" ]]; then
  echo -e "${RED}[!]${NC} Required: --user USERNAME --pubkey \"ssh-ed25519 AAAA...\""
  echo ""
  echo "  Usage:"
  echo "    sudo bash setup.sh --user deploy --pubkey \"ssh-ed25519 AAAA...\""
  echo "    sudo bash setup.sh --user deploy --pubkey \"ssh-ed25519 AAAA...\" --nginx"
  exit 1
fi

TOTAL_STEPS=3
if [[ "${WITH_NGINX}" == "true" ]]; then
  TOTAL_STEPS=4
fi

echo ""
echo -e "${CYAN}══════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VPS Setup: $([ "${WITH_NGINX}" == "true" ] && echo "Full (User + OS + Nginx)" || echo "User + OS Base")${NC}"
echo -e "${CYAN}══════════════════════════════════════════════${NC}"

# ─── 1. User Init ─────────────────────────────────────────
echo ""
echo -e "${CYAN}[1/${TOTAL_STEPS}] init-user.sh${NC}"
echo ""
bash "${SCRIPT_DIR}/init-user.sh" "${USERNAME}" "${PUBKEY}"

# ─── 2. VPS Base Hardening ────────────────────────────────
echo ""
echo -e "${CYAN}[2/${TOTAL_STEPS}] vps-hardening.sh${NC}"
echo ""
bash "${SCRIPT_DIR}/vps-hardening.sh"

# ─── 3. Nginx Hardening (optional) ───────────────────────
if [[ "${WITH_NGINX}" == "true" ]]; then
  echo ""
  echo -e "${CYAN}[3/${TOTAL_STEPS}] nginx-hardening.sh${NC}"
  echo ""

  # Open ports 80/443 in UFW (idempotent)
  ufw allow 80/tcp comment "HTTP" 2>/dev/null || true
  ufw allow 443/tcp comment "HTTPS" 2>/dev/null || true

  bash "${SCRIPT_DIR}/nginx-hardening.sh"
fi

# ─── 4. Verify ────────────────────────────────────────────
echo ""
echo -e "${CYAN}[${TOTAL_STEPS}/${TOTAL_STEPS}] verify.sh${NC}"
echo ""

VERIFY_ARGS=()
if [[ "${WITH_NGINX}" == "true" ]]; then
  VERIFY_ARGS=("--nginx")
fi

if bash "${SCRIPT_DIR}/verify.sh" "${VERIFY_ARGS[@]+"${VERIFY_ARGS[@]}"}"; then
  echo ""
  echo -e "${GREEN}══════════════════════════════════════════════${NC}"
  echo -e "${GREEN}  Setup complete: All tests PASSED${NC}"
  echo -e "${GREEN}══════════════════════════════════════════════${NC}"
  echo ""
  echo "  Next steps:"
  echo "    1. Test login: ssh ${USERNAME}@$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'YOUR_SERVER_IP')"
  echo "    2. root login will be disabled after this session ends"
  echo ""
else
  echo ""
  echo -e "${RED}══════════════════════════════════════════════${NC}"
  echo -e "${RED}  Setup complete: FAILURES detected (see above)${NC}"
  echo -e "${RED}══════════════════════════════════════════════${NC}"
  exit 1
fi
