#!/usr/bin/env bash
# ============================================================
#  VPS Base Hardening Script  v3
#  Target: Ubuntu 22.04 / 24.04
#  Prerequisite: Run as root or with sudo / SSH connected
#  Purpose: OS-level security hardening (works without nginx)
#
#  Idempotent: safe to re-run any number of times
# ============================================================
set -euo pipefail

# ─── User Configuration ──────────────────────────────────
RUN_APT_UPGRADE=true              # false = skip package upgrade (for CI, etc.)
DISABLE_IPV6_RA=false             # true = disable IPv6 RA (static IPv6 only)
                                  # Keep false for cloud VPS (AWS, DO, Vultr, etc.)
                                  # as they rely on RA for IPv6 connectivity
# ────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then warn "Must be run as root"; exit 1; fi
if [[ ! -f /etc/os-release ]] || ! grep -qi 'ID=ubuntu' /etc/os-release; then warn "Ubuntu only"; exit 1; fi

export DEBIAN_FRONTEND=noninteractive

# ─── 0. SSH Lockout Prevention Check ─────────────────────
# Since we set PasswordAuthentication no + PermitRootLogin no,
# a sudo user with SSH keys must exist to avoid permanent lockout
log "SSH lockout prevention check"

# Check for users in the sudo group
SUDO_USERS=$(getent group sudo 2>/dev/null | cut -d: -f4 || true)
if [[ -z "${SUDO_USERS}" ]]; then
  warn "No users found in sudo group"
  warn "Setting PermitRootLogin no will lock you out"
  warn "Create a sudo user first:"
  warn "  adduser yourname && usermod -aG sudo yourname"
  exit 1
fi

# Check that at least one sudo user has authorized_keys
HAS_SSH_KEY=false
IFS=',' read -ra SUDO_USER_ARRAY <<< "${SUDO_USERS}"
for u in "${SUDO_USER_ARRAY[@]}"; do
  USER_HOME=$(getent passwd "${u}" 2>/dev/null | cut -d: -f6 || true)
  if [[ -n "${USER_HOME}" ]] && [[ -s "${USER_HOME}/.ssh/authorized_keys" ]]; then
    HAS_SSH_KEY=true
    log "SSH key verified: ${u} (OK)"
    break
  fi
done

if [[ "${HAS_SSH_KEY}" != "true" ]]; then
  warn "No SSH public keys found for sudo users"
  warn "Setting PasswordAuthentication no will lock you out"
  warn "Set up public key authentication first:"
  warn "  ssh-copy-id yourname@this-server"
  exit 1
fi

# ─── 1. Package Update & Essential Tools ─────────────────
log "Package update & essential tools"
apt-get update -qq

if [[ "${RUN_APT_UPGRADE}" == "true" ]]; then
  apt-get upgrade -y -qq
  log "Package upgrade complete"
else
  info "Package upgrade skipped (RUN_APT_UPGRADE=false)"
fi

apt-get install -y -qq \
  ufw \
  fail2ban \
  unattended-upgrades \
  apt-listchanges \
  auditd \
  audispd-plugins \
  logrotate \
  curl \
  wget \
  git \
  jq

# ─── 2. Automatic Security Updates ───────────────────────
log "Automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUTOEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOEOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'UUEOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UUEOF

# ─── 3. SSH Hardening ────────────────────────────────────
log "SSH hardening"
SSHD_HARDENING="/etc/ssh/sshd_config.d/99-hardening.conf"
cat > "${SSHD_HARDENING}" <<'SSHEOF'
# Managed by vps-hardening.sh
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/issue.net
SSHEOF

# Login banner (hide OS info, show unauthorized access warning)
echo "Authorized access only. All activity is monitored." > /etc/issue.net

# Test config (failure does not affect running sshd)
if sshd -t 2>/dev/null; then
  systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  log "SSH config reloaded"
else
  warn "SSH config error. Check ${SSHD_HARDENING}"
fi

# ─── 4. MOTD Information Leak Prevention ─────────────────
# Default MOTD exposes OS version info
log "MOTD information leak prevention"
chmod -x /etc/update-motd.d/* 2>/dev/null || true

# ─── 5. UFW Firewall ─────────────────────────────────────
log "UFW firewall"

# Detect SSH port
SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | awk '{print $2}')
SSH_PORT="${SSH_PORT:-22}"
log "SSH port detected: ${SSH_PORT}"

# Default policies
ufw default deny incoming 2>/dev/null || true
ufw default allow outgoing 2>/dev/null || true

# Always allow SSH (lockout prevention)
ufw allow "${SSH_PORT}/tcp" comment "SSH" 2>/dev/null || true

# Enable UFW (skip if already active)
if ! ufw status | grep -q "Status: active"; then
  echo "y" | ufw enable
  log "UFW enabled"
else
  info "UFW already active"
fi

# ─── 6. Kernel Parameters (sysctl) ───────────────────────
log "Kernel parameter hardening"

# Generate IPv6 RA config conditionally
IPV6_RA_CONF=""
if [[ "${DISABLE_IPV6_RA}" == "true" ]]; then
  IPV6_RA_CONF="
# ── Disable IPv6 Router Advertisements (static IPv6 only) ──
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0"
  info "IPv6 RA disabled (DISABLE_IPV6_RA=true)"
else
  IPV6_RA_CONF="
# ── IPv6 Router Advertisements ──
# Kept enabled for cloud VPS compatibility (RA required for IPv6)
# Set DISABLE_IPV6_RA=true for static IPv6 environments"
  info "IPv6 RA enabled (cloud VPS compatible)"
fi

cat > /etc/sysctl.d/99-hardening.conf <<SYSEOF
# Managed by vps-hardening.sh

# ── IP Spoofing Protection ──
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── Reject ICMP Redirects ──
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ── Disable Source Routing ──
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ── SYN Flood Protection ──
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# ── Disable ICMP Broadcast Response (Smurf attack protection) ──
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
${IPV6_RA_CONF}

# ── TIME_WAIT Socket Reuse ──
net.ipv4.tcp_tw_reuse = 1

# ── File Descriptor Limit ──
fs.file-max = 65535

# ── Kernel Information Leak Prevention ──
# Restrict dmesg to root (blocks local privilege escalation info gathering)
kernel.dmesg_restrict = 1
# Hide kernel pointer addresses (prevents KASLR bypass)
kernel.kptr_restrict = 2

# ── Disable Core Dumps (prevent sensitive memory data leaks) ──
fs.suid_dumpable = 0
SYSEOF

sysctl --system > /dev/null 2>&1
log "sysctl applied"

# Core dump restriction (also via limits.conf)
echo "* hard core 0" > /etc/security/limits.d/99-no-coredump.conf

# ─── 7. Disable USB Storage ──────────────────────────────
# USB devices are unnecessary attack surface on VPS/cloud
log "USB storage disabled"
echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf

# ─── 8. Fail2ban Base Configuration ──────────────────────
log "Fail2ban base configuration"

# Back up existing jail.local if present (conflicts with jail.d/)
if [[ -f /etc/fail2ban/jail.local ]]; then
  warn "Existing /etc/fail2ban/jail.local detected. Backing up to avoid jail.d/ conflict"
  mv /etc/fail2ban/jail.local "/etc/fail2ban/jail.local.bak.$(date +%s)"
fi

# Default settings
mkdir -p /etc/fail2ban/jail.d

cat > /etc/fail2ban/jail.d/00-defaults.conf <<'F2BDEF'
# Managed by vps-hardening.sh
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = ufw
F2BDEF

# SSH jail
cat > /etc/fail2ban/jail.d/sshd.conf <<F2BSSH
# Managed by vps-hardening.sh
[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
maxretry = 3
bantime  = 86400
F2BSSH

systemctl enable --now fail2ban
systemctl restart fail2ban

# ─── 9. Shared Memory Protection ─────────────────────────
log "Shared memory protection (/dev/shm)"
SHM_FSTAB_LINE="tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
if grep -q "^tmpfs.*/dev/shm.*noexec.*nosuid.*nodev" /etc/fstab 2>/dev/null; then
  info "/dev/shm already correctly configured in fstab"
elif grep -q "/dev/shm" /etc/fstab 2>/dev/null; then
  # Existing entry with insufficient options — replace
  sed -i '\|/dev/shm|c\'"${SHM_FSTAB_LINE}" /etc/fstab
  info "/dev/shm fstab entry updated (noexec,nosuid,nodev added)"
else
  echo "${SHM_FSTAB_LINE}" >> /etc/fstab
  info "/dev/shm fstab entry added"
fi
# Apply immediately via remount
mount -o remount /dev/shm 2>/dev/null \
  && log "/dev/shm remounted (noexec,nosuid,nodev)" \
  || info "/dev/shm remount skipped (effective on next boot)"

# ─── 10. auditd (Log Monitoring & Auditing) ──────────────
log "auditd audit rules"
systemctl enable --now auditd

# Minimal audit rules (overwrite = idempotent)
# Excessive rules cause log bloat and performance degradation
# Extend via additional files in /etc/audit/rules.d/ as needed
cat > /etc/audit/rules.d/99-hardening.rules <<'AUEOF'
# Managed by vps-hardening.sh

# ── Buffer Size ──
-b 8192

# ── Authentication & Account File Change Monitoring ──
-w /etc/shadow -p wa -k shadow_change
-w /etc/passwd -p wa -k passwd_change
-w /etc/group -p wa -k group_change
-w /etc/gshadow -p wa -k gshadow_change
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# ── SSH Config Change Monitoring ──
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# ── Firewall Config Change Monitoring ──
-w /etc/ufw/ -p wa -k ufw_change

# ── Cron Change Monitoring (persistence technique detection) ──
-w /etc/crontab -p wa -k cron_change
-w /etc/cron.d/ -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change

# ── su / sudo Execution Tracking ──
-w /usr/bin/su -p x -k priv_escalation
-w /usr/bin/sudo -p x -k priv_escalation

# ── insmod / modprobe (Kernel Module Load Monitoring) ──
-w /sbin/insmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module

# ── Make Rules Immutable (requires reboot to change) ──
# Comment out this line for debugging
-e 2
AUEOF

# In immutable mode, rules cannot be updated — notify user that reboot is required
if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
  info "auditd rules are in immutable mode. Reboot required to apply changes"
else
  augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true
  log "auditd rules applied"
fi

# ─── 11. Time Synchronization (systemd-timesyncd) ────────
log "Time sync check"

systemctl enable --now systemd-timesyncd 2>/dev/null || true
timedatectl set-ntp true 2>/dev/null || true

TIMESYNC_STATUS=$(timedatectl status 2>/dev/null || echo "timedatectl failed")
NTP_SYNCED=$(echo "${TIMESYNC_STATUS}" | grep -i "synchronized" || true)

if echo "${NTP_SYNCED}" | grep -qi "yes"; then
  log "NTP synchronized"
else
  warn "NTP not synchronized. Check: timedatectl status"
fi

logger -t vps-hardening "Time sync status: ${NTP_SYNCED:-unknown}"

# ─── Done ─────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "${GREEN} VPS Base Hardening v3 Complete${NC}"
echo "=============================================="
echo ""
echo "  SSH        : Port ${SSH_PORT}"
echo "  SSH config : ${SSHD_HARDENING}"
echo "  UFW        : active (SSH=${SSH_PORT} allowed)"
echo "  Fail2ban   : SSH jail enabled (ban=24h)"
echo "  Auto-update: Security patches auto-applied"
echo "  Kernel     : sysctl hardening applied"
echo "  auditd     : Audit rules applied"
echo "  NTP        : ${NTP_SYNCED:-check manually}"
echo ""
echo "  Audit log queries:"
echo "    ausearch -k shadow_change    # Password changes"
echo "    ausearch -k sshd_config      # SSH config changes"
echo "    ausearch -k priv_escalation  # sudo/su execution"
echo "    aureport --summary           # Summary"
echo ""
echo "  To add nginx:"
echo "    1. ufw allow 80/tcp && ufw allow 443/tcp"
echo "    2. sudo bash nginx-hardening.sh"
echo ""
echo "  This script is idempotent. Safe to re-run after config changes."
echo "=============================================="
