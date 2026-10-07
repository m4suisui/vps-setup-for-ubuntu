#!/usr/bin/env bash
# ============================================================
#  VPS Hardening Verification Script  v3
#  Target: Ubuntu 22.04 / 24.04 / 26.04
#  Verifies that vps-hardening.sh / nginx-hardening.sh applied correctly,
#  AND that nothing unexpected exists (open ports, accounts, binaries, ...)
#
#  Usage: sudo bash verify.sh [options]
#    --nginx                 also run nginx-hardening.sh tests
#    --allow-port PORT/PROTO port that may be exposed besides SSH
#                            (repeatable, e.g. --allow-port 51820/udp)
#    --sudo-users a,b        accounts expected to have sudo rights
#    --quick                 skip slow scans (SUID files, package integrity)
#
#  Environment: VERIFY_ALLOWED_PORTS="51820/udp 8080/tcp" (same as --allow-port)
#
#  Exit code: 0 = no FAIL (WARN allowed) / 1 = FAIL detected
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/ssh-keys.sh"
# Do NOT use set -e (test failures should not abort the script)

# ─── Output ───────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

pass() { ((PASS_COUNT++)); echo -e "  ${GREEN}PASS${NC}  $*"; }
fail() { ((FAIL_COUNT++)); echo -e "  ${RED}FAIL${NC}  $*"; }
skip() { ((SKIP_COUNT++)); echo -e "  ${YELLOW}SKIP${NC}  $*"; }
warn_() { ((WARN_COUNT++)); echo -e "  ${YELLOW}WARN${NC}  $*"; }
section() { echo -e "\n${CYAN}── $* ──${NC}"; }

if [[ $EUID -ne 0 ]]; then echo "Must be run as root"; exit 1; fi
if [[ ! -f /etc/os-release ]] || ! grep -qi 'ID=ubuntu' /etc/os-release; then echo "Ubuntu only"; exit 1; fi

CHECK_NGINX=false
QUICK=false
ALLOWED_PORTS=()
EXPECTED_SUDO_USERS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nginx) CHECK_NGINX=true; shift ;;
    --quick) QUICK=true; shift ;;
    --allow-port)
      [[ $# -ge 2 ]] || { echo "--allow-port requires PORT/PROTO (e.g. 51820/udp)"; exit 1; }
      ALLOWED_PORTS+=("$2"); shift 2 ;;
    --sudo-users)
      [[ $# -ge 2 ]] || { echo "--sudo-users requires a comma-separated list"; exit 1; }
      EXPECTED_SUDO_USERS="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -n "${VERIFY_ALLOWED_PORTS:-}" ]]; then
  read -ra _env_ports <<< "${VERIFY_ALLOWED_PORTS//,/ }"
  ALLOWED_PORTS+=("${_env_ports[@]}")
fi

for _p in "${ALLOWED_PORTS[@]+"${ALLOWED_PORTS[@]}"}"; do
  if [[ ! "${_p}" =~ ^[0-9]{1,5}/(tcp|udp)$ ]]; then
    echo "Invalid port '${_p}': use PORT/PROTO, e.g. 51820/udp"
    exit 1
  fi
done

UBUNTU_VERSION=$(grep '^VERSION_ID=' /etc/os-release | tr -d '"' | cut -d= -f2)

# sshd may listen on several ports; all of them are expected
mapfile -t SSH_PORTS < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
[[ ${#SSH_PORTS[@]} -gt 0 ]] || SSH_PORTS=(22)
SSH_PORT="${SSH_PORTS[0]}"
for _p in "${SSH_PORTS[@]}"; do ALLOWED_PORTS+=("${_p}/tcp"); done

# nginx-hardening.sh opens 80/443
if [[ "${CHECK_NGINX}" == "true" ]] || [[ -f /etc/nginx/snippets/security-headers.conf ]]; then
  ALLOWED_PORTS+=("80/tcp" "443/tcp")
fi

# ─── Helpers ──────────────────────────────────────────────
# Get sshd effective config (resolves all Includes and overrides)
sshd_effective() {
  sshd -T 2>/dev/null | grep -i "^$1 " | awk '{print tolower($2)}'
}

# Get sysctl effective value
sysctl_val() {
  sysctl -n "$1" 2>/dev/null
}

# Is PORT/PROTO in the allowlist?
port_allowed() {
  local wanted="$1" a
  for a in "${ALLOWED_PORTS[@]}"; do
    [[ "${a}" == "${wanted}" ]] && return 0
  done
  return 1
}

# Is the file owned by a Debian package? (handles usrmerge /bin <-> /usr/bin)
dpkg_owned() {
  local f="$1"
  dpkg -S "${f}" &>/dev/null && return 0
  case "${f}" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) dpkg -S "${f#/usr}" &>/dev/null && return 0 ;;
    /bin/*|/sbin/*|/lib/*|/lib64/*) dpkg -S "/usr${f}" &>/dev/null && return 0 ;;
  esac
  return 1
}

# Comma-separated list contains item?
list_contains() {
  [[ ",$1," == *",$2,"* ]]
}

# First few items of a list, for compact messages
first_items() {
  local max="$1"; shift
  local out="${*:1:${max}}"
  [[ $# -gt ${max} ]] && out+=" ... (+$(( $# - max )) more)"
  echo "${out}"
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  VPS Base Hardening Tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

section "User & SSH Key"

# At least one sudo user with authorized_keys must exist
SUDO_USERS=$(getent group sudo 2>/dev/null | cut -d: -f4 || true)
if [[ -n "${SUDO_USERS}" ]]; then
  pass "sudo group has members (${SUDO_USERS})"
else
  fail "No users in sudo group (lockout risk)"
fi

# Check that at least one sudo user has authorized_keys
HAS_KEY=false
IFS=',' read -ra SU_ARR <<< "${SUDO_USERS}"
for u in "${SU_ARR[@]}"; do
  UHOME=$(getent passwd "${u}" 2>/dev/null | cut -d: -f6 || true)
  if [[ -n "${UHOME}" ]] && [[ -s "${UHOME}/.ssh/authorized_keys" ]]; then
    pass "SSH key exists for ${u}"
    # Check permissions
    SSH_DIR_PERMS=$(stat -c %a "${UHOME}/.ssh" 2>/dev/null)
    AK_PERMS=$(stat -c %a "${UHOME}/.ssh/authorized_keys" 2>/dev/null)
    [[ "${SSH_DIR_PERMS}" == "700" ]] \
      && pass "${u}: .ssh dir permissions 700" \
      || fail "${u}: .ssh dir permissions ${SSH_DIR_PERMS} (expected: 700)"
    [[ "${AK_PERMS}" == "600" ]] \
      && pass "${u}: authorized_keys permissions 600" \
      || fail "${u}: authorized_keys permissions ${AK_PERMS} (expected: 600)"
    if ssh_keys_has_valid_key "${UHOME}/.ssh/authorized_keys"; then
      pass "${u}: at least one parseable SSH public key"
      HAS_KEY=true
    else
      fail "${u}: no parseable SSH public key (ssh-keygen is required)"
    fi
  fi
done

if [[ "${HAS_KEY}" != "true" ]]; then
  fail "No sudo user has a parseable SSH public key (lockout risk)"
fi

section "SSH Hardening"

# Test effective values, not config file contents
[[ "$(sshd_effective permitrootlogin)" == "no" ]] \
  && pass "PermitRootLogin no" \
  || fail "PermitRootLogin is not no ($(sshd_effective permitrootlogin))"

[[ "$(sshd_effective passwordauthentication)" == "no" ]] \
  && pass "PasswordAuthentication no" \
  || fail "PasswordAuthentication is not no"

[[ "$(sshd_effective kbdinteractiveauthentication)" == "no" ]] \
  && pass "KbdInteractiveAuthentication no" \
  || fail "KbdInteractiveAuthentication is not no"

[[ "$(sshd_effective x11forwarding)" == "no" ]] \
  && pass "X11Forwarding no" \
  || fail "X11Forwarding is not no"

[[ "$(sshd_effective allowagentforwarding)" == "no" ]] \
  && pass "AllowAgentForwarding no" \
  || fail "AllowAgentForwarding is not no"

[[ "$(sshd_effective allowtcpforwarding)" == "no" ]] \
  && pass "AllowTcpForwarding no" \
  || fail "AllowTcpForwarding is not no"

MAX_AUTH=$(sshd_effective maxauthtries)
[[ "${MAX_AUTH}" -le 3 ]] 2>/dev/null \
  && pass "MaxAuthTries <= 3 (${MAX_AUTH})" \
  || fail "MaxAuthTries not <= 3 (${MAX_AUTH})"

MAX_SESS=$(sshd_effective maxsessions)
[[ "${MAX_SESS}" -le 3 ]] 2>/dev/null \
  && pass "MaxSessions <= 3 (${MAX_SESS})" \
  || fail "MaxSessions not <= 3 (${MAX_SESS})"

ALIVE_INT=$(sshd_effective clientaliveinterval)
[[ "${ALIVE_INT}" -gt 0 ]] 2>/dev/null \
  && pass "ClientAliveInterval > 0 (${ALIVE_INT})" \
  || fail "ClientAliveInterval not set"

ALIVE_MAX=$(sshd_effective clientalivecountmax)
[[ "${ALIVE_MAX}" -le 3 ]] 2>/dev/null \
  && pass "ClientAliveCountMax <= 3 (${ALIVE_MAX})" \
  || fail "ClientAliveCountMax not <= 3 (${ALIVE_MAX})"

[[ "$(sshd_effective pubkeyauthentication)" == "yes" ]] \
  && pass "PubkeyAuthentication yes" \
  || fail "PubkeyAuthentication is not yes (key login would fail)"

[[ "$(sshd_effective permitemptypasswords)" == "no" ]] \
  && pass "PermitEmptyPasswords no" \
  || fail "PermitEmptyPasswords is not no"

[[ "$(sshd_effective hostbasedauthentication)" == "no" ]] \
  && pass "HostbasedAuthentication no" \
  || fail "HostbasedAuthentication is not no"

[[ "$(sshd_effective permituserenvironment)" == "no" ]] \
  && pass "PermitUserEnvironment no" \
  || fail "PermitUserEnvironment is not no"

[[ "$(sshd_effective strictmodes)" == "yes" ]] \
  && pass "StrictModes yes (rejects keys with unsafe permissions)" \
  || fail "StrictModes is not yes"

# SSH Banner
BANNER=$(sshd_effective banner)
[[ "${BANNER}" == "/etc/issue.net" ]] \
  && pass "SSH Banner = /etc/issue.net" \
  || warn_ "SSH Banner is not /etc/issue.net (${BANNER})"

# SSH config syntax test
sshd -t 2>/dev/null \
  && pass "sshd -t syntax test" \
  || fail "sshd -t syntax test failed"

# ────────────────────────────────────────────────────────
section "UFW Firewall"

ufw status | grep -q "Status: active" \
  && pass "UFW active" \
  || fail "UFW is not active"

# Default policies
UFW_DEFAULT=$(ufw status verbose 2>/dev/null | grep "Default:")
echo "${UFW_DEFAULT}" | grep -q "deny (incoming)" \
  && pass "UFW default deny incoming" \
  || fail "UFW default incoming is not deny"

echo "${UFW_DEFAULT}" | grep -q "allow (outgoing)" \
  && pass "UFW default allow outgoing" \
  || fail "UFW default outgoing is not allow"

# SSH port allowed
ufw status | grep -q "^${SSH_PORT}/tcp.*ALLOW" \
  && pass "UFW SSH (${SSH_PORT}/tcp) allowed" \
  || fail "UFW SSH (${SSH_PORT}/tcp) not allowed"

# Nothing else opened to the whole Internet
# (rules limited to a source address or an interface such as wg0 are not public)
UFW_UNEXPECTED=0
while IFS= read -r line; do
  [[ "${line}" == *" ALLOW "* ]] || continue
  RULE_TO=$(echo "${line%% ALLOW *}" | sed 's/ (v6)//; s/[[:space:]]*$//')
  RULE_FROM=$(echo "${line#* ALLOW }" | sed 's/^IN //; s/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//')
  [[ "${RULE_FROM}" == Anywhere* ]] || continue
  [[ "${RULE_TO}" == *" on "* ]] && continue

  if [[ "${RULE_TO}" == "Anywhere" ]]; then
    fail "UFW allows ALL ports from Anywhere"
    ((UFW_UNEXPECTED++))
  elif [[ "${RULE_TO}" =~ ^[0-9]+/(tcp|udp)$ ]]; then
    if ! port_allowed "${RULE_TO}"; then
      fail "UFW allows ${RULE_TO} from Anywhere (not in allowlist; --allow-port ${RULE_TO} if intended)"
      ((UFW_UNEXPECTED++))
    fi
  elif [[ "${RULE_TO}" =~ ^[0-9]+$ ]]; then
    if ! port_allowed "${RULE_TO}/tcp" || ! port_allowed "${RULE_TO}/udp"; then
      fail "UFW allows ${RULE_TO} (tcp AND udp) from Anywhere (restrict to one protocol or allowlist both)"
      ((UFW_UNEXPECTED++))
    fi
  else
    warn_ "UFW rule '${RULE_TO}' cannot be evaluated automatically (port range or app profile)"
    ((UFW_UNEXPECTED++))
  fi
done < <(ufw status 2>/dev/null)

[[ ${UFW_UNEXPECTED} -eq 0 ]] \
  && pass "UFW: no public rules beyond allowlist ($(first_items 6 "${ALLOWED_PORTS[@]}"))"

# ────────────────────────────────────────────────────────
section "Kernel Parameters (sysctl)"

# Verify expected effective values
declare -A SYSCTL_TESTS=(
  # IP Spoofing Protection
  ["net.ipv4.conf.all.rp_filter"]="1"
  ["net.ipv4.conf.default.rp_filter"]="1"
  # ICMP Redirects
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.default.accept_redirects"]="0"
  ["net.ipv4.conf.all.send_redirects"]="0"
  ["net.ipv4.conf.default.send_redirects"]="0"
  ["net.ipv6.conf.all.accept_redirects"]="0"
  ["net.ipv6.conf.default.accept_redirects"]="0"
  # Source Routing
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.conf.default.accept_source_route"]="0"
  ["net.ipv6.conf.all.accept_source_route"]="0"
  ["net.ipv6.conf.default.accept_source_route"]="0"
  # SYN Flood Protection
  ["net.ipv4.tcp_syncookies"]="1"
  ["net.ipv4.tcp_synack_retries"]="2"
  # ICMP
  ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
  ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
  # TCP
  ["net.ipv4.tcp_tw_reuse"]="1"
  # Kernel Info Leak Prevention
  ["kernel.dmesg_restrict"]="1"
  ["kernel.kptr_restrict"]="2"
  # Core Dumps
  ["fs.suid_dumpable"]="0"
)

for key in "${!SYSCTL_TESTS[@]}"; do
  expected="${SYSCTL_TESTS[$key]}"
  actual=$(sysctl_val "${key}")
  if [[ "${actual}" == "${expected}" ]]; then
    pass "${key} = ${expected}"
  else
    fail "${key} = ${actual} (expected: ${expected})"
  fi
done

# tcp_max_syn_backlog: >= 2048 (some environments have higher defaults)
SYN_BACKLOG=$(sysctl_val "net.ipv4.tcp_max_syn_backlog")
[[ "${SYN_BACKLOG}" -ge 2048 ]] 2>/dev/null \
  && pass "net.ipv4.tcp_max_syn_backlog >= 2048 (${SYN_BACKLOG})" \
  || fail "net.ipv4.tcp_max_syn_backlog = ${SYN_BACKLOG} (expected: >= 2048)"

# ────────────────────────────────────────────────────────
section "Fail2ban"

systemctl is-active --quiet fail2ban \
  && pass "fail2ban running" \
  || fail "fail2ban is not running"

# SSH jail enabled
fail2ban-client status sshd &>/dev/null \
  && pass "fail2ban sshd jail enabled" \
  || fail "fail2ban sshd jail disabled"

F2B_BANTIME=$(fail2ban-client get sshd bantime 2>/dev/null)
[[ "${F2B_BANTIME}" -ge 86400 ]] 2>/dev/null \
  && pass "fail2ban sshd bantime >= 24h (${F2B_BANTIME}s)" \
  || fail "fail2ban sshd bantime < 24h (${F2B_BANTIME:-unknown})"

F2B_MAXRETRY=$(fail2ban-client get sshd maxretry 2>/dev/null)
[[ "${F2B_MAXRETRY}" -le 3 ]] 2>/dev/null \
  && pass "fail2ban sshd maxretry <= 3 (${F2B_MAXRETRY})" \
  || fail "fail2ban sshd maxretry not <= 3 (${F2B_MAXRETRY:-unknown})"

fail2ban-client get sshd actions 2>/dev/null | grep -q "ufw" \
  && pass "fail2ban sshd bans via UFW" \
  || warn_ "fail2ban sshd does not use the ufw action"

# The jail must actually be reading SSH logs, or it never bans anything
F2B_JOURNAL=$(fail2ban-client get sshd journalmatch 2>/dev/null || true)
F2B_LOGFILES=$(fail2ban-client get sshd logpath 2>/dev/null | grep -oE '/[^ ]+' || true)
if [[ "${F2B_JOURNAL}" == *"_SYSTEMD_UNIT"* || "${F2B_JOURNAL}" == *"_COMM"* ]]; then
  pass "fail2ban sshd reads the systemd journal"
elif [[ -n "${F2B_LOGFILES}" ]] && [[ -f "$(echo "${F2B_LOGFILES}" | head -1)" ]]; then
  pass "fail2ban sshd reads $(echo "${F2B_LOGFILES}" | head -1)"
else
  fail "fail2ban sshd is not reading any log source (it will never ban)"
fi

# jail.local vs jail.d/ conflict check
if [[ -f /etc/fail2ban/jail.local ]]; then
  warn_ "/etc/fail2ban/jail.local exists (potential jail.d/ conflict)"
else
  pass "No jail.local (managed via jail.d/)"
fi

# ────────────────────────────────────────────────────────
section "Automatic Security Updates"

[[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] \
  && pass "20auto-upgrades exists" \
  || fail "20auto-upgrades not found"

grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null \
  && pass "Auto-updates enabled" \
  || fail "Auto-updates disabled"

grep -q -- '-security' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null \
  && pass "Unattended-upgrades includes the security pocket" \
  || fail "Unattended-upgrades does not include the security pocket"

systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null \
  && pass "apt-daily-upgrade.timer enabled" \
  || fail "apt-daily-upgrade.timer disabled (auto-updates never run)"

grep -q 'Automatic-Reboot "true"' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null \
  && pass "Automatic reboot after kernel updates enabled" \
  || warn_ "Automatic reboot disabled (updated kernels run only after a manual reboot)"

# Package lists must be fresh, or "no pending updates" means nothing
STAMP=/var/lib/apt/periodic/update-success-stamp
if [[ -f "${STAMP}" ]]; then
  STAMP_AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y "${STAMP}") ) / 86400 ))
  [[ ${STAMP_AGE_DAYS} -le 3 ]] \
    && pass "Package lists updated ${STAMP_AGE_DAYS} day(s) ago" \
    || fail "Package lists last updated ${STAMP_AGE_DAYS} days ago (auto-updates stalled?)"
else
  warn_ "No apt update-success-stamp yet (first run or auto-updates never ran)"
fi

SEC_PENDING=$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null | grep -c '^Inst .*-security' || true)
[[ "${SEC_PENDING:-0}" -eq 0 ]] \
  && pass "No pending security updates" \
  || warn_ "${SEC_PENDING} security update(s) pending (apply: apt-get upgrade)"

if [[ -f /var/run/reboot-required ]]; then
  REBOOT_PKGS=$(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)
  warn_ "Reboot required to apply updates (${REBOOT_PKGS:-unknown packages})"
else
  pass "No reboot pending"
fi

RUNNING_KERNEL=$(uname -r)
NEWEST_KERNEL=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sed 's/^vmlinuz-//' | sort -V | tail -1)
if [[ -z "${NEWEST_KERNEL}" ]] || [[ "${RUNNING_KERNEL}" == "${NEWEST_KERNEL}" ]]; then
  pass "Running the newest installed kernel (${RUNNING_KERNEL})"
else
  warn_ "Running kernel ${RUNNING_KERNEL}, newer ${NEWEST_KERNEL} installed (reboot to apply)"
fi

# OS release still receiving standard security support
case "${UBUNTU_VERSION}" in
  22.04) END_OF_SUPPORT="2027-04-30" ;;
  24.04) END_OF_SUPPORT="2029-04-30" ;;
  26.04) END_OF_SUPPORT="2031-04-30" ;;
  *)     END_OF_SUPPORT="" ;;
esac
if [[ -n "${END_OF_SUPPORT}" ]]; then
  DAYS_LEFT=$(( ( $(date -d "${END_OF_SUPPORT}" +%s) - $(date +%s) ) / 86400 ))
  if [[ ${DAYS_LEFT} -lt 0 ]]; then
    fail "Ubuntu ${UBUNTU_VERSION} standard support ended ${END_OF_SUPPORT} (upgrade or enable Ubuntu Pro)"
  elif [[ ${DAYS_LEFT} -lt 180 ]]; then
    warn_ "Ubuntu ${UBUNTU_VERSION} standard support ends ${END_OF_SUPPORT} (${DAYS_LEFT} days left)"
  else
    pass "Ubuntu ${UBUNTU_VERSION} supported until ${END_OF_SUPPORT}"
  fi
else
  warn_ "Ubuntu ${UBUNTU_VERSION}: support end date unknown to this script"
fi

# ────────────────────────────────────────────────────────
section "auditd"

systemctl is-active --quiet auditd \
  && pass "auditd running" \
  || fail "auditd is not running"

[[ -f /etc/audit/rules.d/99-hardening.rules ]] \
  && pass "Audit rules file exists" \
  || fail "99-hardening.rules not found"

# Check that every audit rule key is actually loaded (not just written to disk)
AUDIT_LOADED=$(auditctl -l 2>/dev/null)
for key in shadow_change passwd_change group_change gshadow_change sudoers_change \
           sshd_config ufw_change cron_change priv_escalation kernel_module; do
  echo "${AUDIT_LOADED}" | grep -q -- "-k ${key}\b\|key=${key}\b" \
    && pass "auditd rule loaded: ${key}" \
    || fail "auditd rule not loaded: ${key}"
done

auditctl -s 2>/dev/null | grep -q "enabled 2" \
  && pass "auditd rules immutable (cannot be disabled without reboot)" \
  || warn_ "auditd rules not immutable yet (takes effect after reboot)"

# ────────────────────────────────────────────────────────
section "Time Synchronization"

{ systemctl is-active --quiet systemd-timesyncd || systemctl is-active --quiet chrony; } 2>/dev/null \
  && pass "Time sync service running" \
  || fail "No time sync service running (systemd-timesyncd / chrony)"

timedatectl status 2>/dev/null | grep -qi "synchronized: yes" \
  && pass "NTP synchronized" \
  || warn_ "NTP not synchronized (check: timedatectl status)"

# ────────────────────────────────────────────────────────
section "Additional Hardening"

grep -q "^install usb-storage /bin/true" /etc/modprobe.d/disable-usb-storage.conf 2>/dev/null \
  && pass "USB storage disabled" \
  || warn_ "USB storage not disabled"

grep -q "^\* hard core 0" /etc/security/limits.d/99-no-coredump.conf 2>/dev/null \
  && pass "Core dump restriction (limits.d)" \
  || warn_ "Core dump restriction not configured"

[[ -f /etc/sysctl.d/99-hardening.conf ]] \
  && pass "sysctl hardening persisted (/etc/sysctl.d/99-hardening.conf)" \
  || fail "sysctl hardening file missing (settings lost on reboot)"

# /dev/shm: verify actual mount options, not just fstab
SHM_OPTS=$(findmnt -n -o OPTIONS /dev/shm 2>/dev/null || true)
SHM_MISSING=()
for opt in noexec nosuid nodev; do
  [[ ",${SHM_OPTS}," == *",${opt},"* ]] || SHM_MISSING+=("${opt}")
done
if [[ ${#SHM_MISSING[@]} -eq 0 ]]; then
  pass "/dev/shm mounted noexec,nosuid,nodev"
elif grep -q "/dev/shm.*noexec" /etc/fstab 2>/dev/null; then
  warn_ "/dev/shm: ${SHM_MISSING[*]} in fstab but not in current mount (remount needed)"
else
  warn_ "/dev/shm missing mount options: ${SHM_MISSING[*]}"
fi

# MOTD executable check
MOTD_EXECUTABLE=$(find /etc/update-motd.d/ -executable -type f 2>/dev/null | wc -l)
[[ "${MOTD_EXECUTABLE}" -eq 0 ]] \
  && pass "MOTD info leak prevention (no executable scripts)" \
  || warn_ "MOTD: ${MOTD_EXECUTABLE} executable scripts remain"

# SSH banner file
[[ -f /etc/issue.net ]] && grep -qi "authorized" /etc/issue.net 2>/dev/null \
  && pass "SSH banner file configured" \
  || warn_ "SSH banner file not configured"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Nothing Unexpected: checks for state the hardening did NOT create
#  (an applied setting can PASS while something extra is exposed)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

section "Exposed Services"

# Everything listening on a non-loopback address must be in the allowlist.
# UFW normally blocks the rest, but Docker-published ports bypass UFW.
declare -A SEEN_LISTEN=()
LISTEN_UNEXPECTED=0
while read -r netid _state _rq _sq local _peer rest; do
  port="${local##*:}"
  addr="${local%:*}"
  addr="${addr%%\%*}"; addr="${addr#[}"; addr="${addr%]}"
  case "${addr}" in
    127.*|::1|::ffff:127.*) continue ;;   # loopback
    fe80:*) continue ;;                     # link-local, not routable
  esac
  # DHCP / DHCPv6 clients
  [[ "${netid}" == "udp" ]] && [[ "${port}" == "68" || "${port}" == "546" ]] && continue

  key="${port}/${netid}"
  [[ -n "${SEEN_LISTEN[${key}]:-}" ]] && continue
  SEEN_LISTEN[${key}]=1

  if ! port_allowed "${key}"; then
    proc=$(echo "${rest}" | sed -n 's/.*(("\([^"]*\)".*/\1/p')
    fail "Listening on ${addr}:${key} (${proc:-unknown}) — not in allowlist (--allow-port ${key} if intended)"
    ((LISTEN_UNEXPECTED++))
  fi
done < <(ss -H -tuln -p 2>/dev/null | awk '{ if ($1=="tcp" || $1=="udp") print }')

[[ ${LISTEN_UNEXPECTED} -eq 0 ]] \
  && pass "Only allowlisted ports listen on public addresses"

if command -v docker &>/dev/null && docker info &>/dev/null; then
  DOCKER_UNEXPECTED=0
  declare -A SEEN_DOCKER=()
  while read -r cname cports; do
    IFS=',' read -ra entries <<< "${cports}"
    for e in "${entries[@]}"; do
      e="${e# }"
      [[ "${e}" == *"->"* ]] || continue
      [[ "${e}" == 127.* || "${e}" == "[::1]"* ]] && continue
      if [[ "${e}" =~ :([0-9]+)-\>[0-9]+/(tcp|udp)$ ]]; then
        dkey="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
        [[ -n "${SEEN_DOCKER[${cname}/${dkey}]:-}" ]] && continue   # IPv4 + IPv6 entries
        SEEN_DOCKER[${cname}/${dkey}]=1
        if ! port_allowed "${dkey}"; then
          fail "Docker '${cname}' publishes ${dkey} publicly (bypasses UFW; bind to 127.0.0.1 or allowlist)"
          ((DOCKER_UNEXPECTED++))
        fi
      else
        warn_ "Docker '${cname}' publishes a port range publicly: ${e}"
        ((DOCKER_UNEXPECTED++))
      fi
    done
  done < <(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null)
  [[ ${DOCKER_UNEXPECTED} -eq 0 ]] \
    && pass "Docker: no unexpected public port bindings"
fi

# ────────────────────────────────────────────────────────
section "Accounts & Privileges"

UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | tr '\n' ' ')
[[ -z "${UID0}" ]] \
  && pass "Only root has UID 0" \
  || fail "Extra UID 0 accounts: ${UID0}"

EMPTY_PW=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
[[ -z "${EMPTY_PW}" ]] \
  && pass "No accounts with empty passwords" \
  || fail "Accounts with EMPTY password: ${EMPTY_PW}"

# System accounts (UID < 1000) should not have an interactive shell
SYS_SHELL=$(awk -F: '$3 > 0 && $3 < 1000 && $7 !~ /(nologin|false|sync)$/ {print $1}' /etc/passwd | tr '\n' ' ')
[[ -z "${SYS_SHELL}" ]] \
  && pass "No system accounts with a login shell" \
  || warn_ "System accounts with a login shell: ${SYS_SHELL}"

# Who can become root via group membership
PRIV_MEMBERS=$( { getent group sudo | cut -d: -f4; getent group admin | cut -d: -f4; } 2>/dev/null \
  | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -)
if [[ -n "${EXPECTED_SUDO_USERS}" ]]; then
  EXTRA_PRIV=()
  IFS=',' read -ra _members <<< "${PRIV_MEMBERS}"
  for m in "${_members[@]}"; do
    list_contains "${EXPECTED_SUDO_USERS}" "${m}" || EXTRA_PRIV+=("${m}")
  done
  [[ ${#EXTRA_PRIV[@]} -eq 0 ]] \
    && pass "sudo/admin members match expected (${PRIV_MEMBERS:-none})" \
    || warn_ "Unexpected sudo/admin members: ${EXTRA_PRIV[*]} (expected: ${EXPECTED_SUDO_USERS})"
else
  [[ "${PRIV_MEMBERS}" != *","* ]] \
    && pass "Single sudo/admin member (${PRIV_MEMBERS:-none})" \
    || warn_ "Several sudo/admin members: ${PRIV_MEMBERS} (confirm all are expected, or pass --sudo-users)"
fi

# Users granted sudo directly in sudoers (bypassing groups), and NOPASSWD grants
SUDOERS_FILES=(/etc/sudoers /etc/sudoers.d/*)
DIRECT_GRANTS=$(grep -hE '^[[:space:]]*[a-z_][a-z0-9_-]*[[:space:]]+[^=]*=' "${SUDOERS_FILES[@]}" 2>/dev/null \
  | grep -vE '^[[:space:]]*(root|Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)\b' \
  | awk '{print $1}' | sort -u | tr '\n' ' ')
[[ -z "${DIRECT_GRANTS}" ]] \
  && pass "No users granted sudo directly in sudoers" \
  || warn_ "Users granted sudo directly in sudoers: ${DIRECT_GRANTS}"

NOPASSWD_LINES=$(grep -hE '^[^#]*NOPASSWD' "${SUDOERS_FILES[@]}" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
[[ -z "${NOPASSWD_LINES}" ]] \
  && pass "No NOPASSWD sudo grants" \
  || warn_ "NOPASSWD sudo grants for: ${NOPASSWD_LINES}(a stolen SSH key gives root without a password)"

# SSH keys on accounts that are not expected to log in
KEY_HOLDERS=()
while IFS=: read -r uname _ _ _ _ uhome ushell; do
  [[ "${uname}" == "root" ]] && continue       # root login is disabled by sshd
  [[ "${ushell}" =~ (nologin|false)$ ]] && continue
  [[ -s "${uhome}/.ssh/authorized_keys" ]] || continue
  list_contains "${PRIV_MEMBERS}" "${uname}" && continue
  KEY_HOLDERS+=("${uname}")
done < /etc/passwd
[[ ${#KEY_HOLDERS[@]} -eq 0 ]] \
  && pass "SSH keys only on sudo accounts" \
  || warn_ "Non-sudo accounts accepting SSH keys: ${KEY_HOLDERS[*]}"

# ────────────────────────────────────────────────────────
section "Tampering & Persistence"

if [[ -s /etc/ld.so.preload ]]; then
  fail "/etc/ld.so.preload is not empty (common rootkit technique): $(tr '\n' ' ' < /etc/ld.so.preload)"
else
  pass "/etc/ld.so.preload empty or absent"
fi

# Processes running from temp dirs or from deleted binaries
TMP_PROCS=()
DELETED_PROCS=()
for exe in /proc/[0-9]*/exe; do
  target=$(readlink "${exe}" 2>/dev/null) || continue
  pid="${exe#/proc/}"; pid="${pid%/exe}"
  pname=$(cat "/proc/${pid}/comm" 2>/dev/null)
  case "${target}" in
    /tmp/*|/var/tmp/*|/dev/shm/*) TMP_PROCS+=("${pname}(${pid}):${target}") ;;
    *" (deleted)") DELETED_PROCS+=("${pname}(${pid})") ;;
  esac
done
[[ ${#TMP_PROCS[@]} -eq 0 ]] \
  && pass "No processes running from /tmp, /var/tmp or /dev/shm" \
  || fail "Processes running from temp dirs: $(first_items 5 "${TMP_PROCS[@]}")"
[[ ${#DELETED_PROCS[@]} -eq 0 ]] \
  && pass "No processes running deleted binaries" \
  || warn_ "Processes running deleted binaries (restart after upgrade, or investigate): $(first_items 5 "${DELETED_PROCS[@]}")"

mapfile -t TMP_EXEC < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null)
[[ ${#TMP_EXEC[@]} -eq 0 ]] \
  && pass "No executable files in temp dirs" \
  || warn_ "Executable files in temp dirs: $(first_items 5 "${TMP_EXEC[@]}")"

# Scheduled jobs not installed by packages
mapfile -t USER_CRONTABS < <(find /var/spool/cron/crontabs -type f -printf '%f\n' 2>/dev/null)
[[ ${#USER_CRONTABS[@]} -eq 0 ]] \
  && pass "No user crontabs" \
  || warn_ "User crontabs exist for: ${USER_CRONTABS[*]} (confirm expected: crontab -l -u USER)"

LOCAL_CRON=()
for f in /etc/crontab /etc/cron.d/* /etc/cron.{hourly,daily,weekly,monthly}/*; do
  [[ -f "${f}" ]] || continue
  [[ "$(basename "${f}")" == ".placeholder" ]] && continue
  dpkg_owned "${f}" || LOCAL_CRON+=("${f}")
done
[[ ${#LOCAL_CRON[@]} -eq 0 ]] \
  && pass "All system cron jobs belong to packages" \
  || warn_ "Cron jobs not from any package: $(first_items 5 "${LOCAL_CRON[@]}")"

# Locally defined systemd units (worker services land here, so WARN not FAIL)
LOCAL_UNITS=()
for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
  [[ -f "${f}" && ! -L "${f}" ]] || continue
  case "$(basename "${f}")" in snap.*|snap-*) continue ;; esac   # generated by snapd
  LOCAL_UNITS+=("$(basename "${f}")")
done
[[ ${#LOCAL_UNITS[@]} -eq 0 ]] \
  && pass "No locally defined systemd services/timers" \
  || warn_ "Locally defined systemd units: $(first_items 8 "${LOCAL_UNITS[@]}") (confirm expected)"

if [[ "${QUICK}" == "true" ]]; then
  skip "SUID/SGID scan (--quick)"
  skip "Package integrity check (--quick)"
else
  # SUID/SGID binaries not shipped by any package
  UNOWNED_SUID=()
  while IFS= read -r -d '' f; do
    dpkg_owned "${f}" || UNOWNED_SUID+=("${f}")
  done < <(find / -xdev \
      \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers -o -path /snap \) -prune \
      -o -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
  [[ ${#UNOWNED_SUID[@]} -eq 0 ]] \
    && pass "All SUID/SGID binaries belong to packages" \
    || fail "SUID/SGID binaries not from any package: $(first_items 5 "${UNOWNED_SUID[@]}")"

  # Package-shipped executables/libraries whose contents changed
  echo -e "  ${CYAN}....${NC}  checking package integrity (dpkg --verify, may take a minute)"
  mapfile -t MODIFIED < <(dpkg --verify 2>/dev/null \
    | awk '$1 ~ /^..5/ && $2 != "c" {print $NF}' \
    | grep -E '^/(usr/)?(s?bin|lib|lib64|libexec)/')
  [[ ${#MODIFIED[@]} -eq 0 ]] \
    && pass "No modified package binaries/libraries (dpkg --verify)" \
    || fail "Modified package files (possible tampering): $(first_items 5 "${MODIFIED[@]}")"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Nginx Hardening Tests (--nginx option only)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if [[ "${CHECK_NGINX}" == "true" ]]; then

  if ! command -v nginx &>/dev/null; then
    section "Nginx"
    fail "nginx is not installed"
  else

    section "Nginx Basics"

    # Syntax test
    nginx -t 2>/dev/null \
      && pass "nginx -t syntax test" \
      || fail "nginx -t syntax test failed"

    systemctl is-active --quiet nginx \
      && pass "nginx running" \
      || fail "nginx is not running"

    # Fetch full config once and reuse
    NGINX_CONF=$(nginx -T 2>/dev/null)

    echo "${NGINX_CONF}" | grep -q "server_tokens off" \
      && pass "server_tokens off" \
      || fail "server_tokens off not set"

    # ────────────────────────────────────────────────────
    section "Nginx Security Headers"

    echo "${NGINX_CONF}" | grep -q 'X-Frame-Options.*SAMEORIGIN' \
      && pass "X-Frame-Options: SAMEORIGIN" \
      || fail "X-Frame-Options not set"

    echo "${NGINX_CONF}" | grep -q 'X-Content-Type-Options.*nosniff' \
      && pass "X-Content-Type-Options: nosniff" \
      || fail "X-Content-Type-Options not set"

    echo "${NGINX_CONF}" | grep -q 'X-XSS-Protection.*0' \
      && pass "X-XSS-Protection: 0 (disabled)" \
      || warn_ "X-XSS-Protection is not 0"

    echo "${NGINX_CONF}" | grep -q 'Strict-Transport-Security' \
      && pass "HSTS header set" \
      || fail "HSTS header not set"

    echo "${NGINX_CONF}" | grep -q 'Referrer-Policy' \
      && pass "Referrer-Policy set" \
      || fail "Referrer-Policy not set"

    echo "${NGINX_CONF}" | grep -q 'Permissions-Policy' \
      && pass "Permissions-Policy set" \
      || fail "Permissions-Policy not set"

    echo "${NGINX_CONF}" | grep -q 'Cross-Origin-Opener-Policy' \
      && pass "Cross-Origin-Opener-Policy set" \
      || fail "Cross-Origin-Opener-Policy not set"

    echo "${NGINX_CONF}" | grep -q 'Cross-Origin-Resource-Policy' \
      && pass "Cross-Origin-Resource-Policy set" \
      || fail "Cross-Origin-Resource-Policy not set"

    # ────────────────────────────────────────────────────
    section "Nginx CSP"

    if echo "${NGINX_CONF}" | grep -q 'Content-Security-Policy'; then
      pass "CSP header set"
    else
      fail "CSP header not set"
    fi

    echo "${NGINX_CONF}" | grep "Content-Security-Policy" | grep -q "object-src 'none'" \
      && pass "CSP: object-src 'none'" \
      || fail "CSP: object-src 'none' missing"

    echo "${NGINX_CONF}" | grep "Content-Security-Policy" | grep -q "upgrade-insecure-requests" \
      && pass "CSP: upgrade-insecure-requests" \
      || warn_ "CSP: upgrade-insecure-requests missing"

    # Verify img-src does not allow blanket https:
    if echo "${NGINX_CONF}" | grep "Content-Security-Policy" | grep "img-src" | grep -q "https:"; then
      fail "CSP: img-src allows blanket https: (exfiltration risk)"
    else
      pass "CSP: img-src no blanket https:"
    fi

    # ────────────────────────────────────────────────────
    section "Nginx SSL/TLS"

    echo "${NGINX_CONF}" | grep -q "ssl_protocols TLSv1.2 TLSv1.3" \
      && pass "TLS 1.2 + 1.3 only" \
      || fail "TLS protocol config incorrect"

    # Verify TLS 1.0 / 1.1 are not enabled
    if echo "${NGINX_CONF}" | grep "ssl_protocols" | grep -qE "TLSv1 |TLSv1.0|TLSv1.1"; then
      fail "TLS 1.0/1.1 enabled (vulnerable)"
    else
      pass "TLS 1.0/1.1 disabled"
    fi

    echo "${NGINX_CONF}" | grep -q "ssl_prefer_server_ciphers on" \
      && pass "ssl_prefer_server_ciphers on" \
      || fail "ssl_prefer_server_ciphers not on"

    echo "${NGINX_CONF}" | grep -q "ssl_session_tickets off" \
      && pass "ssl_session_tickets off" \
      || fail "ssl_session_tickets not off"

    # DH parameters
    if [[ -f /etc/nginx/dhparam.pem ]]; then
      pass "dhparam.pem exists"
      DHPARAM_PERMS=$(stat -c %a /etc/nginx/dhparam.pem 2>/dev/null)
      [[ "${DHPARAM_PERMS}" == "600" ]] \
        && pass "dhparam.pem permissions 600" \
        || fail "dhparam.pem permissions ${DHPARAM_PERMS} (expected: 600)"
    else
      warn_ "dhparam.pem does not exist"
    fi

    # Private key permissions
    if [[ -f /etc/nginx/self-signed.key ]]; then
      KEY_PERMS=$(stat -c %a /etc/nginx/self-signed.key 2>/dev/null)
      [[ "${KEY_PERMS}" == "600" ]] \
        && pass "self-signed.key permissions 600" \
        || fail "self-signed.key permissions ${KEY_PERMS} (expected: 600)"
    fi

    # ────────────────────────────────────────────────────
    section "Nginx Rate Limiting"

    echo "${NGINX_CONF}" | grep -q "limit_req_zone.*zone=general" \
      && pass "Rate limit general zone defined" \
      || fail "Rate limit general zone not defined"

    echo "${NGINX_CONF}" | grep -q "limit_req_zone.*zone=login" \
      && pass "Rate limit login zone defined" \
      || fail "Rate limit login zone not defined"

    # Login location has login zone applied
    echo "${NGINX_CONF}" | grep -q "limit_req zone=login" \
      && pass "Login location: login zone applied" \
      || fail "Login location: login zone not applied"

    echo "${NGINX_CONF}" | grep -q "limit_req_status 429" \
      && pass "Rate limit status 429" \
      || warn_ "Rate limit status is not 429 (default 503)"

    echo "${NGINX_CONF}" | grep -q "limit_conn_status 429" \
      && pass "Conn limit status 429" \
      || warn_ "Conn limit status is not 429 (default 503)"

    # ────────────────────────────────────────────────────
    section "Nginx Timeouts (slowloris mitigation)"

    echo "${NGINX_CONF}" | grep -q "client_body_timeout" \
      && pass "client_body_timeout set" \
      || fail "client_body_timeout not set"

    echo "${NGINX_CONF}" | grep -q "client_header_timeout" \
      && pass "client_header_timeout set" \
      || fail "client_header_timeout not set"

    # ────────────────────────────────────────────────────
    section "Nginx Proxy"

    echo "${NGINX_CONF}" | grep -q 'proxy_hide_header X-Powered-By' \
      && pass "proxy_hide_header X-Powered-By" \
      || warn_ "X-Powered-By header not stripped"

    # WebSocket: map block exists
    echo "${NGINX_CONF}" | grep -q 'map.*\$http_upgrade.*\$connection_upgrade' \
      && pass "WebSocket map directive exists" \
      || fail "map \$http_upgrade not defined"

    # WebSocket: proxy uses $connection_upgrade
    echo "${NGINX_CONF}" | grep -q 'Connection \$connection_upgrade' \
      && pass "WebSocket Connection header conditional" \
      || fail "Connection header hardcoded (sends upgrade to non-WebSocket requests)"

    # ────────────────────────────────────────────────────
    section "Nginx Default Server"

    # HTTP default server
    echo "${NGINX_CONF}" | grep -A5 "listen 80 default_server" | grep -q "return 444" \
      && pass "HTTP default server -> 444" \
      || fail "HTTP default server does not return 444"

    # HTTPS default server exists
    echo "${NGINX_CONF}" | grep -q "listen 443.*default_server" \
      && pass "HTTPS default server exists" \
      || fail "HTTPS default server missing (SNI bypass risk)"

    # ────────────────────────────────────────────────────
    section "Nginx Attack Path Blocking"

    # Attack paths return 403 (not 444, which doesn't log to access.log)
    echo "${NGINX_CONF}" | grep -A2 "wp-admin" | grep -q "return 403" \
      && pass "Attack paths -> 403 (fail2ban detectable)" \
      || warn_ "Attack paths not returning 403"

    # ────────────────────────────────────────────────────
    section "Nginx systemd"

    if [[ -f /etc/systemd/system/nginx.service.d/nofile.conf ]]; then
      grep -q "LimitNOFILE=65535" /etc/systemd/system/nginx.service.d/nofile.conf \
        && pass "systemd LimitNOFILE=65535" \
        || fail "systemd LimitNOFILE is not 65535"
    else
      warn_ "systemd nginx override does not exist"
    fi

    # ────────────────────────────────────────────────────
    section "Nginx Fail2ban"

    fail2ban-client status nginx-req-limit &>/dev/null \
      && pass "fail2ban nginx-req-limit jail enabled" \
      || fail "fail2ban nginx-req-limit jail disabled"

    fail2ban-client status nginx-botsearch &>/dev/null \
      && pass "fail2ban nginx-botsearch jail enabled" \
      || fail "fail2ban nginx-botsearch jail disabled"

    # ────────────────────────────────────────────────────
    section "Nginx Logrotate"

    [[ -f /etc/logrotate.d/nginx-hardened ]] \
      && pass "nginx-hardened logrotate config exists" \
      || fail "nginx-hardened logrotate config not found"

    # Check that package default logrotate is removed
    [[ ! -f /etc/logrotate.d/nginx ]] \
      && pass "Package default logrotate removed" \
      || warn_ "Package default /etc/logrotate.d/nginx still exists"

    # ────────────────────────────────────────────────────
    section "Let's Encrypt"

    # Detect domain from sites-enabled
    DOMAIN_CONF=$(ls /etc/nginx/sites-enabled/*.conf 2>/dev/null | head -1)
    if [[ -n "${DOMAIN_CONF}" ]]; then
      DETECTED_DOMAIN=$(basename "${DOMAIN_CONF}" .conf)
      if [[ -d "/etc/letsencrypt/live/${DETECTED_DOMAIN}" ]]; then
        pass "Let's Encrypt cert (${DETECTED_DOMAIN})"

        # OCSP Stapling enabled
        echo "${NGINX_CONF}" | grep -q "ssl_stapling on" \
          && pass "OCSP Stapling enabled" \
          || warn_ "OCSP Stapling disabled (re-run script after cert acquisition)"
      else
        echo -e "  ${CYAN}INFO${NC}  No Let's Encrypt cert (${DETECTED_DOMAIN}) — running with self-signed"
      fi
    fi

  fi

else
  echo ""
  echo -e "  ${CYAN}INFO${NC}  Nginx tests skipped (run with: sudo bash verify.sh --nginx)"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Results Summary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "=============================================="
echo -e "  ${GREEN}PASS${NC}: ${PASS_COUNT}  ${RED}FAIL${NC}: ${FAIL_COUNT}  ${YELLOW}WARN${NC}: ${WARN_COUNT}  ${YELLOW}SKIP${NC}: ${SKIP_COUNT}"

if [[ ${FAIL_COUNT} -eq 0 ]]; then
  echo -e "  ${GREEN}All tests PASSED${NC}"
  echo "=============================================="
  exit 0
else
  echo -e "  ${RED}${FAIL_COUNT} FAILURE(s) detected${NC}"
  echo "=============================================="
  exit 1
fi
