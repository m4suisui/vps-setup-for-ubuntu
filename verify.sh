#!/usr/bin/env bash
# ============================================================
#  VPS Hardening Verification Script  v2
#  Target: Ubuntu 22.04 / 24.04
#  Verifies that vps-hardening.sh / nginx-hardening.sh applied correctly
#
#  Usage: sudo bash verify.sh [--nginx]
#    --nginx: also run nginx-hardening.sh tests
#
#  Exit code: 0 = all PASS / 1 = FAIL detected
# ============================================================
set -uo pipefail
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
if [[ "${1:-}" == "--nginx" ]]; then
  CHECK_NGINX=true
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
    HAS_KEY=true
    break
  fi
done

if [[ "${HAS_KEY}" != "true" ]]; then
  fail "No sudo user has authorized_keys (lockout risk)"
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
SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | awk '{print $2}')
SSH_PORT="${SSH_PORT:-22}"
ufw status | grep -q "${SSH_PORT}/tcp.*ALLOW" \
  && pass "UFW SSH (${SSH_PORT}/tcp) allowed" \
  || fail "UFW SSH (${SSH_PORT}/tcp) not allowed"

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
  # File Descriptors
  ["fs.file-max"]="65535"
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

# ────────────────────────────────────────────────────────
section "auditd"

systemctl is-active --quiet auditd \
  && pass "auditd running" \
  || fail "auditd is not running"

[[ -f /etc/audit/rules.d/99-hardening.rules ]] \
  && pass "Audit rules file exists" \
  || fail "99-hardening.rules not found"

# Check that critical audit rules are actually loaded
auditctl -l 2>/dev/null | grep -q "shadow" \
  && pass "auditd: /etc/shadow monitored" \
  || fail "auditd: /etc/shadow monitoring rule not loaded"

auditctl -l 2>/dev/null | grep -q "sshd_config" \
  && pass "auditd: sshd_config monitored" \
  || fail "auditd: sshd_config monitoring rule not loaded"

auditctl -l 2>/dev/null | grep -q "priv_escalation" \
  && pass "auditd: sudo/su tracked" \
  || fail "auditd: sudo/su tracking rule not loaded"

# ────────────────────────────────────────────────────────
section "Time Synchronization"

timedatectl status 2>/dev/null | grep -qi "synchronized: yes" \
  && pass "NTP synchronized" \
  || warn_ "NTP not synchronized (check: timedatectl status)"

# ────────────────────────────────────────────────────────
section "Additional Hardening"

[[ -f /etc/modprobe.d/disable-usb-storage.conf ]] \
  && pass "USB storage disabled" \
  || warn_ "USB storage not disabled"

[[ -f /etc/security/limits.d/99-no-coredump.conf ]] \
  && pass "Core dump restriction (limits.d)" \
  || warn_ "Core dump restriction not configured"

# /dev/shm: verify actual mount options, not just fstab
SHM_MOUNT=$(mount 2>/dev/null | grep "/dev/shm" || true)
if echo "${SHM_MOUNT}" | grep -q "noexec"; then
  pass "/dev/shm noexec (mounted)"
elif grep -q "/dev/shm.*noexec" /etc/fstab 2>/dev/null; then
  warn_ "/dev/shm: noexec in fstab but not in current mount (remount needed)"
else
  warn_ "/dev/shm noexec not configured"
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
