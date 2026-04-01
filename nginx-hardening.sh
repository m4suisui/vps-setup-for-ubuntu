#!/usr/bin/env bash
# ============================================================
#  Nginx One-Shot Hardening Script  v5
#  Target: Ubuntu 22.04 / 24.04
#  Prerequisite: vps-hardening.sh completed / UFW 80,443 open
#  Purpose: Reverse proxy (app listens on localhost:PORT)
#
#  Idempotent: safe to re-run any number of times
# ============================================================
set -euo pipefail

# ─── User Configuration ──────────────────────────────────
DOMAIN="example.com"              # Production domain
APP_PORT="3000"                   # Backend port
CERT_EMAIL="you@example.com"      # Let's Encrypt notification email
ENABLE_SSL=true                   # false = HTTP only (for testing)
RATE_LIMIT_RPS="10"               # Requests per second per IP
RATE_LIMIT_BURST="20"             # Burst allowance
CONN_LIMIT_PER_IP="50"            # Concurrent connections per IP
CLIENT_MAX_BODY="10m"             # Upload size limit
GENERATE_DHPARAM=true             # DH parameter generation (takes 2-3 min on first run)
CSP_REPORT_ONLY=true              # true = observe mode / false = enforce mode
# ────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then warn "Must be run as root"; exit 1; fi
if [[ ! -f /etc/os-release ]] || ! grep -qi 'ID=ubuntu' /etc/os-release; then warn "Ubuntu only"; exit 1; fi

# ─── 0. Input Validation ─────────────────────────────────
if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
  warn "Invalid DOMAIN: ${DOMAIN}"; exit 1
fi

if [[ ! "${APP_PORT}" =~ ^[0-9]+$ ]] || (( APP_PORT < 1 || APP_PORT > 65535 )); then
  warn "Invalid APP_PORT: ${APP_PORT}"; exit 1
fi

if [[ ! "${CERT_EMAIL}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  warn "Invalid CERT_EMAIL: ${CERT_EMAIL}"; exit 1
fi

if [[ ! "${RATE_LIMIT_RPS}" =~ ^[0-9]+$ ]] || (( RATE_LIMIT_RPS < 1 )); then
  warn "Invalid RATE_LIMIT_RPS: ${RATE_LIMIT_RPS}"; exit 1
fi

if [[ ! "${RATE_LIMIT_BURST}" =~ ^[0-9]+$ ]] || (( RATE_LIMIT_BURST < 1 )); then
  warn "Invalid RATE_LIMIT_BURST: ${RATE_LIMIT_BURST}"; exit 1
fi

if [[ ! "${CONN_LIMIT_PER_IP}" =~ ^[0-9]+$ ]] || (( CONN_LIMIT_PER_IP < 1 )); then
  warn "Invalid CONN_LIMIT_PER_IP: ${CONN_LIMIT_PER_IP}"; exit 1
fi

if [[ ! "${CLIENT_MAX_BODY}" =~ ^[0-9]+[kmgKMG]?$ ]]; then
  warn "Invalid CLIENT_MAX_BODY: ${CLIENT_MAX_BODY}"; exit 1
fi

# ─── 0.1 Prerequisite Check ──────────────────────────────
if ! command -v fail2ban-client &>/dev/null; then
  warn "fail2ban not found. Run vps-hardening.sh first"; exit 1
fi

if ! ufw status | grep -q "Status: active"; then
  warn "UFW is not active. Run vps-hardening.sh first"; exit 1
fi

if ! ufw status | grep -q "80/tcp"; then
  warn "UFW: 80/tcp not allowed. Run: ufw allow 80/tcp"
fi
if ! ufw status | grep -q "443/tcp"; then
  warn "UFW: 443/tcp not allowed. Run: ufw allow 443/tcp"
fi

export DEBIAN_FRONTEND=noninteractive

# ─── 1. Nginx Install (nginx-extras from the start) ──────
log "Nginx install"
apt-get update -qq

if dpkg -l | grep -q "^ii.*nginx-extras"; then
  info "nginx-extras already installed"
elif dpkg -l | grep -q "^ii.*nginx-core\|^ii.*nginx-common"; then
  info "Replacing existing nginx with nginx-extras"
  apt-get install -y -qq nginx-extras
else
  apt-get install -y -qq nginx-extras
fi

# Check if more_clear_headers is available
HAS_MORE_HEADERS=false
if nginx -V 2>&1 | grep -q "headers-more"; then
  HAS_MORE_HEADERS=true
  log "headers-more module: available"
else
  info "headers-more module: not available (Server header hiding skipped)"
fi

# Detect nginx version (ssl_reject_handshake requires 1.19.4+)
NGINX_VER=$(nginx -v 2>&1 | sed -n 's/.*nginx\/\([0-9.]*\).*/\1/p')
NGINX_VER="${NGINX_VER:-0.0.0}"
NGINX_MAJOR=$(echo "${NGINX_VER}" | cut -d. -f1)
NGINX_MINOR=$(echo "${NGINX_VER}" | cut -d. -f2)
NGINX_PATCH=$(echo "${NGINX_VER}" | cut -d. -f3)
NGINX_PATCH="${NGINX_PATCH:-0}"
HAS_REJECT_HANDSHAKE=false
if (( NGINX_MAJOR > 1 )) || (( NGINX_MAJOR == 1 && NGINX_MINOR > 19 )) || \
   (( NGINX_MAJOR == 1 && NGINX_MINOR == 19 && NGINX_PATCH >= 4 )); then
  HAS_REJECT_HANDSHAKE=true
  log "ssl_reject_handshake: available (nginx ${NGINX_VER})"
else
  info "ssl_reject_handshake: not supported (nginx ${NGINX_VER} < 1.19.4)"
fi

# nginx 1.25.1+ deprecates listen ... http2 in favor of http2 on;
HTTP2_DIRECTIVE="ssl http2"
HTTP2_EXTRA=""
if (( NGINX_MAJOR > 1 )) || (( NGINX_MAJOR == 1 && NGINX_MINOR > 25 )) || \
   (( NGINX_MAJOR == 1 && NGINX_MINOR == 25 && NGINX_PATCH >= 1 )); then
  HTTP2_DIRECTIVE="ssl"
  HTTP2_EXTRA="http2 on;"
  log "http2 directive: new style (nginx ${NGINX_VER} >= 1.25.1)"
fi

# ─── 2. DH Parameter Generation ──────────────────────────
DHPARAM_LINE="# ssl_dhparam not generated"
if [[ "${GENERATE_DHPARAM}" == "true" ]]; then
  if [[ -f /etc/nginx/dhparam.pem ]]; then
    info "dhparam.pem already exists"
  else
    log "Generating DH parameters (takes 2-3 minutes)..."
    openssl dhparam -out /etc/nginx/dhparam.pem 2048 2>/dev/null
    chmod 600 /etc/nginx/dhparam.pem
    log "DH parameters generated"
  fi
  DHPARAM_LINE="ssl_dhparam /etc/nginx/dhparam.pem;"
fi

# ─── 3. Nginx Main Config (nginx.conf) ───────────────────
log "nginx.conf hardening"

MORE_HEADERS_DIRECTIVE=""
if [[ "${HAS_MORE_HEADERS}" == "true" ]]; then
  MORE_HEADERS_DIRECTIVE="more_clear_headers Server;"
fi

cat > /etc/nginx/nginx.conf <<MAINEOF
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

# Load nginx-extras modules
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 2048;
    multi_accept on;
    use epoll;
}

http {
    # ── Basics ──
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # ── Hide Version ──
    server_tokens off;
    ${MORE_HEADERS_DIRECTIVE}

    # ── Timeouts (slowloris mitigation) ──
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    send_timeout 10s;
    reset_timedout_connection on;

    # ── Buffer Limits (buffer overflow mitigation) ──
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;

    # ── Rate Limit Zone Definitions ──
    limit_req_zone \$binary_remote_addr zone=general:10m rate=${RATE_LIMIT_RPS}r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=3r/s;
    limit_conn_zone \$binary_remote_addr zone=connlimit:10m;

    # ── Rate Limit / Conn Limit Status Code ──
    # Default 503 is indistinguishable from real server overload; use 429 instead
    limit_req_status 429;
    limit_conn_status 429;

    # ── WebSocket Support: Conditional Connection Header ──
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        ''      close;
    }

    # ── Logging ──
    log_format main '\$remote_addr - \$remote_user [\$time_local] '
                    '"\$request" \$status \$body_bytes_sent '
                    '"\$http_referer" "\$http_user_agent" '
                    'rt=\$request_time '
                    'ssl=\$ssl_protocol/\$ssl_cipher';
    access_log /var/log/nginx/access.log main buffer=16k flush=5s;
    error_log /var/log/nginx/error.log warn;

    # ── Gzip ──
    # WARNING: HTTPS + gzip is vulnerable to BREACH attacks
    # Ensure backend does not compress responses containing secret tokens (CSRF, etc.)
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_types
        text/plain text/css text/xml text/javascript
        application/json application/javascript application/xml
        application/rss+xml image/svg+xml;

    # ── Site Config Includes ──
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
MAINEOF

# ─── 4. Security Headers Snippet ─────────────────────────
log "Security headers snippet"
mkdir -p /etc/nginx/snippets

if [[ "${CSP_REPORT_ONLY}" == "true" ]]; then
  CSP_HEADER_NAME="Content-Security-Policy-Report-Only"
  log "CSP mode: Report-Only (report violations, don't block)"
else
  CSP_HEADER_NAME="Content-Security-Policy"
  log "CSP mode: Enforce (block violations)"
fi

cat > /etc/nginx/snippets/security-headers.conf <<HDEOF
# WARNING: nginx add_header inheritance trap:
#   If any add_header directive appears in a location block,
#   ALL headers from the parent (server) level are dropped.
#   Fix: re-include this snippet in location blocks, or use
#   more_set_headers (headers-more module) instead.

# ── Clickjacking Protection ──
add_header X-Frame-Options "SAMEORIGIN" always;

# ── MIME Sniffing Prevention ──
add_header X-Content-Type-Options "nosniff" always;

# ── XSS Filter ──
# Chrome 78+ removed XSS Auditor. Set to "0" and rely on CSP instead
add_header X-XSS-Protection "0" always;

# ── Referrer Control ──
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# ── Permissions Policy ──
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# ── HSTS (2 years + preload) ──
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# ══════════════════════════════════════════════════════════
#  CSP: Current mode = ${CSP_HEADER_NAME}
#
#  Workflow:
#    1. Deploy with CSP_REPORT_ONLY=true
#    2. Check DevTools > Console for "violated"
#    3. Add required domains to the policy below
#    4. When no violations remain, re-run with CSP_REPORT_ONLY=false
#
#  Common additions:
#    Google Fonts  -> font-src https://fonts.googleapis.com https://fonts.gstatic.com
#    CDN (cdnjs)   -> script-src https://cdnjs.cloudflare.com
#    Stripe        -> script-src https://js.stripe.com; frame-src https://js.stripe.com
#    S3 images     -> img-src https://your-bucket.s3.amazonaws.com
#    Inline JS     -> script-src 'unsafe-inline' (not recommended) or nonce-based
# ══════════════════════════════════════════════════════════
# NOTE: img-src — only add specific external domains (blanket https: enables exfiltration)
# NOTE: style-src 'unsafe-inline' — CSS injection risk; consider nonce-based approach
add_header ${CSP_HEADER_NAME} "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;" always;

# ── Cross-Origin Policies ──
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
HDEOF

# ─── 5. Proxy Common Snippet ─────────────────────────────
cat > /etc/nginx/snippets/proxy-params.conf <<'PREOF'
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;

proxy_connect_timeout 10s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;

proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 8k;

# ── Strip Information Leak Headers from Backend ──
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
proxy_hide_header X-Runtime;
PREOF

# ─── 6. Malicious Request Blocking Snippet ───────────────
cat > /etc/nginx/snippets/block-exploits.conf <<'BLEOF'
# ── Reject Invalid HTTP Methods ──
if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) {
    return 444;
}

# ── Block Known Vulnerability Scanners/Bots ──
# NOTE: Easily bypassed via UA spoofing. Defense in depth only — do not rely on this
if ($http_user_agent ~* (sqlmap|nikto|havij|nmap|masscan|zgrab|semrush|ahref|mj12bot|dotbot|blexbot)) {
    return 444;
}

# ── Block Access to Hidden Files ──
location ~ /\. {
    return 404;
}

# ── Block Common Attack Paths ──
# Returns 403 (not 444) so access log records the request for fail2ban detection
location ~* ^/(wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php|\.env|\.git|vendor|node_modules|\.aws|phpmyadmin|myadmin|mysql|db|administrator|admin/config) {
    return 403;
}
BLEOF

# ─── 7. SSL Parameters Snippet ───────────────────────────
# OCSP Stapling only works with Let's Encrypt certs (not self-signed)
HAS_REAL_CERT=false
if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
  HAS_REAL_CERT=true
fi

OCSP_CONF=""
if [[ "${HAS_REAL_CERT}" == "true" ]]; then
  OCSP_CONF="
# ── OCSP Stapling (enabled with Let's Encrypt cert) ──
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;"
else
  OCSP_CONF="
# ── OCSP Stapling ──
# Disabled with self-signed cert. Re-run after certbot obtains a real cert to enable
# ssl_stapling on;
# ssl_stapling_verify on;
# resolver 1.1.1.1 8.8.8.8 valid=300s;
# resolver_timeout 5s;"
fi

cat > /etc/nginx/snippets/ssl-params.conf <<SSLEOF
# ── Protocols (TLS 1.2 + 1.3 only) ──
ssl_protocols TLSv1.2 TLSv1.3;

# ── Cipher Suites (server preference) ──
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

# ── Sessions ──
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
${OCSP_CONF}

# ── DH Parameters ──
${DHPARAM_LINE}
SSLEOF

# ─── 8. Site Configuration ───────────────────────────────
log "Site config: ${DOMAIN}"
rm -f /etc/nginx/sites-enabled/default

# HTTPS default server ssl_reject_handshake support
REJECT_HANDSHAKE_LINE=""
if [[ "${HAS_REJECT_HANDSHAKE}" == "true" ]]; then
  REJECT_HANDSHAKE_LINE="ssl_reject_handshake on;"
fi

cat > /etc/nginx/sites-available/${DOMAIN}.conf <<SITEEOF
# ══════════════════════════════════════════════════════════
#  Default server: Drop direct IP / invalid Host requests
# ══════════════════════════════════════════════════════════

# ── HTTP default ──
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

# ── HTTPS default (SNI bypass prevention) ──
server {
    listen 443 ${HTTP2_DIRECTIVE} default_server;
    listen [::]:443 ${HTTP2_DIRECTIVE} default_server;
    server_name _;
    ${HTTP2_EXTRA}
    ssl_certificate /etc/nginx/self-signed.crt;
    ssl_certificate_key /etc/nginx/self-signed.key;
    ${REJECT_HANDSHAKE_LINE}
    return 444;
}

# ══════════════════════════════════════════════════════════
#  ${DOMAIN}
# ══════════════════════════════════════════════════════════

# ── HTTP -> HTTPS Redirect ──
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# ── Main (HTTPS) ──
server {
    listen 443 ${HTTP2_DIRECTIVE};
    listen [::]:443 ${HTTP2_DIRECTIVE};
    server_name ${DOMAIN} www.${DOMAIN};
    ${HTTP2_EXTRA}

    # SSL certificate (certbot will overwrite later)
    ssl_certificate /etc/nginx/self-signed.crt;
    ssl_certificate_key /etc/nginx/self-signed.key;
    include /etc/nginx/snippets/ssl-params.conf;

    # Security
    include /etc/nginx/snippets/security-headers.conf;
    include /etc/nginx/snippets/block-exploits.conf;

    # Request limits
    client_max_body_size ${CLIENT_MAX_BODY};
    limit_req zone=general burst=${RATE_LIMIT_BURST} nodelay;
    limit_conn connlimit ${CONN_LIMIT_PER_IP};

    # ── App Proxy ──
    location / {
        include /etc/nginx/snippets/proxy-params.conf;
        proxy_pass http://127.0.0.1:${APP_PORT};
    }

    # ── Login Paths: Additional Rate Limiting ──
    # Adjust path patterns to match your application
    # NOTE: nginx location-level limit_req overrides (not inherits) server-level directives,
    #       so the general zone must be explicitly redeclared here
    location ~* ^/(login|signin|auth|api/auth|api/login) {
        include /etc/nginx/snippets/proxy-params.conf;
        limit_req zone=general burst=${RATE_LIMIT_BURST} nodelay;
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:${APP_PORT};
    }
}
SITEEOF

ln -sf /etc/nginx/sites-available/${DOMAIN}.conf /etc/nginx/sites-enabled/

# ─── 9. Self-Signed Certificate (initial boot -> certbot replaces) ──
if [[ ! -f /etc/nginx/self-signed.crt ]]; then
  log "Generating temporary self-signed certificate"
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/nginx/self-signed.key \
    -out /etc/nginx/self-signed.crt \
    -subj "/CN=localhost" 2>/dev/null
  chmod 600 /etc/nginx/self-signed.key
fi

# ─── 10. systemd: LimitNOFILE to match worker_rlimit_nofile ──
log "systemd nginx LimitNOFILE"
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/nofile.conf <<'SDEOF'
[Service]
LimitNOFILE=65535
SDEOF
systemctl daemon-reload

# ─── 11. Nginx Test & Start ──────────────────────────────
nginx -t && log "nginx config OK" || { warn "nginx config error"; exit 1; }
systemctl enable --now nginx
systemctl reload nginx

# ─── 12. Let's Encrypt ───────────────────────────────────
if [[ "${ENABLE_SSL}" == "true" ]]; then
  log "Certbot install & certificate acquisition"
  apt-get install -y -qq certbot python3-certbot-nginx
  mkdir -p /var/www/certbot

  if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
    info "Certificate already exists. Running renewal check only"
    certbot renew --dry-run && log "Certificate auto-renewal test OK"
  else
    # --no-redirect: We handle HTTP->HTTPS redirect manually
    certbot --nginx \
      -d "${DOMAIN}" -d "www.${DOMAIN}" \
      --non-interactive --agree-tos \
      --email "${CERT_EMAIL}" \
      --no-redirect \
      --staple-ocsp

    certbot renew --dry-run && log "Certificate auto-renewal test OK"

    # Enable OCSP Stapling after cert acquisition — regenerate ssl-params.conf
    log "OCSP Stapling enabled (certificate obtained)"
    cat > /etc/nginx/snippets/ssl-params.conf <<SSLEOF2
# ── Protocols (TLS 1.2 + 1.3 only) ──
ssl_protocols TLSv1.2 TLSv1.3;

# ── Cipher Suites (server preference) ──
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

# ── Sessions ──
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# ── OCSP Stapling (enabled with Let's Encrypt cert) ──
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# ── DH Parameters ──
${DHPARAM_LINE}
SSLEOF2

    systemctl reload nginx
  fi

  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'HOOKEOF'
#!/bin/bash
systemctl reload nginx
HOOKEOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
fi

# ─── 13. Fail2ban Nginx Rules ────────────────────────────
# Nginx-specific jails only. SSH jail is managed by vps-hardening.sh
log "Fail2ban: nginx rules"

cat > /etc/fail2ban/filter.d/nginx-req-limit.conf <<'F2BNEOF'
[Definition]
failregex = limiting requests, excess:.* by zone.*client: <HOST>
ignoreregex =
F2BNEOF

# botsearch: detect attack path access (returns 403 so it appears in access.log)
cat > /etc/fail2ban/filter.d/nginx-botsearch.conf <<'F2BBEOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD).*(wp-login|xmlrpc|\.env|\.git|phpmyadmin|admin).*" (403|404)
ignoreregex =
F2BBEOF

mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/nginx.conf <<'F2BJEOF'
# Managed by nginx-hardening.sh

[nginx-req-limit]
enabled  = true
port     = http,https
filter   = nginx-req-limit
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 3
bantime  = 86400
F2BJEOF

systemctl restart fail2ban

# ─── 14. Logrotate ────────────────────────────────────────
log "Logrotate config"
rm -f /etc/logrotate.d/nginx

cat > /etc/logrotate.d/nginx-hardened <<'LREOF'
/var/log/nginx/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid)
    endscript
}
LREOF

# ─── Done ─────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "${GREEN} Nginx Hardening v5 Complete${NC}"
echo "=============================================="
echo ""
echo "  Domain   : ${DOMAIN}"
echo "  Backend  : 127.0.0.1:${APP_PORT}"
echo "  nginx    : ${NGINX_VER}"
echo ""
if [[ "${ENABLE_SSL}" == "true" ]]; then
echo "  SSL      : Let's Encrypt (auto-renewal)"
echo "  DHparam  : $([ -f /etc/nginx/dhparam.pem ] && echo 'enabled' || echo 'disabled')"
echo "  OCSP     : $([ "${HAS_REAL_CERT}" == "true" ] && echo 'enabled' || echo 'enabled after cert acquisition')"
echo "  Test     : https://www.ssllabs.com/ssltest/analyze.html?d=${DOMAIN}"
fi
echo ""
echo "  Automated:"
echo "    - SSL certificate auto-renewal (certbot timer)"
echo "    - Rate limit violation auto-ban (fail2ban)"
echo "    - Vulnerability scanner auto-block (fail2ban)"
echo "    - Log rotation (30-day retention)"
echo ""
if [[ "${CSP_REPORT_ONLY}" == "true" ]]; then
echo -e "  ${CYAN}CSP mode: Report-Only (observing)${NC}"
echo "  -> Check DevTools > Console for 'violated'"
echo "  -> When clean, re-run with CSP_REPORT_ONLY=false"
else
echo -e "  ${GREEN}CSP mode: Enforce (production)${NC}"
fi
echo ""
echo "    Edit CSP: /etc/nginx/snippets/security-headers.conf"
echo "    Apply:    sudo nginx -t && sudo systemctl reload nginx"
echo ""
echo "  This script is idempotent. Safe to re-run after config changes."
echo "=============================================="
