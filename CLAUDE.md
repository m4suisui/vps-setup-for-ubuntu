# Project Instructions for Claude

#!/usr/bin/env bash
# ============================================================
#  Nginx One-Shot Hardening Script  v3
#  Target: Ubuntu 22.04 / 24.04
#  前提: vps-hardening.sh 実行済み / UFW で 80,443 開放済み
#  用途: リバースプロキシ (アプリは localhost:PORT で待機)
#
#  ★ 冪等性あり: 何度実行しても安全
# ============================================================
set -euo pipefail

# ─── ユーザー設定 ──────────────────────────────────────────
DOMAIN="example.com"              # 本番ドメイン
APP_PORT="3000"                   # バックエンドのポート
CERT_EMAIL="you@example.com"      # Let's Encrypt 通知先
ENABLE_SSL=true                   # false → HTTPだけ (テスト用)
RATE_LIMIT_RPS="10"               # 1IPあたり req/sec
RATE_LIMIT_BURST="20"             # バースト許容
CONN_LIMIT_PER_IP="50"            # 1IPあたり同時接続数
CLIENT_MAX_BODY="10m"             # アップロード上限
GENERATE_DHPARAM=true             # DH パラメータ生成 (初回2-3分かかる)
CSP_REPORT_ONLY=true              # true=観察モード(違反を報告のみ) / false=本番(違反をブロック)
                                  # デプロイ直後は true → 違反を潰したら false に切替
# ────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${RED}[!]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then warn "root で実行してください"; exit 1; fi

# ─── 1. Nginx インストール (最初から nginx-extras) ────────
# nginx-extras を最初に入れることで、
# nginx → nginx-extras の入れ替え時に起きるモジュール不整合を回避
log "Nginx インストール"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

if dpkg -l | grep -q "^ii.*nginx-extras"; then
  info "nginx-extras は既にインストール済み"
elif dpkg -l | grep -q "^ii.*nginx-core\|^ii.*nginx-common"; then
  # 既存の nginx を nginx-extras に入れ替え
  info "既存の nginx を nginx-extras に置換"
  apt-get install -y -qq nginx-extras
else
  apt-get install -y -qq nginx-extras
fi

# more_clear_headers が使えるか確認
HAS_MORE_HEADERS=false
if nginx -V 2>&1 | grep -q "headers-more"; then
  HAS_MORE_HEADERS=true
  log "headers-more モジュール: 利用可能"
else
  info "headers-more モジュール: 非対応 (Server ヘッダ隠蔽スキップ)"
fi

# ─── 2. DH パラメータ生成 ─────────────────────────────────
DHPARAM_LINE="# ssl_dhparam not generated"
if [[ "${GENERATE_DHPARAM}" == "true" ]]; then
  if [[ -f /etc/nginx/dhparam.pem ]]; then
    info "dhparam.pem は既に存在"
  else
    log "DHパラメータ生成中 (2-3分かかります)..."
    openssl dhparam -out /etc/nginx/dhparam.pem 2048 2>/dev/null
    log "DHパラメータ生成完了"
  fi
  DHPARAM_LINE="ssl_dhparam /etc/nginx/dhparam.pem;"
fi

# ─── 3. Nginx メイン設定 (nginx.conf) ─────────────────────
# 毎回上書き = 冪等
log "nginx.conf ハードニング"

MORE_HEADERS_DIRECTIVE=""
if [[ "${HAS_MORE_HEADERS}" == "true" ]]; then
  MORE_HEADERS_DIRECTIVE="more_clear_headers Server;"
fi

cat > /etc/nginx/nginx.conf <<MAINEOF
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

# nginx-extras のモジュール読み込み
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 2048;
    multi_accept on;
    use epoll;
}

http {
    # ── 基本 ──
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # ── バージョン隠蔽 ──
    server_tokens off;
    ${MORE_HEADERS_DIRECTIVE}

    # ── タイムアウト (slowloris 対策) ──
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    send_timeout 10s;
    reset_timedout_connection on;

    # ── バッファ制限 (buffer overflow 対策) ──
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;

    # ── Rate Limit ゾーン定義 ──
    limit_req_zone \$binary_remote_addr zone=general:10m rate=${RATE_LIMIT_RPS}r/s;
    limit_req_zone \$binary_remote_addr zone=login:10m rate=3r/s;
    limit_conn_zone \$binary_remote_addr zone=connlimit:10m;

    # ── ログ ──
    log_format main '\$remote_addr - \$remote_user [\$time_local] '
                    '"\$request" \$status \$body_bytes_sent '
                    '"\$http_referer" "\$http_user_agent" '
                    'rt=\$request_time';
    access_log /var/log/nginx/access.log main buffer=16k flush=5s;
    error_log /var/log/nginx/error.log warn;

    # ── Gzip ──
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_types
        text/plain text/css text/xml text/javascript
        application/json application/javascript application/xml
        application/rss+xml image/svg+xml;

    # ── サイト設定読み込み ──
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
MAINEOF

# ─── 4. セキュリティヘッダ snippet ────────────────────────
log "セキュリティヘッダ snippet 作成"
mkdir -p /etc/nginx/snippets

# CSP ヘッダ名を決定
if [[ "${CSP_REPORT_ONLY}" == "true" ]]; then
  CSP_HEADER_NAME="Content-Security-Policy-Report-Only"
  log "CSP モード: Report-Only (違反を報告のみ、ブロックしない)"
else
  CSP_HEADER_NAME="Content-Security-Policy"
  log "CSP モード: Enforce (違反をブロック)"
fi

cat > /etc/nginx/snippets/security-headers.conf <<HDEOF
# ── クリックジャッキング防御 ──
add_header X-Frame-Options "SAMEORIGIN" always;

# ── MIME スニッフィング防止 ──
add_header X-Content-Type-Options "nosniff" always;

# ── XSS フィルタ (レガシーブラウザ用) ──
add_header X-XSS-Protection "1; mode=block" always;

# ── Referrer 制御 ──
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# ── Permissions Policy ──
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# ── HSTS (2年 + preload) ──
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# ══════════════════════════════════════════════════════════
#  CSP: 現在のモード → ${CSP_HEADER_NAME}
#
#  Report-Only = 違反をブラウザコンソールに表示するが、ブロックしない
#  Enforce     = 違反をブロックする (本番用)
#
#  運用フロー:
#    1. CSP_REPORT_ONLY=true でデプロイ
#    2. DevTools > Console で "violated" を検索
#    3. 必要なドメインを下記ポリシーに追加
#    4. 違反が出なくなったら CSP_REPORT_ONLY=false で再実行
#
#  よくある追加例:
#    Google Fonts  → font-src https://fonts.googleapis.com https://fonts.gstatic.com
#    CDN (cdnjs)   → script-src https://cdnjs.cloudflare.com
#    Stripe        → script-src https://js.stripe.com; frame-src https://js.stripe.com
#    S3 画像       → img-src https://your-bucket.s3.amazonaws.com
#    インラインJS  → script-src 'unsafe-inline' (非推奨) or nonce-based
# ══════════════════════════════════════════════════════════
add_header ${CSP_HEADER_NAME} "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;

# ── Cross-Origin 系 ──
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
HDEOF

# ─── 5. プロキシ共通 snippet ──────────────────────────────
cat > /etc/nginx/snippets/proxy-params.conf <<'PREOF'
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";

proxy_connect_timeout 10s;
proxy_send_timeout 30s;
proxy_read_timeout 30s;

proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 8k;
PREOF

# ─── 6. 悪意あるリクエスト遮断 snippet ───────────────────
cat > /etc/nginx/snippets/block-exploits.conf <<'BLEOF'
# ── 不正な HTTP メソッド拒否 ──
if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) {
    return 444;
}

# ── 既知の脆弱性スキャナ/bot ブロック ──
if ($http_user_agent ~* (sqlmap|nikto|havij|nmap|masscan|zgrab|semrush|ahref|mj12bot|dotbot|blexbot)) {
    return 444;
}

# ── 隠しファイルへのアクセス遮断 ──
location ~ /\. {
    deny all;
    return 404;
}

# ── よくある攻撃パスを即切断 ──
location ~* ^/(wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php|\.env|\.git|vendor|node_modules|\.aws|phpmyadmin|myadmin|mysql|db|administrator|admin/config) {
    return 444;
}
BLEOF

# ─── 7. SSL パラメータ snippet ────────────────────────────
cat > /etc/nginx/snippets/ssl-params.conf <<SSLEOF
# ── プロトコル (TLS 1.2 + 1.3 のみ) ──
ssl_protocols TLSv1.2 TLSv1.3;

# ── 暗号スイート (サーバー側優先) ──
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

# ── セッション ──
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# ── OCSP Stapling ──
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# ── DH パラメータ ──
${DHPARAM_LINE}
SSLEOF

# ─── 8. サイト設定 ────────────────────────────────────────
# 上書き = 冪等
log "サイト設定: ${DOMAIN}"
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/${DOMAIN}.conf <<SITEEOF
# ── IP直アクセス / 不正Host → 即切断 ──
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}

# ── HTTP → HTTPS リダイレクト ──
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    # Let's Encrypt 認証用
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# ── メイン (HTTPS) ──
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};

    # SSL証明書 (certbot が後で上書き)
    ssl_certificate /etc/nginx/self-signed.crt;
    ssl_certificate_key /etc/nginx/self-signed.key;
    include /etc/nginx/snippets/ssl-params.conf;

    # セキュリティ
    include /etc/nginx/snippets/security-headers.conf;
    include /etc/nginx/snippets/block-exploits.conf;

    # リクエスト制限
    client_max_body_size ${CLIENT_MAX_BODY};
    limit_req zone=general burst=${RATE_LIMIT_BURST} nodelay;
    limit_conn connlimit ${CONN_LIMIT_PER_IP};

    # ── アプリへのプロキシ ──
    location / {
        include /etc/nginx/snippets/proxy-params.conf;
        proxy_pass http://127.0.0.1:${APP_PORT};
    }

    # ── ログインパスは追加レート制限 ──
    # ★ パス名はアプリに合わせて変更
    location ~* ^/(login|signin|auth|api/auth|api/login) {
        include /etc/nginx/snippets/proxy-params.conf;
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:${APP_PORT};
    }
}
SITEEOF

ln -sf /etc/nginx/sites-available/${DOMAIN}.conf /etc/nginx/sites-enabled/

# ─── 9. 自己署名証明書 (初回起動用 → certbot が上書き) ────
if [[ ! -f /etc/nginx/self-signed.crt ]]; then
  log "一時的な自己署名証明書を生成"
  openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/nginx/self-signed.key \
    -out /etc/nginx/self-signed.crt \
    -subj "/CN=${DOMAIN}" 2>/dev/null
fi

# ─── 10. Nginx テスト & 起動 ──────────────────────────────
nginx -t && log "nginx config OK" || { warn "nginx config エラー"; exit 1; }
systemctl enable --now nginx
systemctl reload nginx

# ─── 11. Let's Encrypt ───────────────────────────────────
if [[ "${ENABLE_SSL}" == "true" ]]; then
  log "Certbot インストール & 証明書取得"
  apt-get install -y -qq certbot python3-certbot-nginx
  mkdir -p /var/www/certbot

  # 既に証明書がある場合は取得スキップ (冪等)
  if [[ -d "/etc/letsencrypt/live/${DOMAIN}" ]]; then
    info "証明書は既に存在。更新チェックのみ実行"
    certbot renew --dry-run && log "証明書自動更新テスト OK"
  else
    certbot --nginx \
      -d "${DOMAIN}" -d "www.${DOMAIN}" \
      --non-interactive --agree-tos \
      --email "${CERT_EMAIL}" \
      --redirect \
      --staple-ocsp

    certbot renew --dry-run && log "証明書自動更新テスト OK"
  fi

  # 更新後に nginx を reload する hook (上書き = 冪等)
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'HOOKEOF'
#!/bin/bash
systemctl reload nginx
HOOKEOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
fi

# ─── 12. Fail2ban nginx ルール (冪等: ファイル丸ごと上書き) ─
log "Fail2ban: nginx ルール設定"

# フィルタ定義 (上書き = 冪等)
cat > /etc/fail2ban/filter.d/nginx-req-limit.conf <<'F2BNEOF'
[Definition]
failregex = limiting requests, excess:.* by zone.*client: <HOST>
ignoreregex =
F2BNEOF

cat > /etc/fail2ban/filter.d/nginx-botsearch.conf <<'F2BBEOF'
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD).*(wp-login|xmlrpc|\.env|\.git|phpmyadmin|admin).*" (404|444)
ignoreregex =
F2BBEOF

# SSH ポートを sshd の実効設定から取得
# sshd -T は Include やオーバーライドを全て解決した最終値を返す
# どのファイルにポート設定があっても正しく検出できる
SSH_PORT_FOR_F2B=$(sshd -T 2>/dev/null | grep "^port " | awk '{print $2}')
SSH_PORT_FOR_F2B="${SSH_PORT_FOR_F2B:-22}"
log "Fail2ban: SSH ポート検出 → ${SSH_PORT_FOR_F2B}"

cat > /etc/fail2ban/jail.local <<F2BJEOF
# ============================================================
#  Fail2ban 統合設定 (vps-hardening + nginx-hardening)
#  ★ このファイルはスクリプトが管理。手動編集は上書きされる
#  ★ カスタム設定は /etc/fail2ban/jail.d/ に別ファイルで追加
# ============================================================

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = ufw

# ── SSH ──
[sshd]
enabled  = true
port     = ${SSH_PORT_FOR_F2B}
filter   = sshd
maxretry = 3
bantime  = 86400

# ── Nginx Rate Limit 超過 ──
[nginx-req-limit]
enabled  = true
port     = http,https
filter   = nginx-req-limit
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

# ── Nginx 脆弱性スキャナ ──
[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 3
bantime  = 86400
F2BJEOF

systemctl restart fail2ban

# ─── 13. Logrotate (既存の nginx 設定を置換) ──────────────
# Ubuntu の nginx パッケージが作る /etc/logrotate.d/nginx と競合させない
log "Logrotate 設定 (既存を置換)"
rm -f /etc/logrotate.d/nginx  # パッケージ標準を削除

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

# ─── 完了 ──────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "${GREEN} Nginx Hardening v3 完了${NC}"
echo "=============================================="
echo ""
echo "  ドメイン : ${DOMAIN}"
echo "  バックエンド: 127.0.0.1:${APP_PORT}"
echo "  SSH(f2b) : Port ${SSH_PORT_FOR_F2B} (sshd実効値から自動検出)"
echo ""
if [[ "${ENABLE_SSL}" == "true" ]]; then
echo "  SSL      : Let's Encrypt (自動更新)"
echo "  DHparam  : $([ -f /etc/nginx/dhparam.pem ] && echo '有効' || echo '無効')"
echo "  テスト   : https://www.ssllabs.com/ssltest/analyze.html?d=${DOMAIN}"
fi
echo ""
echo "  自動化済み:"
echo "    - SSL証明書の自動更新 (certbot timer)"
echo "    - Rate limit 超過IPの自動BAN (fail2ban)"
echo "    - 脆弱性スキャナの自動遮断 (fail2ban)"
echo "    - ログローテーション (30日保持)"
echo ""
if [[ "${CSP_REPORT_ONLY}" == "true" ]]; then
echo -e "  ${CYAN}CSP モード: Report-Only (観察中)${NC}"
echo "  → ブラウザ DevTools > Console で 'violated' を検索"
echo "  → 違反が出なくなったら CSP_REPORT_ONLY=false で再実行"
else
echo -e "  ${GREEN}CSP モード: Enforce (本番)${NC}"
fi
echo ""
echo "    CSP編集: /etc/nginx/snippets/security-headers.conf"
echo "    反映:    sudo nginx -t && sudo systemctl reload nginx"
echo ""
echo "  ★ このスクリプトは冪等です。設定変更後の再実行も安全です"
echo "=============================================="
