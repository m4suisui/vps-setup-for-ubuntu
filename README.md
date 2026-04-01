# vps-setup

One-command security hardening for Ubuntu 22.04 / 24.04 / 26.04 LTS VPS.

## Overview

```
Local Machine                        VPS (fresh)
─────────────                        ──────────────────

1. cat ~/.ssh/id_ed25519.pub
   → copy the output

2. ssh root@SERVER_IP ────────────→  logged in

                                     3. curl -sL https://github.com/m4suisui/vps-setup/archive/main.tar.gz | tar xz
                                        cd vps-setup-main

                                     4. (if using nginx: edit DOMAIN etc. in nginx-hardening.sh)

                                     5. bash setup.sh --user deploy --pubkey "paste-your-key-here" [--nginx]
                                        ├─ [1] init-user.sh       create user + deploy SSH key
                                        ├─ [2] vps-hardening.sh   harden OS
                                        ├─ [3] nginx-hardening.sh (--nginx only, off by default)
                                        └─ [4] verify.sh          PASS/FAIL all settings

                                     6. exit

7. ssh deploy@SERVER_IP ──────────→  from now on, use this
                                     (root login is disabled)
```

No SSH key yet? Run `ssh-keygen -t ed25519` once on your local machine. One key for life, reuse it across servers.

## What Gets Hardened

**OS Base** (`vps-hardening.sh`)
- SSH: key-only auth, root login disabled, brute-force protection
- Firewall: UFW deny-all incoming, SSH only
- Kernel: SYN flood protection, ICMP hardening, source routing disabled
- fail2ban: SSH jail (24h ban)
- auditd: monitors /etc/shadow, sshd_config, sudo usage, cron
- Auto-updates: unattended security patches
- Extras: core dumps disabled, USB storage disabled, MOTD stripped

**Nginx** (`nginx-hardening.sh`) — edit config section before running
- TLS 1.2+1.3 only, strong ciphers, HSTS, OCSP stapling
- Security headers: CSP, X-Frame-Options, CORP, COOP
- Rate limiting (429) + fail2ban auto-ban
- Default server drops unknown hosts (SNI bypass prevention)
- Attack path blocking (wp-admin, .env, .git, etc.)
- Let's Encrypt auto-renewal

## Nginx Configuration

Edit the top of `nginx-hardening.sh` before running:

```bash
DOMAIN="example.com"
APP_PORT="3000"
CERT_EMAIL="you@example.com"
```

## Verify Anytime

```bash
sudo bash verify.sh           # OS base
sudo bash verify.sh --nginx   # OS + nginx
```

## Files

| File | Purpose |
|---|---|
| `setup.sh` | Orchestrator — runs everything in order |
| `init-user.sh` | Creates sudo user with SSH key |
| `vps-hardening.sh` | OS-level hardening |
| `nginx-hardening.sh` | Nginx hardening |
| `verify.sh` | PASS/FAIL verification of all settings |

All scripts are idempotent — safe to re-run.
