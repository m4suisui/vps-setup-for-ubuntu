# vps-setup

One-command security hardening for Ubuntu 22.04 / 24.04 / 26.04 LTS VPS.

## Quick Start

**1. On your PC** — copy your public key, then log in to the new VPS as root

```bash
cat ~/.ssh/id_ed25519.pub      # no key yet? run: ssh-keygen -t ed25519
ssh root@SERVER_IP
```

**2. On the VPS** — download and run

```bash
curl -sL https://github.com/m4suisui/vps-setup-for-ubuntu/archive/main.tar.gz | tar xz
cd vps-setup-for-ubuntu-main
bash setup.sh --user deploy --pubkey "PASTE_YOUR_KEY_HERE"
```

**3. On your PC** — keep the root session open, and log in from a new terminal

```bash
ssh deploy@SERVER_IP
```

Logged in? Done. From now on use `deploy` (root login is disabled).

> Using nginx? Edit `DOMAIN` etc. at the top of `nginx-hardening.sh`, then add `--nginx` to the `setup.sh` command.

`setup.sh` runs, in order: `init-user.sh` (user + SSH key) → `vps-hardening.sh` (OS hardening) → `nginx-hardening.sh` (`--nginx` only) → `verify.sh` (PASS/FAIL check).

## What Gets Hardened

**OS Base** (`vps-hardening.sh`)
- SSH: key-only auth, root login disabled, brute-force protection
- Firewall: UFW deny-all incoming, SSH only
- Kernel: SYN flood protection, ICMP hardening, source routing disabled
- fail2ban: SSH jail (24h ban)
- auditd: monitors /etc/shadow, sshd_config, sudo usage, cron
- Auto-updates: unattended security patches, automatic reboot at 04:00 when required
  (set `AUTO_REBOOT=false` in `vps-hardening.sh` to disable)
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

### SSH public key validation

Keep `lib/ssh-keys.sh` alongside the scripts when copying them to a server.
`ssh-keygen` (Ubuntu's `openssh-client` package) must be available before running
user initialization, hardening, or verification. These scripts fail closed if
OpenSSH cannot parse a public key. Initialization accepts one key line, validates
it before changing users or `authorized_keys`, and detects duplicates by SHA256
fingerprint even when comments differ. Existing lines are preserved.

Hardening and verification parse existing `authorized_keys` lines individually
and require at least one parseable key for a sudo user. This is a syntax check;
confirm an actual SSH login before closing the current session, since key
options, server policy, and possession of the corresponding private key can
still affect access.

Run the isolated regression tests (Python 3 and OpenSSH required):

```bash
python3 -m unittest discover -s tests -v
```

The tests generate temporary Ed25519, RSA, and ECDSA keys and execute the relevant
script sections with mocked account operations. They do not modify system users
or SSH configuration.
