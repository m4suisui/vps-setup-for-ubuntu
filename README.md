# vps-setup

One-command security hardening for Ubuntu 22.04 / 24.04 / 26.04 LTS VPS.

## Quick Start

**1. On your PC** — copy your public key, then log in to the new VPS as root

```bash
cat ~/.ssh/id_ed25519.pub      # no key yet? run: ssh-keygen -t ed25519
ssh root@SERVER_IP
```

**2. On the VPS** — run one line

```bash
curl -fsSL https://raw.githubusercontent.com/m4suisui/vps-setup-for-ubuntu/main/install.sh | bash -s -- --user deploy --pubkey "PASTE_YOUR_KEY_HERE"
```

**3. On your PC** — keep the root session open, and log in from a new terminal

```bash
ssh deploy@SERVER_IP
```

Logged in? Done. From now on use `deploy` (root login is disabled).

> Using nginx? Put the settings in front of `bash` and add `--nginx`:
> `... | DOMAIN=example.org CERT_EMAIL=you@example.org APP_PORT=3000 bash -s -- --user deploy --pubkey "..." --nginx`

The scripts stay in `/opt/vps-setup` (re-check anytime: `sudo bash /opt/vps-setup/verify.sh`).
`install.sh` runs `setup.sh`, which runs, in order: `init-user.sh` (user + SSH key) → `vps-hardening.sh` (OS hardening) → `nginx-hardening.sh` (`--nginx` only) → `verify.sh` (PASS/FAIL check).

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

**Nginx** (`nginx-hardening.sh`) — set DOMAIN / CERT_EMAIL first
- TLS 1.2+1.3 only, strong ciphers, HSTS, OCSP stapling
- Security headers: CSP, X-Frame-Options, CORP, COOP
- Rate limiting (429) + fail2ban auto-ban
- Default server drops unknown hosts (SNI bypass prevention)
- Attack path blocking (wp-admin, .env, .git, etc.)
- Let's Encrypt auto-renewal

## Nginx Configuration

Pass as environment variables (as in Quick Start), or edit the top of `nginx-hardening.sh`:

```bash
DOMAIN="example.org"          # required
CERT_EMAIL="you@example.org"  # required, Let's Encrypt notices
APP_PORT="3000"               # backend port, default 3000
```

The script stops if DOMAIN / CERT_EMAIL are left as placeholders.

## Verify Anytime

```bash
cd /opt/vps-setup                            # where install.sh put the scripts
sudo bash verify.sh                          # OS base
sudo bash verify.sh --nginx                  # OS + nginx
sudo bash verify.sh --allow-port 51820/udp   # also expose e.g. a WireGuard port
sudo bash verify.sh --sudo-users deploy      # only these accounts may have sudo
sudo bash verify.sh --quick                  # skip slow scans (~1 min)
```

`verify.sh` checks two things:

1. **Applied settings are in effect** — SSH (effective `sshd -T` values), UFW, sysctl,
   fail2ban (incl. that the jail actually reads logs), auto-updates (incl. timer,
   fresh package lists, pending reboot, OS support end date), auditd (every rule loaded).
2. **Nothing unexpected exists** — a setting can PASS while something extra is exposed:

| Check | Result if found |
|---|---|
| Port listening on a public address, not SSH / `--allow-port` / nginx | FAIL |
| UFW rule opening a non-allowlisted port to Anywhere | FAIL |
| Docker container publishing a port publicly (bypasses UFW) | FAIL |
| Extra UID 0 account, account with empty password | FAIL |
| `/etc/ld.so.preload` in use, process running from `/tmp` etc. | FAIL |
| SUID/SGID binary not from any package, modified package binary (`dpkg --verify`) | FAIL |
| Unexpected sudo members, direct sudoers grants, NOPASSWD | WARN |
| SSH keys on non-sudo accounts, system accounts with a shell | WARN |
| User crontabs, cron jobs / systemd units not from packages | WARN |
| Executables in temp dirs, processes running deleted binaries | WARN |

WARN items may be legitimate (your own worker service, cron job, ...); confirm each
once. Exit code is 1 only when a FAIL is found.

Ports can also be allowlisted with `VERIFY_ALLOWED_PORTS="51820/udp 8080/tcp"`.

## Files

| File | Purpose |
|---|---|
| `install.sh` | One-line installer — downloads to `/opt/vps-setup`, runs `setup.sh` |
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
