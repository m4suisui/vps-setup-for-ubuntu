#!/usr/bin/env bash
# ============================================================
#  One-line installer
#
#  Usage (as root on the VPS):
#    curl -fsSL https://raw.githubusercontent.com/m4suisui/vps-setup-for-ubuntu/main/install.sh \
#      | bash -s -- --user deploy --pubkey "ssh-ed25519 AAAA..."
#
#  All arguments are passed to setup.sh. Environment variables
#  (DOMAIN, APP_PORT, CERT_EMAIL, VERIFY_ALLOWED_PORTS) are passed through too.
#
#  The scripts are kept in /opt/vps-setup so you can re-run verify.sh later:
#    sudo bash /opt/vps-setup/verify.sh
#
#  VPS_SETUP_REF=<tag or commit> pins the version (default: main).
# ============================================================
set -euo pipefail

# Everything runs inside main(), called on the last line, so bash has read the
# whole script from the pipe before any command executes.
main() {
  local repo="m4suisui/vps-setup-for-ubuntu"
  local ref="${VPS_SETUP_REF:-main}"
  local dest="/opt/vps-setup"
  local tmp rc

  if [[ $EUID -ne 0 ]]; then
    echo "[!] Must be run as root (pipe into 'sudo bash -s --' if needed)" >&2
    exit 1
  fi
  for cmd in curl tar; do
    command -v "${cmd}" >/dev/null || { echo "[!] ${cmd} is required" >&2; exit 1; }
  done

  tmp=$(mktemp -d)
  trap 'rm -rf -- "${tmp}"' EXIT

  echo "[i] Downloading ${repo}@${ref}"
  curl -fsSL "https://github.com/${repo}/archive/${ref}.tar.gz" \
    | tar xz -C "${tmp}" --strip-components=1

  [[ -f "${tmp}/setup.sh" ]] || { echo "[!] Download incomplete: setup.sh not found" >&2; exit 1; }

  # Replace the previous copy atomically-ish; scripts run as root, so root-only
  rm -rf -- "${dest}.new"
  cp -a "${tmp}" "${dest}.new"
  chmod 700 "${dest}.new"
  chown -R root:root "${dest}.new"
  rm -rf -- "${dest}"
  mv "${dest}.new" "${dest}"
  echo "[i] Installed to ${dest}"

  # stdin is the curl pipe; give setup.sh the terminal for its y/N prompts
  rc=0
  if ( : </dev/tty ) 2>/dev/null; then
    bash "${dest}/setup.sh" "$@" </dev/tty || rc=$?
  else
    bash "${dest}/setup.sh" "$@" </dev/null || rc=$?
  fi
  exit "${rc}"
}

main "$@"
