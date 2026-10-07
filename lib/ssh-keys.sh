#!/usr/bin/env bash
# Parse one authorized_keys line with OpenSSH. A private temporary file avoids
# exposing key material in process arguments and is removed on every exit.
ssh_key_fingerprint() (
  local line="${1:-}" tmp result
  command -v ssh-keygen >/dev/null 2>&1 || return 1
  [[ -n "$line" && "$line" != *$'\n'* && "$line" != *$'\r'* ]] || return 1
  tmp=$(mktemp) || return 1
  trap 'rm -f -- "$tmp"' EXIT
  printf '%s\n' "$line" > "$tmp" || return 1
  result=$(ssh-keygen -l -E sha256 -f "$tmp" 2>/dev/null) || return 1
  [[ -n "$result" ]] || return 1
  printf '%s\n' "$result" | awk '{print $2}'
)

# Inspect each line independently: malformed existing lines must not hide a
# later valid key, and comments/blank lines must not satisfy the lockout guard.
ssh_keys_has_valid_key() {
  local file="$1" line
  [[ -r "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if ssh_key_fingerprint "$line" >/dev/null; then return 0; fi
  done < "$file"
  return 1
}

ssh_keys_contains_fingerprint() {
  local file="$1" wanted="$2" line fingerprint
  [[ -r "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if fingerprint=$(ssh_key_fingerprint "$line") && [[ "$fingerprint" == "$wanted" ]]; then
      return 0
    fi
  done < "$file"
  return 1
}
