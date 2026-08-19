#!/bin/sh
# remove-client NAME — revoke a user: drop its WireGuard peer (live) and its
# Hysteria2 password, then regenerate config from the registry.
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
WG_PORT="${WG_PORT:-51820}"
. /usr/local/bin/breach-lib.sh
NAME="${1:?usage: remove-client NAME}"
touch "$CONF_DIR/clients"

if ! awk -F"$TAB" -v n="$NAME" '$1==n{f=1} END{exit !f}' "$CONF_DIR/clients"; then
  echo "no such client: $NAME" >&2; exit 1
fi

pub="$(awk -F"$TAB" -v n="$NAME" '$1==n{print $2}' "$CONF_DIR/clients")"
awk -F"$TAB" -v n="$NAME" '$1!=n' "$CONF_DIR/clients" > "$CONF_DIR/clients.tmp"
mv "$CONF_DIR/clients.tmp" "$CONF_DIR/clients"

[ -n "$pub" ] && wg set wg0 peer "$pub" remove 2>/dev/null || true
write_wg_conf
write_hy2_users
reload_hy2
echo "removed client: $NAME"
