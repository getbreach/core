#!/bin/sh
# provision-client — register a NEW user on a running breach-exit and print its
# client block. Run via: docker exec breach-exit provision-client [name]
#
# Generates this user's own WireGuard keypair + next free 10.9.0.x AND its own
# Hysteria2 password, records it in the client registry, applies it live (WG peer
# added hot, Hy2 reloaded — no container restart), and emits one combined block
# the app maps onto a single ServerConfig (both wireguard.* and hysteria2.*).
set -eu

CONF_DIR="${CONF_DIR:-/etc/breach}"
WG_PORT="${WG_PORT:-51820}"
. /usr/local/bin/breach-lib.sh
NAME="${1:-client}"
umask 077
touch "$CONF_DIR/clients"

PUBLIC_ENDPOINT="$(awk -F= '/^PUBLIC_ENDPOINT=/{print $2}' "$CONF_DIR/meta" 2>/dev/null)"
HY2_SNI="$(awk -F= '/^HY2_SNI=/{print $2}' "$CONF_DIR/meta" 2>/dev/null)"
[ -z "$PUBLIC_ENDPOINT" ] && PUBLIC_ENDPOINT="YOUR_VPS_IP:48000"
[ -z "$HY2_SNI" ] && HY2_SNI="www.bing.com"

# Reject a duplicate name (would confuse remove/list).
if awk -F"$TAB" -v n="$NAME" '$1==n{found=1} END{exit !found}' "$CONF_DIR/clients"; then
  echo "client '$NAME' already exists" >&2; exit 1
fi

WG_JSON='null'
HY2_JSON='null'
CLIENT_PRIV=""; CLIENT_PUB=""; ip4=""; HY2_PW=""

if [ -f "$CONF_DIR/server.key" ]; then
  SRV_PUB="$(wg pubkey < "$CONF_DIR/server.key")"
  PSK="$(cat "$CONF_DIR/psk" 2>/dev/null)"; [ -z "$PSK" ] && { PSK="$(wg genpsk)"; printf '%s\n' "$PSK" > "$CONF_DIR/psk"; }
  CLIENT_PRIV="$(wg genkey)"
  CLIENT_PUB="$(printf '%s' "$CLIENT_PRIV" | wg pubkey)"
  ip4="10.9.0.$(( $(registry_max_ip) > 1 ? $(registry_max_ip) + 1 : 2 ))"
  WG_JSON="{\"privateKey\":\"$CLIENT_PRIV\",\"peerPublicKey\":\"$SRV_PUB\",\"presharedKey\":\"$PSK\",\"address\":\"$ip4/32\"}"
fi

# One secret serves both Hysteria2 and stream mode: each authenticates against
# field 4 of the registry, so a client provisioned on an exit running both gets
# a single password that works either way.
SOCKS_JSON='null'
if [ -f "$CONF_DIR/cert.pem" ] || [ -f "$CONF_DIR/qtun-pin" ]; then
  HY2_PW="$(openssl rand -base64 18 | tr -d '\n/+=')"
fi
# Stream mode authenticates on the same field, so the password must exist even
# when Hysteria2 is off.
if [ -z "$HY2_PW" ] && pgrep -f 'breach-server .*-socks ' >/dev/null 2>&1; then
  HY2_PW="$(openssl rand -base64 18 | tr -d '\n/+=')"
fi
if [ -f "$CONF_DIR/cert.pem" ]; then
  HY2_JSON="{\"password\":\"$HY2_PW\",\"sni\":\"$HY2_SNI\",\"insecure\":true,\"alpn\":[\"h3\"]}"
fi
# The pin is what lets a client verify the exit; without it the client still
# connects but cannot tell the exit from an impostor, and says so.
#
# Gated on stream mode being live NOW, not merely on the pin file: it survives in
# the volume after PROTO stops including socks, and a client handed a socks5
# block for an exit that no longer answers it just fails with no explanation.
SOCKS_LIVE=0
if [ -f "$CONF_DIR/qtun-pin" ] && pgrep -f 'breach-server .*-socks ' >/dev/null 2>&1; then
  SOCKS_LIVE=1
fi
if [ "$SOCKS_LIVE" = 1 ]; then
  SOCKS_JSON="{\"token\":\"$HY2_PW\",\"certSha256\":\"$(cat "$CONF_DIR/qtun-pin")\"}"
fi

# Append to the registry, then regenerate the live config from it.
printf '%s\t%s\t%s\t%s\n' "$NAME" "$CLIENT_PUB" "$ip4" "$HY2_PW" >> "$CONF_DIR/clients"

if [ -n "$CLIENT_PUB" ]; then
  # The registry can hold WireGuard state from an earlier PROTO while wg0 is not
  # up (the operator narrowed PROTO to hy2,socks). Applying the peer is then
  # impossible but not fatal: the config is still written, and the peer becomes
  # live if WireGuard is switched back on. Without the guard `set -e` aborted the
  # script here and no client block was ever printed.
  printf '%s\n' "$PSK" > /tmp/psk.$$
  if ip link show wg0 >/dev/null 2>&1; then
    wg set wg0 peer "$CLIENT_PUB" preshared-key /tmp/psk.$$ allowed-ips "$ip4/32" || true
  else
    echo "note: wg0 is not up (PROTO has no wg); recorded the peer without applying it" >&2
  fi
  rm -f /tmp/psk.$$
  write_wg_conf
fi
if [ -n "$HY2_PW" ] && [ -f "$CONF_DIR/cert.pem" ]; then write_hy2_users; reload_hy2; fi

echo "===BREACH-CLIENT-CONFIG-BEGIN==="
echo "{\"name\":\"$NAME\",\"server\":\"$PUBLIC_ENDPOINT\",\"wireguard\":$WG_JSON,\"hysteria2\":$HY2_JSON,\"socks5\":$SOCKS_JSON}"
echo "===BREACH-CLIENT-CONFIG-END==="
