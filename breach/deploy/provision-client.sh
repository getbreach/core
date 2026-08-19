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

if [ -f "$CONF_DIR/cert.pem" ]; then
  HY2_PW="$(openssl rand -base64 18 | tr -d '\n/+=')"
  HY2_JSON="{\"password\":\"$HY2_PW\",\"sni\":\"$HY2_SNI\",\"insecure\":true,\"alpn\":[\"h3\"]}"
fi

# Append to the registry, then regenerate the live config from it.
printf '%s\t%s\t%s\t%s\n' "$NAME" "$CLIENT_PUB" "$ip4" "$HY2_PW" >> "$CONF_DIR/clients"

if [ -n "$CLIENT_PUB" ]; then
  printf '%s\n' "$PSK" > /tmp/psk.$$; wg set wg0 peer "$CLIENT_PUB" preshared-key /tmp/psk.$$ allowed-ips "$ip4/32"; rm -f /tmp/psk.$$
  write_wg_conf
fi
if [ -n "$HY2_PW" ]; then write_hy2_users; reload_hy2; fi

echo "===BREACH-CLIENT-CONFIG-BEGIN==="
echo "{\"name\":\"$NAME\",\"server\":\"$PUBLIC_ENDPOINT\",\"wireguard\":$WG_JSON,\"hysteria2\":$HY2_JSON}"
echo "===BREACH-CLIENT-CONFIG-END==="
