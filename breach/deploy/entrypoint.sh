#!/bin/sh
# breach-exit entrypoint (persistent, multi-user).
#
# Runs the MAX-TURN relay front (breach-server) plus both inner-protocol servers.
# breach-server dispatches each client to the right backend by sniffing its first
# packet, so a single public UDP port serves BOTH protocols and MANY users at
# once — each user with its OWN WireGuard keypair+IP and its OWN Hysteria2
# password. Manage users with:
#   docker exec breach-exit provision-client <name>   # add, prints client block
#   docker exec breach-exit list-clients              # JSON list
#   docker exec breach-exit remove-client <name>      # revoke
#
# State lives in $CONF_DIR (mount a volume there to survive restarts). The client
# registry $CONF_DIR/clients is authoritative; wg0.conf + hy2_users are derived.
#
#   wg  -> userspace wireguard-go (needs --cap-add NET_ADMIN --device /dev/net/tun
#          --sysctl net.ipv4.ip_forward=1)
#   hy2 -> sing-box hysteria2 server
#
# Env (only SEED a fresh state dir; ignored once state exists):
#   PROTO both|wg|hy2 (default both)   LOG_LEVEL info|debug|trace
#   RELAY_LISTEN :48000   KEEPALIVE_MS 50   PUBLIC_ENDPOINT <auto>:48000
#   WG_SERVER_PRIVKEY  WG_PSK  WG_PEERS(seed pubkeys)  HY2_PASSWORD(seed)  HY2_SNI
set -eu

PROTO="${PROTO:-both}"
LOG_LEVEL="${LOG_LEVEL:-info}"
RELAY_LISTEN="${RELAY_LISTEN:-:48000}"
KEEPALIVE_MS="${KEEPALIVE_MS:-50}"
WG_PORT=51820
HY2_PORT=51821
# sing-box's Clash API (per-user Hy2 traffic/online state), loopback only. Fixed
# like the two above so it can never collide with an operator-set RELAY_PORT or
# MGMT_PORT; breach-mgmt is told the same value below.
CLASH_PORT=51822
CONF_DIR="${CONF_DIR:-/etc/breach}"
mkdir -p "$CONF_DIR"
export CONF_DIR WG_PORT HY2_PORT CLASH_PORT LOG_LEVEL
. /usr/local/bin/breach-lib.sh

case "$PROTO" in both) DO_WG=1; DO_HY2=1;; wg) DO_WG=1; DO_HY2=0;; hy2) DO_WG=0; DO_HY2=1;;
  *) echo "unknown PROTO=$PROTO (want both|wg|hy2)" >&2; exit 1;; esac

DEV="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"; [ -z "$DEV" ] && DEV=eth0

if [ -z "${PUBLIC_ENDPOINT:-}" ]; then
  IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"; [ -z "$IP" ] && IP="YOUR_VPS_IP"
  PUBLIC_ENDPOINT="${IP}:${RELAY_LISTEN##*:}"
fi
[ -f "$CONF_DIR/meta" ] || { echo "PUBLIC_ENDPOINT=$PUBLIC_ENDPOINT"; echo "HY2_SNI=${HY2_SNI:-www.bing.com}"; } > "$CONF_DIR/meta"

umask 077
touch "$CONF_DIR/clients"

# ---- one-time server identity (kept across restarts via the volume) ----------
if [ "$DO_WG" = 1 ] && [ ! -f "$CONF_DIR/server.key" ]; then
  if [ -n "${WG_SERVER_PRIVKEY:-}" ]; then printf '%s\n' "$WG_SERVER_PRIVKEY" > "$CONF_DIR/server.key"
  else wg genkey > "$CONF_DIR/server.key"; fi
  printf '%s\n' "${WG_PSK:-$(wg genpsk)}" > "$CONF_DIR/psk"
  if [ -n "${WG_PEERS:-}" ]; then
    n=2
    for pub in $(echo "$WG_PEERS" | tr ',' ' '); do
      [ -z "$pub" ] && continue
      printf 'seed%s\t%s\t10.9.0.%s\t\n' "$n" "$pub" "$n" >> "$CONF_DIR/clients"; n=$((n+1))
    done
  fi
fi

if [ "$DO_HY2" = 1 ] && [ ! -f "$CONF_DIR/cert.pem" ]; then
  HY2_SNI="${HY2_SNI:-www.bing.com}"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CONF_DIR/key.pem" -out "$CONF_DIR/cert.pem" -days 3650 -nodes -subj "/CN=$HY2_SNI" >/dev/null 2>&1
  [ -n "${HY2_PASSWORD:-}" ] && printf 'hy2seed\t\t\t%s\n' "$HY2_PASSWORD" >> "$CONF_DIR/clients"
fi

PIDS=""
# breach-server's -wg defaults to 127.0.0.1:51820, so NOT passing the flag leaves
# a phantom WireGuard backend enabled on a hy2-only exit: the banner advertises
# it and a non-QUIC first packet gets dispatched to a port nothing listens on.
# "-wg=" is one word (survives the unquoted splice below) and parses as empty,
# which disables the backend outright. The DO_WG branch overrides it.
WG_FLAG="-wg="
HY2_FLAG=""

# ---- WireGuard bring-up (config derived from the registry) -------------------
if [ "$DO_WG" = 1 ]; then
  write_wg_conf
  ip link del wg0 2>/dev/null || true
  WGGO_LOG="error"; case "$LOG_LEVEL" in debug|trace) WGGO_LOG="verbose";; esac
  LOG_LEVEL="$WGGO_LOG" wireguard-go --foreground wg0 & WGGO=$!; PIDS="$PIDS $WGGO"
  for _ in 1 2 3 4 5 6 7 8 9 10; do ip link show wg0 >/dev/null 2>&1 && break; sleep 0.3; done
  wg setconf wg0 "$CONF_DIR/wg0.conf"
  ip addr add 10.9.0.1/24 dev wg0 2>/dev/null || true
  ip link set wg0 up
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || ( echo 1 > /proc/sys/net/ipv4/ip_forward ) 2>/dev/null || true
  [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = 1 ] || echo "WARN: ip_forward=0 — add --sysctl net.ipv4.ip_forward=1"
  iptables -P FORWARD ACCEPT 2>/dev/null || true
  # WG egress is governed by sing-box (its tun); the policy route is wired up
  # after sing-box has created singtun (below).
  WG_FLAG="-wg 127.0.0.1:$WG_PORT"
fi

# ---- sing-box: hy2 server + WG egress gateway (tun) + admin route rules ------
# The WG policy route is (re)wired after EVERY sing-box start, because singtun is
# recreated on each (re)start/reload and the table-100 route dies with it.
if [ "$DO_HY2" = 1 ] || [ "$DO_WG" = 1 ]; then
  [ "$DO_HY2" = 1 ] && write_hy2_users
  rebuild-singbox.sh
  (
    while :; do
      sing-box run -c "$CONF_DIR/singbox.json" &
      sbpid=$!
      [ "$DO_WG" = 1 ] && wire_wg_gateway || true
      wait "$sbpid"
      sleep 1
    done
  ) & SBW=$!; PIDS="$PIDS $SBW"
  [ "$DO_HY2" = 1 ] && HY2_FLAG="-hy2 127.0.0.1:$HY2_PORT"
fi

echo "breach-exit: PROTO=$PROTO relay=$RELAY_LISTEN endpoint=$PUBLIC_ENDPOINT dev=$DEV (state=$CONF_DIR)"

# ---- management API (optional) ----------------------------------------------
# breach-mgmt is a fixed-verb HTTPS wrapper over provision/list/remove/stats,
# guarded by a per-server secret + pinned self-signed TLS, so the app can manage
# the exit after install WITHOUT keeping SSH root creds. It is present only when
# the image was built with --build-arg MGMT=1, and started only when
# MGMT_ENABLE!=0. It listens on TCP (same port number as the UDP relay by
# default) but is reachable from outside ONLY if that TCP port is published
# (docker-compose maps it). Restart-supervised in its own subshell so a mgmt
# crash self-heals instead of taking the whole exit down. On start it prints a
# ===BREACH-MGMT-BEGIN===/END=== handle block (install.sh slices it from logs).
if command -v breach-mgmt >/dev/null 2>&1 && [ "${MGMT_ENABLE:-1}" != 0 ]; then
  MGMT_LISTEN="${MGMT_LISTEN:-:${RELAY_LISTEN##*:}}"
  MGMT_HOST="${PUBLIC_ENDPOINT%:*}"
  (
    while :; do
      breach-mgmt -listen "$MGMT_LISTEN" -conf-dir "$CONF_DIR" -advertise-host "$MGMT_HOST" \
        -clash-port "$CLASH_PORT" || true
      sleep 2
    done
  ) & MGW=$!; PIDS="$PIDS $MGW"
fi

# shellcheck disable=SC2086
breach-server -listen "$RELAY_LISTEN" $WG_FLAG $HY2_FLAG -keepalive-ms "$KEEPALIVE_MS" & MT=$!; PIDS="$PIDS $MT"

trap 'kill $PIDS 2>/dev/null || true' TERM INT
while :; do
  for p in $PIDS; do
    kill -0 "$p" 2>/dev/null || { echo "process $p exited"; kill $PIDS 2>/dev/null || true; exit 1; }
  done
  sleep 2
done
