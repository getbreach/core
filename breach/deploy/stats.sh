#!/bin/sh
# stats — JSON snapshot for the admin app: per-client WireGuard traffic + online
# state (joined from `wg show wg0 dump` and the client registry) plus host load.
# Hysteria2 per-user traffic isn't included yet (needs the sing-box stats API).
#   { "server":{"load1":..,"memTotalKb":..,"memAvailKb":..,"uptimeSec":..},
#     "clients":[{"name","address","rx","tx","handshake","online"}, ...] }
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
TAB="$(printf '\t')"
touch "$CONF_DIR/clients"

DUMP=""
if wg show wg0 dump > /tmp/wgdump 2>/dev/null; then DUMP=/tmp/wgdump; fi
NOW="$(date +%s)"

read -r LOAD1 _rest < /proc/loadavg
MEMTOTAL="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
MEMAVAIL="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
UPTIME="$(awk '{print int($1)}' /proc/uptime)"

CLIENTS="$(awk -F"$TAB" -v dump="$DUMP" -v now="$NOW" '
  BEGIN {
    if (dump != "") {
      while ((getline line < dump) > 0) {
        n = split(line, f, "\t")
        if (n >= 8) { hs[f[1]] = f[5]; rx[f[1]] = f[6]; tx[f[1]] = f[7] }
      }
    }
  }
  $1 == "" { next }
  {
    pub = $2; h = (pub in hs) ? hs[pub] : 0
    r = (pub in rx) ? rx[pub] : 0; t = (pub in tx) ? tx[pub] : 0
    online = (h > 0 && now - h < 180) ? "true" : "false"
    printf "%s{\"name\":\"%s\",\"address\":\"%s\",\"rx\":%d,\"tx\":%d,\"handshake\":%d,\"online\":%s}", \
      sep, $1, $3, r, t, h, online
    sep = ","
  }
' "$CONF_DIR/clients")"

printf '{"server":{"load1":%s,"memTotalKb":%s,"memAvailKb":%s,"uptimeSec":%s},"clients":[%s]}\n' \
  "${LOAD1:-0}" "${MEMTOTAL:-0}" "${MEMAVAIL:-0}" "${UPTIME:-0}" "$CLIENTS"
