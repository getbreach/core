#!/bin/sh
# stats — JSON snapshot for the admin app: per-client traffic + online state,
# joined from the client registry plus host load.
#   { "server":{"load1":..,"memTotalKb":..,"memAvailKb":..,"uptimeSec":..},
#     "clients":[{"name","address","rx","tx","handshake","online"}, ...] }
#
# Two sources, summed per client:
#   WireGuard — `wg show wg0 dump` (rx/tx and a real handshake timestamp)
#   Hysteria2 — $CONF_DIR/hy2_stats, kept by breach-mgmt from sing-box's Clash
#               API ("name<TAB>up<TAB>down<TAB>lastSeen"). Absent when the image
#               was built without mgmt or MGMT_ENABLE=0, in which case Hy2
#               clients simply report zeros, as they always did.
# rx is client->internet, tx is internet->client, matching the WireGuard sense.
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
TAB="$(printf '\t')"
touch "$CONF_DIR/clients"

DUMP=""
if wg show wg0 dump > /tmp/wgdump 2>/dev/null; then DUMP=/tmp/wgdump; fi
HY2=""
if [ -f "$CONF_DIR/hy2_stats" ]; then HY2="$CONF_DIR/hy2_stats"; fi
NOW="$(date +%s)"

read -r LOAD1 _rest < /proc/loadavg
MEMTOTAL="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
MEMAVAIL="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
UPTIME="$(awk '{print int($1)}' /proc/uptime)"

CLIENTS="$(awk -F"$TAB" -v dump="$DUMP" -v hy2="$HY2" -v now="$NOW" '
  BEGIN {
    if (dump != "") {
      while ((getline line < dump) > 0) {
        n = split(line, f, "\t")
        if (n >= 8) { hs[f[1]] = f[5]; rx[f[1]] = f[6]; tx[f[1]] = f[7] }
      }
    }
    # Hy2 totals are keyed by client NAME (WireGuard keys by pubkey).
    if (hy2 != "") {
      while ((getline line < hy2) > 0) {
        n = split(line, g, "\t")
        if (n >= 4 && g[1] != "") { hup[g[1]] = g[2]; hdown[g[1]] = g[3]; hseen[g[1]] = g[4] }
      }
    }
  }
  $1 == "" { next }
  {
    pub = $2; h = (pub in hs) ? hs[pub] : 0
    r = (pub in rx) ? rx[pub] : 0; t = (pub in tx) ? tx[pub] : 0
    # A client may run both protocols; report the sum.
    r += ($1 in hup) ? hup[$1] : 0
    t += ($1 in hdown) ? hdown[$1] : 0
    hsn = ($1 in hseen) ? hseen[$1] : 0
    wgOn  = (h > 0 && now - h < 180)
    hy2On = (hsn > 0 && now - hsn < 180)
    online = (wgOn || hy2On) ? "true" : "false"
    # Surface whichever liveness stamp is fresher, so the app can show "last seen"
    # for an Hy2-only client instead of a permanent 0.
    seen = (hsn > h) ? hsn : h
    # %.0f, not %d: busybox awk truncates %d to 32 bits, so a client past 2 GiB
    # would report a NEGATIVE byte count -- and Hy2 totals are persisted, so the
    # wrong number would never heal. %.0f is exact to 2^53.
    nm = $1; gsub(/\\/, "\\\\", nm); gsub(/"/, "\\\"", nm)
    ad = $3; gsub(/\\/, "\\\\", ad); gsub(/"/, "\\\"", ad)
    printf "%s{\"name\":\"%s\",\"address\":\"%s\",\"rx\":%.0f,\"tx\":%.0f,\"handshake\":%d,\"online\":%s}", \
      sep, nm, ad, r, t, seen, online
    sep = ","
  }
' "$CONF_DIR/clients")"

printf '{"server":{"load1":%s,"memTotalKb":%s,"memAvailKb":%s,"uptimeSec":%s},"clients":[%s]}\n' \
  "${LOAD1:-0}" "${MEMTOTAL:-0}" "${MEMAVAIL:-0}" "${UPTIME:-0}" "$CLIENTS"
