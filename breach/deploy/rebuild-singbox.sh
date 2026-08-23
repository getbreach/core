#!/bin/sh
# Write $CONF_DIR/singbox.json from persisted state:
#   - hysteria2 inbound (users from hy2_users)
#   - tun inbound "wg-tun" (only if WG enabled) so WireGuard egress is governed by
#     the SAME route engine — the entrypoint policy-routes 10.9.0.0/24 into it
#   - outbounds: direct + block
#   - route: from $CONF_DIR/routes.json (admin server rules) or passthrough default
# Shared by the entrypoint (boot), provision-client/remove-client (Hy2 reload),
# and set-routes (rule changes).
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
HY2_PORT="${HY2_PORT:-51821}"
LOG_LEVEL="${LOG_LEVEL:-info}"
# This script does NOT source breach-lib.sh (it runs standalone from the image),
# so it defines its own TAB.
TAB="$(printf '\t')"

# hy2_users is "name<TAB>password" (older volumes: password only, no tab). The
# name is what lets sing-box attribute traffic to a user; auth uses the password.
# Read with `IFS=` + case/expr rather than `IFS="$TAB" read a b`: a tab is an IFS
# whitespace char, so that form collapses runs of tabs and silently mangles rows
# (see the same trap documented in breach-lib.sh).
users=""
if [ -f "$CONF_DIR/hy2_users" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
      *"$TAB"*) name="${line%%"$TAB"*}"; pw="${line#*"$TAB"}" ;;
      *)        name=""; pw="$line" ;;
    esac
    [ -z "$pw" ] && continue
    # Names come from the registry; keep JSON well-formed even if one has a quote.
    name="$(printf '%s' "$name" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    users="${users:+$users, }{ \"name\": \"$name\", \"password\": \"$pw\" }"
  done < "$CONF_DIR/hy2_users"
fi
[ -z "$users" ] && users="{ \"password\": \"__none__\" }"

# Clash API on loopback: the ONLY way to get per-user Hy2 traffic + online state
# out of sing-box. breach-mgmt polls it and accumulates totals. The secret is
# generated once and kept in the state dir; the controller stays on 127.0.0.1
# because the API defaults to CORS "*" and the secret is its only guard.
if [ ! -s "$CONF_DIR/clash-secret" ]; then
  (umask 077; openssl rand -base64 18 | tr -d '\n/+=' > "$CONF_DIR/clash-secret")
fi
# Fail closed: an empty secret would leave the control API UNAUTHENTICATED, and
# the exit would otherwise come up looking perfectly healthy.
[ -s "$CONF_DIR/clash-secret" ] || { echo "FATAL: could not generate the Clash API secret (openssl missing?)" >&2; exit 1; }
CLASH_SECRET="$(cat "$CONF_DIR/clash-secret")"
# Fixed internal port, like WG_PORT/HY2_PORT — deliberately NOT operator-settable
# via .env, so it can never collide with RELAY_PORT/MGMT_PORT. The entrypoint
# exports it and passes the same value to breach-mgmt.
CLASH_PORT="${CLASH_PORT:-51822}"

HY2_IN=""
if [ -f "$CONF_DIR/cert.pem" ]; then
  HY2_IN="{ \"type\": \"hysteria2\", \"tag\": \"hy2-in\", \"listen\": \"127.0.0.1\", \"listen_port\": $HY2_PORT, \"users\": [ $users ], \"tls\": { \"enabled\": true, \"alpn\": [\"h3\"], \"certificate_path\": \"$CONF_DIR/cert.pem\", \"key_path\": \"$CONF_DIR/key.pem\" } }"
fi

# WireGuard egress is funnelled through this tun (entrypoint sets up the policy route).
WG_TUN=""
if [ -f "$CONF_DIR/server.key" ]; then
  WG_TUN="{ \"type\": \"tun\", \"tag\": \"wg-tun\", \"interface_name\": \"singtun\", \"address\": [\"172.31.0.1/30\"], \"mtu\": 1400, \"auto_route\": false, \"strict_route\": false, \"stack\": \"gvisor\" }"
fi

# Comma-join the present inbounds.
INBOUNDS=""
for x in "$WG_TUN" "$HY2_IN"; do [ -n "$x" ] && INBOUNDS="${INBOUNDS:+$INBOUNDS, }$x"; done

# Admin route rules, or passthrough.
# Default route rejects private destinations. Loopback is NOT a boundary here:
# an authenticated Hy2 client could otherwise ask the exit's own `direct`
# outbound to reach 127.0.0.1 (the Clash API), the docker bridge, or the host's
# LAN. A public exit has no business proxying RFC1918/loopback anyway. An admin
# who needs it can override the whole object with set-routes.
if [ -f "$CONF_DIR/routes.json" ]; then ROUTE="$(cat "$CONF_DIR/routes.json")"; else ROUTE='{ "rules": [ { "ip_is_private": true, "action": "reject" } ], "final": "direct", "auto_detect_interface": true }'; fi

cat > "$CONF_DIR/singbox.json" <<EOF
{
  "log": { "level": "$LOG_LEVEL" },
  "inbounds": [ $INBOUNDS ],
  "outbounds": [ { "type": "direct", "tag": "direct" }, { "type": "block", "tag": "block" } ],
  "route": $ROUTE,
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:$CLASH_PORT", "secret": "$CLASH_SECRET" }
  }
}
EOF
