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

users=""
if [ -f "$CONF_DIR/hy2_users" ]; then
  while IFS= read -r pw; do
    [ -z "$pw" ] && continue
    users="${users:+$users, }{ \"password\": \"$pw\" }"
  done < "$CONF_DIR/hy2_users"
fi
[ -z "$users" ] && users="{ \"password\": \"__none__\" }"

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
if [ -f "$CONF_DIR/routes.json" ]; then ROUTE="$(cat "$CONF_DIR/routes.json")"; else ROUTE='{ "rules": [], "final": "direct", "auto_detect_interface": true }'; fi

cat > "$CONF_DIR/singbox.json" <<EOF
{
  "log": { "level": "$LOG_LEVEL" },
  "inbounds": [ $INBOUNDS ],
  "outbounds": [ { "type": "direct", "tag": "direct" }, { "type": "block", "tag": "block" } ],
  "route": $ROUTE
}
EOF
