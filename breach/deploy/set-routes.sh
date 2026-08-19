#!/bin/sh
# set-routes — replace the exit's server-side routing policy.
#   set-routes <base64 of a sing-box "route" object>   -> apply
#   set-routes clear                                    -> passthrough (allow all)
# The route object governs BOTH protocols (WG via singtun, Hy2 via its inbound).
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
arg="${1:-}"
if [ "$arg" = "clear" ] || [ -z "$arg" ]; then
  rm -f "$CONF_DIR/routes.json"
else
  printf '%s' "$arg" | base64 -d > "$CONF_DIR/routes.json" 2>/dev/null || { echo "bad base64 route" >&2; exit 1; }
fi
rebuild-singbox.sh
pkill -f 'sing-box run' 2>/dev/null || true
echo "routes applied"
