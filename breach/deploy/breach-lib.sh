# breach-exit shared helpers (sourced by entrypoint/provision/remove/list).
# The client registry $CONF_DIR/clients is the source of truth — one TSV line
# per user: name <TAB> wg_pubkey <TAB> wg_ip <TAB> hy2_password
# (wg_pubkey/wg_ip empty if WG off; hy2_password empty if Hy2 off).
# wg0.conf and hy2_users are regenerated from it.
TAB="$(printf '\t')"

# Highest 10.9.0.x in the registry (server is .1).
registry_max_ip() {
  awk -F"$TAB" '{n=$3; sub(/.*\./,"",n); if (n+0>m) m=n+0} END{print m+0}' "$CONF_DIR/clients" 2>/dev/null
}

# Rewrite wg0.conf (interface + one [Peer] per registry entry that has a pubkey).
write_wg_conf() {
  [ -f "$CONF_DIR/server.key" ] || return 0
  psk="$(cat "$CONF_DIR/psk" 2>/dev/null)"
  { echo "[Interface]"; echo "PrivateKey = $(cat "$CONF_DIR/server.key")"; echo "ListenPort = ${WG_PORT:-51820}"; } > "$CONF_DIR/wg0.conf"
  [ -f "$CONF_DIR/clients" ] || return 0
  while IFS="$TAB" read -r name pub ip pw; do
    [ -z "$pub" ] && continue
    { echo; echo "# $name"; echo "[Peer]"; echo "PublicKey = $pub"; echo "PresharedKey = $psk"; echo "AllowedIPs = $ip/32"; } >> "$CONF_DIR/wg0.conf"
  done < "$CONF_DIR/clients"
  # A while-read loop ends with read's non-zero EOF status; return 0 so a caller
  # under `set -e` (e.g. provision-client) is not killed before its next step.
  return 0
}

# Rewrite hy2_users (one password per registry entry that has one).
write_hy2_users() {
  : > "$CONF_DIR/hy2_users"
  [ -f "$CONF_DIR/clients" ] || return 0
  while IFS="$TAB" read -r name pub ip pw; do
    [ -n "$pw" ] && printf '%s\n' "$pw" >> "$CONF_DIR/hy2_users"
  done < "$CONF_DIR/clients"
  return 0 # see write_wg_conf: don't leak the loop's EOF status under `set -e`
}

# Reload sing-box with the current hy2_users (auto-restart wrapper relaunches it).
reload_hy2() {
  [ -f "$CONF_DIR/cert.pem" ] || return 0
  rebuild-singbox.sh
  pkill -f 'sing-box run' 2>/dev/null || true
}

# Funnel WG egress (10.9.0.0/24) into sing-box's tun. MUST be re-run after every
# sing-box (re)start: singtun is recreated each time, and the table-100 route dies
# with the old device. The ip rule survives; only the route needs re-adding.
wire_wg_gateway() {
  i=0
  while [ "$i" -lt 30 ] && ! ip link show singtun >/dev/null 2>&1; do sleep 0.3; i=$((i + 1)); done
  ip link show singtun >/dev/null 2>&1 || { echo "WARN: singtun not up; WG egress not wired"; return 1; }
  ip rule list 2>/dev/null | grep -q "from 10.9.0.0/24 lookup 100" || ip rule add from 10.9.0.0/24 table 100
  ip route replace default dev singtun table 100
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
    || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
}
