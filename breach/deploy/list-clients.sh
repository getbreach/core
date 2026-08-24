#!/bin/sh
# list-clients — print the registered users as a JSON array (no secrets):
#   [{"name":"phoneA","address":"10.9.0.2","wg":true,"hy2":true}, ...]
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
TAB="$(printf '\t')"
touch "$CONF_DIR/clients"
# Field 4 is one shared secret: Hysteria2 and stream mode both authenticate on
# it, so it cannot say WHICH the exit serves. Report what the exit is actually
# running instead of guessing from the registry — otherwise a PROTO=socks exit
# lists every client as "hy2":true and the app offers a protocol that is not
# there.
#
# A blank registry line would otherwise emit a bogus {"name":""} entry, and a
# name holding a quote/backslash would make the whole array invalid JSON — which
# the mgmt API rejects wholesale, blanking the app's client list.
HAS_HY2=0; [ -f "$CONF_DIR/cert.pem" ] && HAS_HY2=1
HAS_SOCKS=0; pgrep -f 'breach-server .*-socks ' >/dev/null 2>&1 && HAS_SOCKS=1
awk -F"$TAB" -v hasHy2="$HAS_HY2" -v hasSocks="$HAS_SOCKS" 'BEGIN{ printf "[" ; sep="" }
  $1 == "" { next }
  { nm = $1; gsub(/\\/, "\\\\", nm); gsub(/"/, "\\\"", nm)
    ad = $3; gsub(/\\/, "\\\\", ad); gsub(/"/, "\\\"", ad)
    hasSecret = ($4 != "")
    printf "%s{\"name\":\"%s\",\"address\":\"%s\",\"wg\":%s,\"hy2\":%s,\"socks\":%s}", \
      sep, nm, ad, ($2==""?"false":"true"),
      ((hasSecret && hasHy2=="1")?"true":"false"),
      ((hasSecret && hasSocks=="1")?"true":"false"); sep="," }
  END{ print "]" }' "$CONF_DIR/clients"
