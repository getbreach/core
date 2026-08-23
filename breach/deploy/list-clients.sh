#!/bin/sh
# list-clients — print the registered users as a JSON array (no secrets):
#   [{"name":"phoneA","address":"10.9.0.2","wg":true,"hy2":true}, ...]
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
TAB="$(printf '\t')"
touch "$CONF_DIR/clients"
# A blank registry line would otherwise emit a bogus {"name":""} entry, and a
# name holding a quote/backslash would make the whole array invalid JSON — which
# the mgmt API rejects wholesale, blanking the app's client list.
awk -F"$TAB" 'BEGIN{ printf "[" ; sep="" }
  $1 == "" { next }
  { nm = $1; gsub(/\\/, "\\\\", nm); gsub(/"/, "\\\"", nm)
    ad = $3; gsub(/\\/, "\\\\", ad); gsub(/"/, "\\\"", ad)
    printf "%s{\"name\":\"%s\",\"address\":\"%s\",\"wg\":%s,\"hy2\":%s}", \
      sep, nm, ad, ($2==""?"false":"true"), ($4==""?"false":"true"); sep="," }
  END{ print "]" }' "$CONF_DIR/clients"
