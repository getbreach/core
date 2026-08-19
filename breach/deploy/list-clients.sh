#!/bin/sh
# list-clients — print the registered users as a JSON array (no secrets):
#   [{"name":"phoneA","address":"10.9.0.2","wg":true,"hy2":true}, ...]
set -eu
CONF_DIR="${CONF_DIR:-/etc/breach}"
TAB="$(printf '\t')"
touch "$CONF_DIR/clients"
awk -F"$TAB" 'BEGIN{ printf "[" ; sep="" }
  { printf "%s{\"name\":\"%s\",\"address\":\"%s\",\"wg\":%s,\"hy2\":%s}", \
      sep, $1, $3, ($2==""?"false":"true"), ($4==""?"false":"true"); sep="," }
  END{ print "]" }' "$CONF_DIR/clients"
