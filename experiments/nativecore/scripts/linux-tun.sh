#!/bin/sh
# Compile as the invoking user; root is needed only for a fresh network namespace.
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" != Linux ]; then
  echo 'This test requires Linux, iproute2, util-linux and /dev/net/tun.' >&2
  exit 1
fi
command -v ip >/dev/null
command -v unshare >/dev/null
test -c /dev/net/tun
native_test_dir=$(mktemp -d)
trap 'rm -f "$native_test_dir/tun.test"; rmdir "$native_test_dir"' EXIT
go test -c -o "$native_test_dir/tun.test" ./integration
if [ "$(id -u)" = 0 ]; then
  env BREACH_NATIVE_TUN_TEST=1 unshare --net "$native_test_dir/tun.test" -test.run '^TestLinuxTUN$' -test.v -test.timeout 60s
else
  sudo env BREACH_NATIVE_TUN_TEST=1 unshare --net "$native_test_dir/tun.test" -test.run '^TestLinuxTUN$' -test.v -test.timeout 60s
fi
