#!/bin/sh
# Root tests use test routes, a scoped physical default, and .invalid DNS.
# It never changes the machine's default route or default DNS service.
set -eu
cd "$(dirname "$0")/.."
test "$(uname -s)" = Darwin
native_test_dir=$(mktemp -d)
trap 'rm -f "$native_test_dir/tun.test" "$native_test_dir/dns.test"; rmdir "$native_test_dir"' EXIT
go test -c -o "$native_test_dir/tun.test" ./integration
go test -c -o "$native_test_dir/dns.test" ./systemtun
if [ "$(id -u)" = 0 ]; then
  env BREACH_NATIVE_MAC_TUN_TEST=1 "$native_test_dir/tun.test" -test.run '^TestMacOSTUN$' -test.v -test.timeout 45s
  env BREACH_NATIVE_MAC_TUN_TEST=1 "$native_test_dir/dns.test" -test.run '^(TestTemporaryDNS|TestMacOSScopedBypass|TestRouteGuardianKernelCleanup)' -test.v -test.timeout 60s
else
  sudo env BREACH_NATIVE_MAC_TUN_TEST=1 "$native_test_dir/tun.test" -test.run '^TestMacOSTUN$' -test.v -test.timeout 45s
  sudo env BREACH_NATIVE_MAC_TUN_TEST=1 "$native_test_dir/dns.test" -test.run '^(TestTemporaryDNS|TestMacOSScopedBypass|TestRouteGuardianKernelCleanup)' -test.v -test.timeout 60s
fi
