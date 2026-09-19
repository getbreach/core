#!/bin/sh
# Read-only diagnostics for an already running macOS TUN. No sudo required.
# Does not read the config, credentials, or the FakeIP browsing history.
set -u
if [ "$(uname -s)" != Darwin ]; then
  echo 'This diagnostic is for macOS.' >&2
  exit 1
fi

echo '=== System DNS ==='
/usr/sbin/scutil --dns
echo '=== Routes: physical default, public IP, tunnel DNS, FakeIP ==='
for native_target in default 1.1.1.1 198.19.255.2 198.18.0.1; do
  /sbin/route -n get "$native_target"
done
native_physical=$(/sbin/route -n get default | awk '$1 == "interface:" {print $2}')
if [ -n "$native_physical" ]; then
  echo '=== Route for a socket bound to the physical interface ==='
  /sbin/route -n get -ifscope "$native_physical" 1.1.1.1
fi

echo '=== Tunnel DNS over UDP ==='
/usr/bin/dig +time=2 +tries=1 @198.19.255.2 example.com A
echo '=== Tunnel DNS over TCP ==='
/usr/bin/dig +tcp +time=2 +tries=1 @198.19.255.2 example.com A

echo '=== HTTPS by IP (no DNS) ==='
/usr/bin/curl --noproxy '*' --connect-timeout 5 --max-time 8 -sS -o /dev/null \
  -w 'IP: HTTP=%{http_code} peer=%{remote_ip} seconds=%{time_total}\n' https://1.1.1.1/
echo '=== HTTPS using system DNS ==='
/usr/bin/curl --noproxy '*' --connect-timeout 5 --max-time 8 -sS -o /dev/null \
  -w 'System DNS: HTTP=%{http_code} peer=%{remote_ip} seconds=%{time_total}\n' https://example.com/
native_fake=$(/usr/bin/dig +short +time=2 +tries=1 @198.19.255.2 example.com A | awk '/^198\.18\.[0-9]+\.[0-9]+$/ {print; exit}')
if [ -n "$native_fake" ]; then
  echo '=== HTTPS using the tunnel FakeIP explicitly ==='
  /usr/bin/curl --noproxy '*' --resolve "example.com:443:$native_fake" \
    --connect-timeout 5 --max-time 8 -sS -o /dev/null \
    -w 'FakeIP: HTTP=%{http_code} peer=%{remote_ip} seconds=%{time_total}\n' https://example.com/
fi
echo '=== Interface packet counters ==='
/usr/sbin/netstat -ibn | awk 'NR == 1 || $1 ~ /^utun/'
echo '=== End of diagnostics ==='
