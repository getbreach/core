#!/bin/sh
# Compile the actual bridge dependencies, not the OS-specific device stub alone.
set -eu
cd "$(dirname "$0")/.."
for native_target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 android/arm64 ios/arm64; do
  native_os=${native_target%/*}
  native_arch=${native_target#*/}
  echo "compile bridge: $native_target"
  env GOOS="$native_os" GOARCH="$native_arch" CGO_ENABLED=0 go build ./bridge ./hy2 ./inbound ./transport ./routing ./geodata ./reconnect ./engine
done
for native_target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  native_os=${native_target%/*}
  native_arch=${native_target#*/}
  echo "compile command and device adapter: $native_target"
  env GOOS="$native_os" GOARCH="$native_arch" CGO_ENABLED=0 go build ./...
done
echo 'Compile success is NOT a device, VPN-service, driver or signed-extension test.'
