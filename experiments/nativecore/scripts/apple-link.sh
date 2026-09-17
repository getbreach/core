#!/bin/sh
# Actual iOS arm64 c-archive linking, beyond a CGO-disabled package compile.
# Does not sign an extension or claim a device runtime test.
set -eu
cd "$(dirname "$0")/.."
native_output=${1:?usage: sh scripts/apple-link.sh /absolute/output/directory}
case "$native_output" in /*) ;; *) echo 'Output directory must be absolute.' >&2; exit 1;; esac
mkdir -p "$native_output"
native_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
env GOOS=ios GOARCH=arm64 CGO_ENABLED=1 CC="$(xcrun --find clang)" \
  CGO_CFLAGS="-isysroot $native_sdk -target arm64-apple-ios15.0" \
  CGO_LDFLAGS="-isysroot $native_sdk -target arm64-apple-ios15.0" \
  go build -buildmode=c-archive -o "$native_output/libbreach-probe.a" ./cmd/linkprobe
echo "Linked iOS arm64 archive: $native_output/libbreach-probe.a"
