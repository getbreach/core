#!/bin/sh
# Unified CLI plus compatibility commands, with release-style Go flags.
set -eu
cd "$(dirname "$0")/.."
native_output=${1:-../../breach/bin}
mkdir -p "$native_output"
native_output=$(cd "$native_output" && pwd)
go build -trimpath -ldflags='-s -w' -o "$native_output/breach" ./cmd/breach
go build -trimpath -ldflags='-s -w' -o "$native_output/breach-native" ./cmd/nativeprobe
cd ../../breach
go build -trimpath -ldflags='-s -w' -o "$native_output/breach-client" ./cmd/client
echo "Built $native_output/breach (unified), breach-native and breach-client (compatibility)"
