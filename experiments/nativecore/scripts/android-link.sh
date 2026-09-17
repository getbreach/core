#!/bin/sh
# Link an arm64 Android library with the NDK, without producing a final AAR.
set -eu
cd "$(dirname "$0")/.."
native_output=${1:?usage: ANDROID_NDK_HOME=... sh scripts/android-link.sh /absolute/output/directory}
case "$native_output" in /*) ;; *) echo 'Output directory must be absolute.' >&2; exit 1;; esac
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed NDK}"
case "$(uname -s)" in Darwin) native_host=darwin-x86_64;; Linux) native_host=linux-x86_64;; *) echo 'Run this link check on macOS or Linux.' >&2; exit 1;; esac
native_cc="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$native_host/bin/aarch64-linux-android26-clang"
test -x "$native_cc"
mkdir -p "$native_output"
env GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC="$native_cc" \
  go build -buildmode=c-shared -o "$native_output/libbreach-probe.so" ./cmd/linkprobe
echo "Linked Android arm64 library: $native_output/libbreach-probe.so"
