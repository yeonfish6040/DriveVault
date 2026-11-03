#!/bin/sh
# Run after extracting the entire archive. No installer or administrator required.
set -eu
APP_ROOT=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
export VAULTDRIVE_PORTABLE_HOME="$APP_ROOT"
os=$(uname -s)
cpu=$(uname -m)
case "$os" in
  Darwin)
    # A shell launched through Rosetta should still prefer the native ARM app.
    if [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then cpu=arm64; fi
    case "$cpu" in arm64|aarch64) target=aarch64-apple-darwin;; x86_64|amd64) target=x86_64-apple-darwin;; *) echo "Unsupported macOS CPU: $cpu" >&2; exit 2;; esac
    app="$APP_ROOT/bin/$target/VaultDrive.app/Contents/MacOS/VaultDrive"
    ;;
  Linux)
    bits=$(getconf LONG_BIT 2>/dev/null || printf 64)
    case "$cpu:$bits" in
      x86_64:32|i386:*|i486:*|i586:*|i686:*) target=i686-unknown-linux-gnu;;
      x86_64:*|amd64:*) target=x86_64-unknown-linux-gnu;;
      aarch64:64|arm64:64) target=aarch64-unknown-linux-gnu;;
      *) echo "Unsupported Linux CPU/userspace: $cpu ($bits-bit)" >&2; exit 2;;
    esac
    app="$APP_ROOT/bin/$target/vault-gui"
    ;;
  *) echo "Unsupported OS: $os. On Windows, use VaultDrive.bat." >&2; exit 2;;
esac
if [ ! -f "$app" ]; then
  echo "This package does not contain $target. Use a complete package or download that platform build." >&2
  exit 3
fi
if [ ! -x "$app" ]; then
  echo "Cannot execute $app. Check executable permission and whether the SSD is mounted with noexec." >&2
  exit 4
fi
exec "$app" "$@"
