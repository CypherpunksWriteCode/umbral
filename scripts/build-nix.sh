#!/usr/bin/env bash
# Build entry point for NixOS hosts (no nix-ld: gradle/jdk/aapt2 come from nixpkgs).
set -euo pipefail
cd "$(dirname "$0")/.."

nix-shell shell.nix --run '
set -euo pipefail
echo "ANDROID_HOME=$ANDROID_HOME"
AAPT2="$ANDROID_HOME/build-tools/36.1.0/aapt2"
test -x "$AAPT2" || { echo "aapt2 not found at $AAPT2" >&2; exit 1; }
exec gradle -Pandroid.aapt2FromMavenOverride="$AAPT2" "$@"
'
