#!/usr/bin/env bash
# Fetches and verifies the prebuilt native dependency AARs that are too big
# to vendor in-repo. Run from repo root. Downloads go to core/vpn/libs/.
set -euo pipefail
cd "$(dirname "$0")/.."

HEV_VERSION=2.19.3
HEV_URL="https://github.com/heiher/hev-socks5-tunnel/releases/download/${HEV_VERSION}/hev-socks5-tunnel.aar"
HEV_SHA256="ab6c581e6157680cfe5687ee7bbdcf95405c006c2db3701879ec44b9e5f83836"

mkdir -p core/vpn/libs
target="core/vpn/libs/hev-socks5-tunnel-${HEV_VERSION}.aar"

if [ -f "$target" ] && echo "$HEV_SHA256  $target" | sha256sum -c --quiet; then
    echo "hev-socks5-tunnel AAR already present and verified"
    exit 0
fi

echo "downloading hev-socks5-tunnel ${HEV_VERSION}…"
curl -sL --fail -o "$target" "$HEV_URL"
echo "$HEV_SHA256  $target" | sha256sum -c
echo "verified $target"
