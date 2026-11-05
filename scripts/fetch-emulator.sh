#!/usr/bin/env bash
# Detached emulator toolchain build (robust against tool timeouts).
set -euo pipefail
cd "$(dirname "$0")/.."
exec env NIXPKGS_ACCEPT_ANDROID_SDK_LICENSE=1 nix-build -E 'let pkgs = import <unstable> { config = { allowUnfree = true; }; }; a = pkgs.androidenv.composeAndroidPackages { platformVersions = [ "35" ]; buildToolsVersions = [ "36.1.0" ]; includeSystemImages = true; emulatorVersion = "37.2.4"; systemImageTypes = [ "google_apis" ]; abiVersions = [ "x86_64" ]; }; in [ a.emulator (builtins.head a.system-images) (builtins.head a.platforms) (builtins.head a.build-tools) a.platform-tools ]' -o /home/noid/Trash/project/.toolchain/emu-parts
