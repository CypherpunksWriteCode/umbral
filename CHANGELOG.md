# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog; versioning is semantic once 1.0 ships.

## [0.2.0] — 2026-11-05

### Added
- **I2P module**: bundled i2pd router (Purple I2P 3.0.0 release binaries,
  BSD-3) executed in-app; loopback SOCKS/HTTP proxies, webconsole, optional
  SAM; transit participation off by default; `RouteAction.I2P` + "I2P
  Routing" preset + dedicated UI screen with advanced options (ports,
  outproxy, allow-listed extra i2pd.conf lines).
- I2P config builder validated against the real daemon (boot test) and a
  live end-to-end test (our SOCKS5 client fetches zzz.i2p through a fresh
  router) — both executed in this iteration.
- Per-ABI APK splits (arm64 build ≈80 MB vs 195 MB universal v0.1).
- Install-corruption guidance + SHA-256 workflow in README.

### Fixed
- (docs) I2P research section corrected: i2p.android.base is archived, but
  PurpleI2P/i2pd-android actively ships official Android binaries.

## [0.1.0] — 2026-11-05

First public source release. Codename **Umbral**.

### Added
- VPN-based per-app firewall (Tunnel / Bypass / Block; per-network block in
  Advanced mode) with TCP RST for blocked connections and default-on non-DNS
  UDP dropping.
- Local DNS engine: DNS-over-HTTPS (RFC 8484), DNS-over-TLS (RFC 7858),
  passthrough mode, TTL cache, interception of all port-53 traffic inside the
  tunnel, provider catalogue + custom endpoints.
- Bundled Tor (tor-android 0.4.9.14) with status/bootstrap/NEWNYM, bridge
  management and pluggable transports via IPtProxy 5.7.0.
- Global tunnel routing Direct/Tor/custom-SOCKS5 with strict no-fallback
  semantics and remote DNS at proxies.
- Diagnostics: connection log, DNS log, Tor log.
- Configurable presets (Privacy First, Tor Routing, DNS Firewall).
- Configuration export/import, optional AES-256-GCM encrypted export.
- 47 JVM unit/integration tests (routing policy, packet filter, IP/TCP/UDP
  codec incl. checksums, DNS wire format incl. compression, SOCKS5 client and
  relay end-to-end over real loopback sockets, OkHttp SOCKS remote-DNS
  verification, config crypto and persistence).

### Known limitations
See docs/IMPLEMENTATION_STATUS.md — notably: no on-device testing yet,
per-app *upstream* selection not possible with the current tun2socks engine,
no I2P, no local DNSSEC validation.
