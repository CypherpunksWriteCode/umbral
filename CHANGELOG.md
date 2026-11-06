# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog; versioning is semantic once 1.0 ships.

## [0.5.0] — 2026-11-07

### Fixed — three real crashes, all reproduced on an API 35 emulator
1. Release-only crash when starting Tor: R8 renamed JNI-referenced members
   of TorService → NoSuchFieldError in libtor (fixed with keep rules;
   tor-android's AAR ships none).
2. Native SIGABRT in libtor (FORTIFY: destroyed mutex) whenever the tunnel
   restarted while Tor ran: full service teardown killed TorService mid-run.
   Tunnels now reconfigure in place (ACTION_RESTART) and reuse running
   Tor/i2pd daemons.
3. Crash in the i2pd log reader thread (IllegalThreadStateException from
   exitValue() before process reaping).

### UI — simple by default
- Home is now: one Start/Stop button + four plain toggles (Tor, I2P,
  encrypted DNS, anti-DPI). Toggles apply immediately — the tunnel
  reconfigures in place, daemons are not restarted (Tor bootstrap survives).
- Live status subtitles (Tor bootstrap %, SOCKS port, i2pd router state).
- Presets removed from the UI; advanced controls live on the Advanced tab.

## [0.4.1] — 2026-11-06

### Fixed
- THE start crash, reproduced and verified fixed on a live Android 15
  emulator: the VPN service's notification channel was never created
  (createChannel was lost in an earlier refactor), so Android killed the
  service ("invalid channel for service notification") and the whole
  process on Start. Channel is now created in onCreate AND defensively
  before startForeground.

### Tested on emulator (API 35, x86_64)
- install, VPN consent, start: tunnel CONNECTED and system-VALIDATED
  (DNS+HTTP through the tunnel), browser loads pages
- stop/start cycles, i2pd child process with SOCKS/webconsole listening,
  Tor daemon loading. Unit suite: 68/68.

## [0.4.0] — 2026-11-06

### Added
- Tor bridges: built-in public sets (Snowflake, obfs4, meek_lite — the same
  list Orbot ships, from Tor Project/Guardian Project), selectable in the UI;
  custom paste stays available. Parser tested.
- Crash reporter: uncaught exceptions are saved locally and shown on the
  Diagnostics screen (never uploaded) — field debugging without adb.
- Dashboard: plain-language "how do I use this" card.

### Fixed
- VpnService: fixed illegal mixing of allow/disallow app lists when
  include-only mode is used (hard crash on start for that configuration).
- UI: FilterChip import, LazyColumn scoping.

## [0.3.0] — 2026-11-06

### Added
- Anti-DPI: TLS ClientHello fragmentation at the relay (handshake-safe,
  verified against a real TLS server in tests) + SNI observation in
  diagnostics. In-place SNI rewriting is documented as impossible without
  MITM (Finished MAC) — we ship the honest variant.
- Tor bridges: batch paste (multi-line, validated per line, deduplicated).
- Relay port fallback (bind 10808..10813), crash-hardened tunnel start:
  any startup failure now surfaces as an error and stops the service
  instead of killing the process.
- UI: bottom bar reduced to 5 tabs; DNS/Tor/I2P/Routing merged into a
  "Net" screen with internal tabs.
- Repository slimmed down: corporate-flavored docs removed (CoC,
  contributing boilerplate, marketing comparisons); engineering docs kept.

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
