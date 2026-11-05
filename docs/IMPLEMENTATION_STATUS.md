# Implementation status — v0.1.0 (2026-11-05)

Legend: **IMPLEMENTED AND TESTED** (unit/integration test executed and
passing) · **IMPLEMENTED, NOT FULLY TESTED** (code paths exercised only by
compilation and review, not runtime) · **PARTIALLY IMPLEMENTED** ·
**NOT IMPLEMENTED** · **BLOCKED BY PLATFORM LIMITATION**.

## Modules

| Feature | Status | Notes |
|---|---|---|
| Routing policy engine (per-app rules, networks, strict no-fallback) | IMPLEMENTED AND TESTED | 10 unit tests |
| Config repository (DataStore, export/import, strict schema) | IMPLEMENTED AND TESTED | 5 tests |
| Encrypted config export (AES-256-GCM + PBKDF2) | IMPLEMENTED AND TESTED | 4 tests |
| DNS wire codec (RFC 1035 incl. compression, FORMERR/SERVFAIL) | IMPLEMENTED AND TESTED | 9 tests |
| DNS engine (cache, upstream failover → SERVFAIL, passthrough) | IMPLEMENTED AND TESTED | via engine tests |
| DoH resolver (RFC 8484, OkHttp) | IMPLEMENTED AND TESTED | incl. SOCKS path behavior test; live upstream test not run in CI (network) |
| DoT resolver (RFC 7858/7766) | IMPLEMENTED, NOT FULLY TESTED | framing reviewed; no TLS loopback test yet |
| IP packet codec (IPv4/IPv6 parse, build, checksums, RST) | IMPLEMENTED AND TESTED | 5 tests incl. checksum verification |
| Packet filter (DNS interception, UDP policy, block/reset/pass) | IMPLEMENTED AND TESTED | 5 tests |
| SOCKS5 client (RFC 1928/1929, remote DNS ATYP) | IMPLEMENTED AND TESTED | 2 tests |
| SOCKS5 relay (loopback, routing dialer, refuse semantics, UID filter) | IMPLEMENTED AND TESTED | 3 end-to-end socket tests (direct/blocked/upstream-down) |
| /proc/net parser | IMPLEMENTED AND TESTED | 2 tests (fallback path for API<29 class devices; minSdk 29 makes this auxiliary) |
| VPN service (TUN pumps, socketpair↔hev, DNS responder, notification, boot) | IMPLEMENTED, NOT FULLY TESTED | crash-hardened start (failures surface instead of crashing) |
| Anti-DPI ClientHello fragmentation + SNI observation | IMPLEMENTED AND TESTED | parser unit tests + real TLS handshake through fragmenting relay |
| Tor bridge batch paste parser | IMPLEMENTED AND TESTED | 3 unit tests (validation, dedupe, errors) | **not run on a device/emulator in this environment** |
| Tor controller (TorService lifecycle, status, bootstrap, NEWNYM, torrc, bridges via IPtProxy) | IMPLEMENTED, NOT FULLY TESTED | API surface verified against tor-android sources; runtime not exercised here |
| I2P: i2pd.conf generator (allow-listed options, loopback-only services) | IMPLEMENTED AND TESTED | 4 unit tests + **real-daemon boot test** (nixpkgs i2pd runs the generated config; SOCKS + webconsole verified; catches invalid options) |
| I2P: live end-to-end (our SOCKS5 client → i2pd → I2P network → eepsite HTTP 200) | TESTED (opt-in) | `UMBRAL_I2PD_LIVE=1`, network+minutes required; executed successfully in this iteration (zzz.i2p) |
| I2P: I2pdController (exec libi2pd.so, log tail, SOCKS readiness probing, lifecycle) | IMPLEMENTED, NOT FULLY TESTED | same exec technique as upstream i2pd-android; runtime not exercised on a device here |
| I2P: routing action + preset + UI screen | IMPLEMENTED, NOT FULLY TESTED | policy logic covered by 3 new unit tests |
| hev-socks5-tunnel integration (JNI contract, SEQPACKET interposer) | IMPLEMENTED, NOT FULLY TESTED | verified against hev source; runtime untested |
| Dashboard / Apps / DNS / Tor / Routing / Diagnostics / Settings UI | IMPLEMENTED, NOT FULLY TESTED | compiles; no UI test run |
| Instrumented smoke test (app) | NOT EXECUTED | source present (`app/src/androidTest`); no emulator in environment |

## Explicitly NOT implemented (no placeholders shipped)

| Feature | Status | Why |
|---|---|---|
| I2P | NOT IMPLEMENTED → **IMPLEMENTED in v0.2.0** (see module rows above; decision reversed after verifying PurpleI2P releases) |
| Per-app *upstream* selection inside tunnel | BLOCKED BY PLATFORM LIMITATION | hev does not preserve source ports (source-verified); see architecture doc |
| DNSCrypt client | NOT IMPLEMENTED | protocol work beyond v0.1 scope |
| DNSSEC local validation | NOT IMPLEMENTED | would require embedding a validator (unbound-class) responsibly |
| WireGuard | NOT IMPLEMENTED | one-VPN-per-user platform limit; combining requires deep wg integration |
| WebRTC leak *detection* | NOT IMPLEMENTED | apps' internals not observable; education text only (by design, not fake detection) |
| App-lock / biometric gate | NOT IMPLEMENTED | roadmap; keystore groundwork present only in vault |
| F-Droid metadata, reproducible builds | NOT IMPLEMENTED | roadmap |
| Translations (non-English) | NOT IMPLEMENTED | strings are inline English in v0.1 |

## Build & test evidence (this iteration)

- `gradle :app:assembleDebug` — **BUILD SUCCESSFUL**; artifact
  `app/build/outputs/apk/debug/app-debug.apk` (universal, 4 ABIs, contains
  libtor.so / libgojni.so / libhev-socks5-tunnel.so — verified via aapt2/unzip).
- `gradle :app:assembleRelease` — **BUILD SUCCESSFUL** (R8 + lintVital pass;
  Instantiatable lint check disabled with justification).
- `gradle test` — **47 tests, 0 failures** across :core:model (10),
  :core:config (9), :core:dns (11), :core:net (17).
- Instrumentation/UI/device tests: **not executed** (no emulator/device
  available in the build environment) — this is the main gap of this release.
