# Umbral — Android privacy suite

**Codename "Umbral"** — an open-source, modular privacy and anonymity suite for
Android 10+ (API 29+): a per-app firewall, encrypted DNS (DoH/DoT), and optional
bundled Tor routing, combined in one VPN-based tunnel with **strict no-fallback
semantics**.

> "Privacy is necessary for an open society in the electronic age." — Eric Hughes,
> *A Cypherpunk's Manifesto* (1993). This project tries to honor that idea in its
> engineering decisions: local-only configuration, no accounts, no telemetry, no
> developer-controlled infrastructure, and honest documentation of what it can
> and cannot protect against.

**Status: v0.1.0 — see [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md)
for exactly what is implemented, tested, and missing.** This is an early
release. It is NOT audited. Do not bet your life on it.

## What it does

- **VPN-based firewall with per-app rules** — Tunnel / Bypass / Block per
  application (block rules per Wi-Fi/mobile network in Advanced mode). Blocked
  TCP connections are actively reset; non-DNS UDP (QUIC etc.) is dropped by
  default so apps cannot escape the enforced path.
- **Encrypted DNS** — a local DNS engine inside the tunnel. DNS-over-HTTPS
  (RFC 8484) or DNS-over-TLS (RFC 7858), with a local TTL cache. Shipped
  provider catalogue (Cloudflare, Quad9, AdGuard, DNSforge, Mullvad) plus fully
  custom endpoints. All plaintext port-53 traffic inside the tunnel is
  intercepted and answered locally — pushed/rogue resolvers are ignored.
- **Bundled Tor** — the real Tor daemon (`tor-android` 0.4.9.14 from Maven
  Central, BSD-3) with pluggable transports via IPtProxy (obfs4, snowflake,
  webtunnel, meek_lite). Route the whole tunnel through Tor with one preset;
  DNS can be resolved through Tor as well (remote DNS, see below). Circuit
  renewal (`NEWNYM`), bootstrap progress, bridge management.
- **Custom SOCKS5 upstream** for the whole tunnel, with username/password
  support, hostnames always sent to the proxy (remote DNS).
- **Strict failure mode (default on)** — if Tor or the configured proxy is
  unavailable, connections are **refused**, never silently sent directly.
- **Diagnostics you can trust** — connection log (what was blocked/passed),
  DNS query log (which upstream, cached or not), Tor log. The screens say
  explicitly what the app *cannot* observe.
- **Simple and Advanced UI modes** — Material 3 / Jetpack Compose.

## What it does NOT do (honest limitations)

- It does **not** anonymize traffic you route directly. Encrypted DNS hides
  queries from the local network only; the resolver still sees them.
- It does **not** protect against a compromised OS, a rooted/backdoored device,
  or physical access to an unlocked phone.
- Per-app upstream selection *inside* the tunnel (app A → Tor, app B → direct)
  is **not possible in v0.1** for a verified technical reason: the tun2socks
  engine (hev-socks5-tunnel) does not preserve original source ports, so
  per-connection UID attribution stops at the packet filter. Per-app options
  are Block / Bypass; the tunnel route (Direct/Tor/Proxy) is global. See
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#known-limitation-per-app-upstream).
- No DNSSEC validation is performed locally; providers that validate are
  marked in the UI (validation happens upstream).
- No I2P module. The i2p.android.base codebase was assessed and is not
  integrable in this release (see docs/RESEARCH.md §7). Do not expect I2P.
- Not tested on a physical device yet in this iteration — see
  docs/IMPLEMENTATION_STATUS.md.

## Architecture (short version)

```
TUN fd ─pump─► PacketFilter ──UDP:53──► DnsEngine (DoH/DoT) ─► TUN
                   │
                 pass ─► socketpair(SOCK_SEQPACKET) ─► hev tun2socks (C, MIT)
                                                           │ SOCKS5 loopback
                 SocksRelayServer (Kotlin) ◄────────────────┘
                       │ RoutingPolicy (strict, no silent fallback)
                 DIRECT (resolve via DoH, then connect)
                 TOR    (SOCKS5 to TorService, hostname sent remotely)
                 PROXY  (SOCKS5 to user proxy, remote DNS)
                 BLOCK  (refuse / reset)
```

Full description: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Building

### Conventional hosts (Linux/macOS, JDK 21, Android SDK)

```bash
./scripts/fetch-native-deps.sh   # downloads + SHA256-verifies hev-socks5-tunnel AAR
./gradlew :app:assembleDebug
```

You need Android SDK platform 37 and build-tools 36.1.0 (`sdkmanager
"platforms;android-37" "build-tools;36.1.0"`), plus JDK 17+ (built with 21).

### NixOS

No Android Studio needed:

```bash
nix-shell shell.nix --run 'true'          # builds the patched SDK toolchain
./scripts/build-nix.sh :app:assembleDebug # wrapper that points AGP at the patched aapt2
```

### Tests

```bash
./gradlew test                # 47 JVM unit/integration tests (real sockets, no mocks for SOCKS)
```

## Installing

Debug APK: `app/build/outputs/apk/debug/app-debug.apk`
(`adb install -r app-debug.apk`). On first start you must grant the VPN
permission. Distribution target is F-Droid/GitHub releases, **not** Google
Play (the firewall needs `QUERY_ALL_PACKAGES`, which Play rejects).

## Permissions and why

| Permission | Reason |
|---|---|
| `INTERNET` | Sockets for the tunnel, DNS upstreams, Tor |
| `ACCESS_NETWORK_STATE` | UID attribution (`getConnectionOwnerUid`), Wi-Fi/mobile rule selection |
| `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_SPECIAL_USE` | The VPN runs as a foreground service (type `specialUse`, subtype vpn) |
| `POST_NOTIFICATIONS` | Status notification (Android 13+) |
| `RECEIVE_BOOT_COMPLETED` | Optional auto-start after boot (off by default, user opt-in) |
| `QUERY_ALL_PACKAGES` | List installed apps for per-app firewall rules |

There is no analytics, no advertising, no tracking SDK, no account system, no
remote configuration. See [PRIVACY.md](PRIVACY.md) for the complete network
egress manifest — every outbound connection the app can make.

## Included third-party work

| Component | License | Source |
|---|---|---|
| Tor (`libtor.so`) via tor-android 0.4.9.14 | BSD-3-Clause | https://github.com/guardianproject/tor-android |
| jtorctl 0.4.5.7 | BSD-style | https://github.com/guardianproject/jtorctl |
| IPtProxy 5.7.0 (obfs4/snowflake/webtunnel/meek_lite/dnstt) | MIT | https://github.com/tladesignz/IPtProxy |
| hev-socks5-tunnel 2.19.3 | MIT | https://github.com/heiher/hev-socks5-tunnel |
| OkHttp 4.12.0 | Apache-2.0 | https://github.com/square/okhttp |
| AndroidX / Jetpack Compose | Apache-2.0 | https://source.android.com |

This project is licensed under **GPLv3 or later** ([LICENSE](LICENSE)).

## Threat model & security

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — what Umbral defends against, and against what it cannot.
- [docs/SECURITY.md](docs/SECURITY.md) and [SECURITY.md](SECURITY.md) — engineering rules and reporting.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small, reviewable, tested PRs.
All crypto is standard (AES-256-GCM, PBKDF2-HMAC-SHA256, TLS via platform
stacks); we do not invent cryptography.

## Roadmap

- Device/emulator test pass, integration test suite (instrumented).
- Per-app upstream selection (requires a UID-aware tun2socks; tracking in docs).
- DNSSEC local validation (or integration of a reviewed validator).
- I2P assessment follow-up.
- Reproducible builds, release signing story, F-Droid metadata.
- Translations (UI strings are English-only in v0.1).
