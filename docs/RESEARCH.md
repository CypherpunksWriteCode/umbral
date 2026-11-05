# Research notes

Everything below was verified during the v0.1 iteration (November 2026) by
inspecting **actual release artifacts and sources**, not READMEs. Two classes
of statements are used: **[VERIFIED]** (artifact/сURL/source inspected in this
session, reference given) and **[ASSESSMENT]** (engineering judgement).

## 1. Orbot (guardianproject/orbot-android)

- License [VERIFIED]: repo `LICENSE` ~5.9 KB, BSD-style; repo API
  `license.spdx_id = NOASSERTION` (custom 3-clause text).
- Active (last push Oct 2026), ~3.7k stars.
- Build stack [VERIFIED from `gradle/libs.versions.toml` + `app/build.gradle.kts`]:
  AGP 9.4.1, Kotlin 2.4, `info.guardianproject:tor-android:0.4.9.14` (Maven
  Central), `info.guardianproject:jtorctl:0.4.5.7`, `com.netzarchitekten:IPtProxy:5.7.0`,
  gpmaven repo `https://raw.githubusercontent.com/guardianproject/gpmaven/master`,
  tor itself also built in-tree via `externalNativeBuild ndkBuild` (NDK 30).
- Tor daemon interaction [VERIFIED from tor-android `TorService.java`]:
  service loads `libtor.so`, writes `torrc`/`torrc-defaults`, prefers
  SOCKSPort 9050, exposes status via `LocalBroadcastManager` and a `LocalBinder`
  with `getSocksPort()`, `getInfo()`, `getTorControlConnection()` (already
  cookie-authenticated by the service itself, `CookieAuthentication 0`).
- tun2socks: Orbot uses **hev-socks5-tunnel** (listed as Android use case in
  its README) [VERIFIED].

**Takeaway [ASSESSMENT]:** consuming `tor-android` + `IPtProxy` from Maven
Central gives a real, maintained Tor stack without building tor with the NDK.
TorService is not a foreground service and must be started from a foreground
context.

## 2. InviZible (Gedsh/InviZible)

- License [VERIFIED via GitHub API]: GPL-3.0, ~2.9k stars, active (Oct 2026).
- Runs tor, dnscrypt-proxy and i2pd as **native executables** managed from the
  app [ASSESSMENT based on repo structure/docs; executables are built out of
  tree and shipped].
- UX strength: one dashboard, module toggles; weakness reported by users:
  size, battery, complexity of advanced settings.

**Takeaway:** the UX model (dashboard + per-module screens) is worth copying;
shipping i2p.d/tor as out-of-tree binaries complicates reproducibility — we
prefer Maven-hosted AARs where possible.

## 3. RethinkDNS (celzero/rethink-app)

- License [VERIFIED]: Apache-2.0, ~5.9k stars, active (Oct 2026).
- DNS-over-HTTPS/DoT/DNSCrypt, firewall + WireGuard proxifier in one app.
- Uses its own `tun2socks` integration (go-tun2socks lineage) [ASSESSMENT].

## 4. NetGuard (M66B/NetGuard)

- License [VERIFIED]: GPL-3.0, ~4k stars, last push Aug 2026.
- The reference implementation of a pure-Java Android firewall: VpnService +
  its own userspace TCP stack (packet-level NAT) enabling **per-app,
  per-connection routing incl. SOCKS proxying**.
- Key insight we inherited: UID attribution is the hard part. NetGuard reads
  `/proc/net/tcp*` (and `getConnectionOwnerUid` on newer APIs) to map
  connections to UIDs.

## 5. hev-socks5-tunnel (heiher)

- License [VERIFIED]: MIT (README).
- Release 2.19.3 artifacts [VERIFIED by download + unzip]: an official AAR
  with all four ABIs and a self-contained `hev.htproxy.TProxyService` JNI
  wrapper: `TProxyStartService(String configPath, int tunFd)` — i.e. it
  accepts the VpnService's TUN fd directly.
- Source-verified behavior critical to our design:
  - `hev_socks5_client_connect` uses `klass->binder`, and the default binder
    (`hev_socks5_bind`) **is a no-op** → outbound sockets are NOT bound to the
    original source ports → per-connection UID attribution inside the SOCKS
    path is impossible [VERIFIED, hev-socks5-core `hev-socks5-client.c:105,305`].
  - When handed an external fd it only sets `FIONBIO` and probes `TUNGETIFF`;
    on failure (e.g. our socketpair) it falls back to **plain packets**
    [VERIFIED, `hev-tunnel-linux.c` set_offload comments + `hev-socks5-tunnel.c`
    tunnel_init] → we can legally interpose a JVM packet filter via
    `socketpair(AF_UNIX, SOCK_SEQPACKET)` preserving packet boundaries.

## 6. IPtProxy (tladesignz)

- License [VERIFIED]: MIT; AAR 5.7.0 on Maven Central [VERIFIED by download];
  contains `IPtProxy.Controller` (Go/gomobile) with `start(transport, proxy)`,
  `port(transport)`, `stop(transport)`, snowflake broker setters
  [VERIFIED by javap + controller.go]. Transports: lyrebird (obfs2..obfs4,
  scramblesuit, meek_lite, webtunnel) 0.9.0, snowflake 2.15.1, dnstt
  [VERIFIED from README table].

## 7. I2P (updated in v0.2.0 — decision reversed by verified artifacts)

Two distinct projects must not be confused:

- **i2p.android.base** (Java I2P router app) [VERIFIED via GitHub API]:
  archived, read-only — not integrable. This was the basis of the v0.1 "no
  I2P" decision.
- **PurpleI2P/i2pd** (C++ router) and **PurpleI2P/i2pd-android** [VERIFIED]:
  active (pushed Nov 2026), BSD-3-Clause; the Android app publishes official
  release 3.0.0 (Oct 2026) including `i2pd_3.0.0_android_binary.zip` with
  standalone per-ABI executables (`file` confirms: PIE ELF,
  interpreter /system/bin/linker64, "for Android 23", NDK r29).

v0.2.0 therefore ships i2pd: binaries vendored as `libi2pd.so` in jniLibs
(extractNativeLibs=true; exec'd via ProcessBuilder — the same technique the
upstream app uses), config generated by our own allow-listed builder.

**Config validated against the real daemon:** the sandbox test
(`core/i2p/.../I2pdConfigBuilderTest`, env `UMBRAL_I2PD_TEST=1`) runs nixpkgs
i2pd 2.61 with the generated file and asserts the SOCKS proxy and webconsole
come up. This process caught three invalid option names in the first draft
(`webconsole.*` → `http.*`, `transitenabled` → `notransit`, spurious
`persist`) — exactly why config generators must be tested against the real
consumer. Live e2e (env `UMBRAL_I2PD_LIVE=1`): fresh daemon → reseed →
tunnels → our `Socks5Client` CONNECT to `zzz.i2p:80` → **HTTP 200 from the
eepsite** (observed in this iteration; network-dependent, opt-in).

## 8. DNSCrypt

- Protocol (v2) is well-specified (curves, XChaCha20-Poly1305 certs). A real
  client is a nontrivial implementation (cert rotation, encrypted frames,
  anonymization relays). v0.1 ships DoH/DoT only; DNSCrypt is roadmap
  [ASSESSMENT].

## 9. WireGuard

- Official Android app (ACL: Apache-2.0) is a VPN itself; Android allows only
  one active VpnService per user [PLATFORM LIMITATION]. Therefore *combining*
  WireGuard and our firewall in one session requires embedding wg-quick-style
  internals into our own VpnService — out of scope for v0.1, documented.

## 10. Platform constraints (Android 10–15)

- One VPN at a time; `VpnService.prepare()` consent; always-on support needs
  the `android.net.VpnService` intent filter (we declare it).
- FGS on API 34+ requires an explicit type; we use `specialUse` with subtype
  `vpn_privacy_suite` and `FOREGROUND_SERVICE_SPECIAL_USE` permission.
- `QUERY_ALL_PACKAGES` is required to enumerate apps for rules → Play
  distribution is not possible; F-Droid/GitHub is the channel.
- `ConnectivityManager.getConnectionOwnerUid` is public since API 29
  [VERIFIED against android-35 android.jar via javap] — the clean way for UID
  attribution; `/proc/net` parsing remains as a fallback path.
- `android.system.Os.socketpair(...)` exists since API 21
  [VERIFIED against android.jar].
