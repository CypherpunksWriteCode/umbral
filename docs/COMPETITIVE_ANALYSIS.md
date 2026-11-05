# Competitive analysis

Verified facts about the projects compared (licenses, activity from GitHub
API, Nov 2026). Feature matrix reflects our **code-level** review, not
marketing claims.

## Feature matrix

| Capability | Umbral 0.1 | Orbot | InviZible | RethinkDNS | NetGuard |
|---|---|---|---|---|---|
| Firewall per app (block/bypass) | ✔ (packet-level RST + allow/deny lists) | – (allow/deny only) | ✔ | ✔ | ✔ (reference impl) |
| Per-network (Wi-Fi/mobile) rules | ✔ block rules | – | ✔ | ✔ | ✔ |
| Encrypted DNS | DoH, DoT, passthrough | (via Tor) | DoH, DoT, DNSCrypt | DoH, DoT, DNSCrypt | – |
| Local DNS interception in tunnel | ✔ all :53 | n/a | ✔ | ✔ | ✔ |
| DNS cache | ✔ TTL | – | ✔ | ✔ | – |
| Tor integration | ✔ bundled (Maven AAR), bridges via IPtProxy | ✔ (upstream itself) | ✔ executable | DoT-to-Tor for DNS only | – |
| Tor circuit control (NEWNYM) | ✔ | ✔ | partial | – | – |
| Custom SOCKS5 upstream | ✔ (remote DNS) | ✔ | ✔ | ✔ | ✔ |
| Per-app *upstream* selection | ✖ (see limitation below) | ✔ (allowlist semantics) | ✔ | ✔ | ✔ (self-built TCP stack) |
| Strict no-fallback | ✔ default-on, tested | partial | ✖ | ✖ | ✖ |
| DNS-via-Tor | ✔ (verified remote-DNS test) | ✔ | ✔ | ✔ | – |
| Config export/import, encrypted export | ✔ / ✔ AES-GCM | – | ✔ | ✔ | ✔ |
| UI modes (simple/advanced) | ✔ | – | partial | ✔ | ✔ |
| License | GPLv3+ | BSD-3 | GPL-3 | Apache-2 | GPL-3 |
| Telemetry | none | none | none | none (has opt-in?) | none |
| Distribution | F-Droid/GitHub | Play+F-Droid | F-Droid | Play+F-Droid | Play+F-Droid |

## What we deliberately did NOT copy

- **Out-of-tree native executables** (InviZible model): harder to verify and
  reproduce. We consume signed Maven artifacts (tor-android, IPtProxy) and one
  SHA-256-pinned release AAR (hev).
- **A homegrown userspace TCP stack** (NetGuard model): correct but large and
  subtle; we cannot responsibly write one untested-in-this-iteration. We use
  hev-socks5-tunnel (MIT, used by Orbot) for TCP, and pay for it with the
  per-app-upstream limitation below.
- **Everything-and-the-kitchen-sink**: no I2P, no WireGuard, no DNSCrypt in
  v0.1 — rather than shipping fakes or unmaintained code.

## Where Umbral aims to be better (with evidence)

1. **Strict no-fallback semantics as a tested property.** The routing policy
   unit tests assert that a TOR-route with Tor down resolves to BLOCK, and
   the relay integration test asserts SOCKS refusal (reply 0x05) when the
   upstream dial fails. We are not aware of equivalent hard guarantees in the
   compared apps (their fallback behavior is configurable at best).
2. **Honest per-app model.** We do not pretend per-app Tor selection exists:
   we document exactly why it cannot work with our tun2socks engine and what
   the UI exposes instead (Block/Bypass/Tunnel + global route).
3. **DNS leak-resistance by construction:** every plaintext :53 datagram in
   the tunnel is answered locally regardless of the destination address;
   non-DNS UDP is dropped by default (tests cover both verdicts).
4. **Remote-DNS verified by test:** the DoH-via-Tor path is covered by a
   loopback SOCKS recorder test asserting the hostname is sent to the proxy
   (ATYP=domain), never resolved locally.
5. **Smaller trust surface:** no Play channel, no update pings, no remote
   config; every egress is enumerated in PRIVACY.md.

## Where competitors remain ahead (no spin)

- NetGuard/Rethink per-app *upstream* routing; NetGuard's connection history
  and lockdown; Rethink's DNSCrypt + WireGuard; Orbot's maturity, audits and
  device testing; InviZible's integrated I2P. Umbral 0.1 has **no on-device
  test pass yet** — treat it as source-complete, runtime-unproven.
