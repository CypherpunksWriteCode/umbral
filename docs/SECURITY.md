# Security review — v0.1.0

Self-audit performed at the end of the iteration. Findings and their
dispositions (all code references to this tree).

## 1. Review of permissions

Declared: INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE,
FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS, RECEIVE_BOOT_COMPLETED,
QUERY_ALL_PACKAGES. Each is required and documented in README. No location,
storage, camera, contacts. **OK.**

## 2. Network behavior

- All app-initiated egress enumerated in PRIVACY.md.
- DoH URL must be https (enforced, tested).
- Relay binds 127.0.0.1 only (verified `InetAddress.getLoopbackAddress()` bind).
- Tor/relay/DoH sockets excluded from the VPN via
  `addDisallowedApplication(self)` — required for function; documented that
  the app's own egress is therefore direct except when explicitly via Tor.

## 3. Findings & fixes applied in this iteration

| Finding | Severity | Disposition |
|---|---|---|
| Loopback relay usable by other apps (shared 127.0.0.1) | Medium | FIXED: accept filter rejects foreign-UID connections via `getConnectionOwnerUid` (API 29+). Residual: owner-unresolvable accepts; documented. |
| Direct dial would resolve hostnames via system DNS (leak) | High | FIXED: relay resolves through the encrypted DNS engine first (literal IPs pass through un-resolved) |
| SOCKS chain could resolve hostname locally (DoT-via-Tor leak) | High | FIXED: `Socks5Client` sends ATYP=domain; DoT resolver uses the SocksConnection contract; OkHttp SOCKS behavior verified by loopback test |
| QDCOUNT typo produced zero-question queries (DNS breakage, caught by tests) | High | FIXED in `DnsCodec.buildQuery` |
| TCP packets evaluated by UDP rules (filter bug, caught by tests) | High | FIXED in `PacketFilter.decide` |
| IPv6 text formatting wrong (decimal + '.' separator, caught by tests) | Medium | FIXED in `IpCodec.ip6Text`, `DnsCodec.Record.asAAAA` |
| Extra NUL byte in SOCKS5 CONNECT (caught by byte-dump test) | Medium | FIXED request framing in `Socks5Client` |
| `ConfigVault` PBKDF2 210k iterations, random salt+IV per export | — | Verified correct (roundtrip + wrong-pass tests) |
| Config import parses untrusted JSON with strict schema (`ignoreUnknownKeys=false`), rejects garbage | — | OK (tested) |
| Extra torrc options allow-listed (no arbitrary config injection) | — | OK |

## 4. Open items (accepted risks / roadmap)

1. TorService's loopback SOCKS/HTTP ports (9050/8118) are shared with all
   apps on the device — inherited tor-android behavior (same as Orbot).
   Roadmap: optional loopback auth / port choice.
2. No Maven artifact signature verification; native AAR is pinned by SHA-256
   at download time only.
3. No obfuscation/optimization verification for release beyond R8 passing;
   unsigned release build is for distributors to sign.
4. No instrumented tests executed (no emulator/device in this environment).
5. `getConnectionOwnerUid` results are cached 15 s by source port; a racing
   port reuse could mis-attribute for that window (standard practice; low
   risk).
6. Boot auto-start is best-effort under FGS launch restrictions.
