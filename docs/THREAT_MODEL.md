# Threat model

Umbral v0.1. Honest scope: read together with PRIVACY.md and
docs/IMPLEMENTATION_STATUS.md.

## Assets

- The fact and content of the user's communications.
- The mapping user → visited names (DNS) and user → destinations (IP).
- Local configuration (may include proxy credentials, bridge lines).
- The integrity of routing decisions (anonymized traffic must not leak direct).

## Adversaries and outcomes

| # | Adversary | Capability | Umbral's answer | Residual risk |
|---|---|---|---|---|
| 1 | Local Wi-Fi/ISP observer | Sees plaintext DNS, SNI, destinations | DoH/DoT in-tunnel; Tor option hides destinations; Direct route hides nothing except plaintext DNS | Traffic volume/timing; SNI of DoH provider host; Direct route is not anonymity (stated in UI) |
| 2 | Pushed/rogue resolver | Tries to make the device use attacker DNS | All :53 in tunnel answered locally regardless of target | System DNS of *bypassed* apps still network-controlled |
| 3 | Malicious app on device | Tries to escape the tunnel; tries to abuse our loopback relay | VPN allow/deny lists; non-DNS UDP drop; relay rejects foreign-UID connections (API 29+) when owner resolvable | Apps with bypass; owner-unresolvable accepts (documented); TorService's own loopback SOCKS remains shared device-wide (same as Orbot) |
| 4 | Network-level traffic analysis | Correlates flows | Tor route with padding options (allow-listed torrc); QUIC dropped so flows stay on Tor's TCP | Global adversaries can correlate Tor entry/exit timing — fundamental Tor limit, not fixable here |
| 5 | Compromised OS / rooted device | Everything | None | Out of scope, stated |
| 6 | Physical access to unlocked device | Reads config, toggles settings | Config export is opt-in only; diagnostics memory-only; Android profile/lock protection is the OS's job | No in-app app-lock in v0.1 (roadmap) |
| 7 | Compromised DNS provider | Logs/blocks/tampers answers | Provider is user-chosen; DoH/DoT integrity is TLS-bound; provider choice is displayed everywhere | Provider sees queries (unless via Tor); no local DNSSEC in v0.1 |
| 8 | Malicious/blocked Tor (censor) | Blocks Tor endpoints | Bridges: obfs4/webtunnel/snowflake/meek_lite via IPtProxy | Bridge availability; no Moat/bridge-distribution UI in v0.1 (user must obtain bridge lines) |
| 9 | Misconfiguration | User turns strict fallback off, route=TOR, Tor dies → traffic goes direct | Default ON strict mode; UI marks fallback red as "leaks traffic"; RoutingPolicy test pins the semantics | If the user disables the guard, we warn but obey |
| 10 | Supply chain (dependency compromise) | Trojan artifact | Coordinates pinned in the version catalog; native AAR pinned by SHA-256; dependency count kept tiny; licenses reviewed | No signature verification of Maven artifacts yet; no lockfile beyond the catalog (roadmap: Gradle lockfiles, VEX, update bot) |
| 11 | Side channels (WebRTC, apps ignoring proxy) | App-level IP disclosure | Documented in Diagnostics screen: we cannot observe browser-internal WebRTC; bypassed apps are direct | Education, honest labeling |
| 12 | State actor with device seizure | Forensics | Diagnostics memory-only; tor data dir in app-private storage (`AvoidDiskWrites 1` limits artifacts) | No plausible-deniability features |

## Key security properties (tested)

1. Strict no-fallback: `RoutingPolicyTest` asserts TOR-route+Tor-down ⇒ BLOCK;
   `SocksTest` asserts the relay refuses (0x05/0x02) when upstream dial fails —
   there is no code path from "upstream failed" to "connect direct".
2. DNS interception: `PacketFilterTest` asserts every UDP/53 verdict is
   DNS_LOCAL; other UDP dropped unless the user opts out.
3. Remote DNS at proxies: `DohResolverSocksTest` asserts ATYP=DOMAINNAME is
   sent to the SOCKS proxy (OkHttp behavior verified on the wire).
4. Crafted packets: IpCodec tests verify IPv4 header/UDP checksums and the
   mandatory IPv6 UDP checksum; RST builder inverts the tuple correctly.

## Explicit non-goals

- Protection against a compromised OS or bootloader.
- Anonymity for bypassed apps or for the Direct route.
- Hiding that Tor/DoH is in use from the local network (bridges help against
  Tor blocking specifically; DoH is recognizable as TLS to a known resolver
  host unless routed via Tor).
- Multi-user/work-profile scenarios (untested).
- Protection of loopback Tor SOCKS from other apps (inherited tor-android
  behavior, same as Orbot; roadmap: optional loopback auth).
