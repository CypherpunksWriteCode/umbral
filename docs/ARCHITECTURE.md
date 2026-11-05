# Architecture

## Modules

```
:core:model   pure Kotlin domain (rules, presets, RoutingPolicy) — no Android
:core:config  DataStore repository, JSON export/import, AES-GCM vault (pure JVM)
:core:net     IP/TCP/UDP codec, packet filter, SOCKS5 client+relay, /proc/net parser (pure JVM)
:core:dns     DNS wire codec, cache, DoH (OkHttp), DoT, engine (pure JVM)
:core:tor     Android lib: TorService wrapper (status, torrc, bridges/IPtProxy, NEWNYM)
:core:vpn     Android lib: PrivacyVpnService (VpnService, pumps, hev glue, DNS responder,
              UID attribution, boot receiver), diagnostics hub, service locator (U)
:app          Compose UI (dashboard, apps, dns, tor, routing, diagnostics, settings)
```

Pure-JVM modules keep all network logic unit-testable without a device.
The Android libs are thin adaptation layers.

## Data plane

```
                ┌────────────────────────────────────────────────────┐
                │                    TUN fd (VpnService)             │
                └───────────────┬────────────────────────────────────┘
                                │ FileInputStream (blocking, dedicated thread)
                                ▼
                      IpCodec.parse (IPv4/IPv6 + TCP/UDP headers)
                                │
                        PacketFilter.decide
              ┌───────────┬─────────────┬──────────────┬─────────────┐
              ▼           ▼             ▼              ▼             ▼
          DnsLocal     Drop          Reset           Pass        (non-IP: drop)
              │     (policy/UDP)  (blocked SYN)        │
              ▼                                       ▼
        DnsEngine (suspend)              socketpair(AF_UNIX, SOCK_SEQPACKET)
        DoH/DoT/passthrough                          │ (packet-boundary preserving)
              │                                      ▼
              └────► TUN (crafted response)   hev-socks5-tunnel (C, MIT)
        (IpCodec.buildUdp4/6, correct                        │ SOCKS5 127.0.0.1:10808
         checksums incl. mandatory v6)                       ▼
                                              SocksRelayServer (Kotlin, loopback,
                                              UID-allowlist on accept)
                                                       │ RoutingPolicy (global route)
                              ┌──────────────┬─────────┴────────┐
                              ▼              ▼                  ▼
                          DIRECT          TOR                PROXY (SOCKS5)
                    (resolve via DoH,  (Socks5Client →    (Socks5Client →
                     then connect)      TorService SOCKS,   user proxy,
                                        hostname remote)   hostname remote)
```

Reverse path: hev writes response packets into the socketpair; a second
thread copies them to the TUN fd. All TUN writes are serialized under one
lock; DNS responses are written from coroutines under the same lock.

### Why the socketpair interposer?

Per-app blocking requires attributing each packet to a UID **before** the
traffic is re-originated by tun2socks. hev-socks5-tunnel takes ownership of
the TUN fd via `TProxyStartService(config, fd)`; interposing a
`SOCK_SEQPACKET` socketpair in front of it lets the JVM filter parse original
tuples (src port → `getConnectionOwnerUid`) and drop/reset/passthrough, while
hev still sees a packet-framed fd. Verified against hev sources: an fd that
fails `TUNGETIFF` is handled as "plain packets" (no virtio headers), and
`FIONBIO` is applied to whatever fd it receives.

### DNS inside the tunnel

Every UDP/53 datagram in the tunnel is answered by the local engine — no
matter which resolver address the network pushed. Responses are built with
correct IPv4/IPv6 + UDP checksums (IPv6 UDP checksum is mandatory; unit
tests verify both). Non-DNS UDP defaults to drop (QUIC-hardening; forces
apps onto the enforced TCP path). Cache honors TTLs; reverse zones bypass
the cache.

### Routing semantics (v0.1, deliberately honest)

- **Block** — per app, per network kind; enforced at packet level (SYN→RST,
  established→drop).
- **Bypass** — per app; enforced via `addDisallowedApplication` (the app then
  uses direct, unfiltered connectivity).
- **Tunnel** — app traffic enters the data plane; the *upstream* is the
  global route: Direct / Tor / custom SOCKS5.
- **Strict no-fallback** — if the chosen upstream is unavailable, the relay
  refuses the connection (SOCKS reply 0x05 / blocked 0x02). Tested.

#### Known limitation: per-app upstream

hev's SOCKS client does not bind original source ports (verified:
`hev_socks5_bind` is a no-op), so when hev connects to the relay, the
connection no longer maps to the originating app — all tunnelled connections
look like they belong to Umbral itself. Per-app Tor-vs-Direct selection
*inside* the tunnel is therefore impossible in this design. Options for the
future: (a) port NetGuard's userspace TCP stack (GPL-compatible), (b) an
fd-attribute-preserving tun2socks, (c) upstream contribution to hev.

## Tor integration

`TorController` (core:tor) wraps `org.torproject.jni.TorService`:
- writes `torrc` (ClientOnly, AvoidDiskWrites, optional bridges +
  `ClientTransportPlugin … socks5 127.0.0.1:<IPtProxy port>` with an
  allow-list for extra torrc options),
- binds the service (`LocalBinder`) to read `getSocksPort()`,
- listens for `ACTION_STATUS` LocalBroadcasts (OFF/STARTING/ON/STOPPING),
- attaches a `RawEventListener` for `STATUS_CLIENT` BOOTSTRAP progress,
- exposes `newIdentity()` via `SIGNAL NEWNYM`.

TorService itself sets SOCKSPort 9050 (or auto) in its own torrc-defaults;
our code must not fight it.

## Failure modes

| Failure | Behavior |
|---|---|
| hev fails to start | Tunnel torn down, error surfaced on dashboard |
| Tor down / bootstrapping, route=TOR | Connections refused (strict), UI shows bootstrap % |
| Custom proxy unreachable | Connections refused (strict) |
| DoH/DoT upstream fails | DNS answered SERVFAIL; diagnostics log the error |
| Malformed packet | Dropped silently |
| VPN permission revoked (`onRevoke`) | Clean teardown |
| Boot with consent missing | Auto-start skipped silently |

## Threading

- `umbral-tun-read`: blocking TUN reads, filtering, DNS hand-off.
- `umbral-hev-read`: socketpair → TUN copy.
- Relay: coroutine per connection on Dispatchers.IO (SupervisorJob).
- DNS engine: suspend, runs in the service scope.
- UI: Compose; state via StateFlows from the `U` kernel singleton.

## Build/toolchain notes

- AGP 8.10.1, Kotlin 2.1.21, compileSdk 37 (forced by tor-android's AAR
  metadata), minSdk 29 (forced by hev AAR + getConnectionOwnerUid), targetSdk 35.
- NixOS: `shell.nix` composes a patched SDK (platform 37, build-tools 36.1.0)
  and `scripts/build-nix.sh` points AGP at the patched aapt2
  (`android.aapt2FromMavenOverride`).
