# Privacy manifest

Umbral is a privacy tool. That claim is only worth something if it is precise.
This document lists **every outbound connection the app can make**, what
triggers it, and what the peer can observe. There is no analytics, no crash
reporting, no update checking, no "phoning home" of any kind.

## Data that never leaves the device

- All configuration (app rules, DNS settings, bridges, proxy credentials)
  is stored in app-private storage via DataStore. `allowBackup=false`;
  cloud backup and device-transfer of app data are excluded.
- Diagnostics logs (connections, DNS queries, Tor log tail) live in memory
  only, capped at 500 entries, and are lost on restart.
- Exported configuration leaves the device **only** if you explicitly pick a
  file via the system file picker (`Settings → Export`).

## Outbound connections

| # | When | Destination | Purpose | What the peer sees |
|---|------|-------------|---------|--------------------|
| 1 | VPN active, DNS mode DoH | The chosen DoH provider (e.g. `cloudflare-dns.com`) | Resolve names asked by apps in the tunnel (POST `application/dns-message`) | Your IP (unless "via Tor"), the query names, TLS SNI (the provider host) |
| 2 | VPN active, DNS mode DoT | Chosen provider, port 853 | Same over TLS | Your IP, query names, SNI |
| 3 | VPN active, DNS mode passthrough | The resolver the network handed the device | Forward the original query unmodified | Everything: plaintext queries |
| 4 | VPN active, route Direct | Whatever apps in the tunnel connect to | Re-originate app TCP connections | Your IP; TLS content stays end-to-end encrypted by the app itself |
| 5 | VPN active, route Tor | Tor guard/relay/bridge endpoints | Tunnelled traffic + Tor's own directory fetches | That you use Tor (bridges mitigate); not the destinations |
| 6 | Tor with bridges | The bridge addresses you configured | Connect to Tor via pluggable transports | Bridge sees a Tor client; obfs4/webtunnel/snowflake disguise the protocol |
| 7 | Route Proxy | Your configured SOCKS5 host | Tunnelled traffic | The proxy sees everything you send it (it is a trusted hop by definition) |
| 7a | I2P module on | i2pd reseed hosts (HTTPS), then I2P routers (NTCP2 TCP / SSU2 UDP) | Join the I2P network and route `*.i2p` traffic | Reseed hosts see your IP once at bootstrap (use a bridge/VPN if that matters); I2P peers see your (random, non-IP) router identity; destination eepsites see the tunnel, not you |
| 7b | I2P transit enabled (off by default) | Random I2P peers | You relay others' encrypted I2P traffic | Peers see your router identity; bandwidth is consumed |
| 8 | DoH-via-Tor | DoH provider through Tor exit | Hide your IP from the resolver | Resolver sees a Tor exit; Tor sees you use encrypted DNS (not the contents) |

**DNS upstreams are user-selected.** Umbral ships suggestions; it never
overrides your choice and has no provider of its own. No request is ever sent
to any umbral/developer-controlled host.

## What the OS and others can still observe

- The Android OS (and any party that compromises it) sees everything.
- Your network sees: that a VPN is up, the volume/timing of encrypted traffic,
  the IPs of Tor guards/bridges or the DoH/DoT provider, and the VPN's own
  TLS-less TCP re-origination targets when routing Direct (see
  docs/THREAT_MODEL.md — Direct is not anonymity).
- Apps you mark **Bypass** use direct, unfiltered connections.
- Tor guards know your IP; Tor exits see your traffic destinations and
  plaintext content of any non-TLS protocol you use over Tor.
- A global passive adversary can attempt traffic correlation on Tor. This is
  a fundamental Tor limitation, not something this app can fix.

## Local attack surface (documented honestly)

- The local SOCKS relay binds to `127.0.0.1:10808`. Android loopback is shared
  between all apps, so a malicious app could try to use the relay. Mitigation
  implemented: on Android 10+ the relay rejects connections not owned by
  Umbral's own UID (verified via `ConnectivityManager.getConnectionOwnerUid`).
  On the pre-provisioning code path where the owner cannot be determined,
  the connection is served (documented residual risk).
- Tor's SOCKS/HTTP ports (9050/8118 by default, loopback) are provided by the
  bundled TorService and — like in Orbot — are reachable by other apps on the
  device. This is the standard "share Tor with other apps" behavior of
  tor-android; treat it as a feature and a risk.
