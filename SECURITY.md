# Security policy

## Reporting a vulnerability

Open a private security advisory on the repository (GitHub → Security →
"Report a vulnerability") or contact the maintainers listed in the README.
Please do not open public issues for exploitable bugs. We aim to respond
within 72 hours.

## Engineering security rules

1. **No custom cryptography.** Only standard, platform-provided primitives
   (AES-256-GCM, PBKDF2-HMAC-SHA256 with 210k iterations, TLS via the
   platform/OkHttp stacks) and standard protocols (SOCKS5 RFC 1928/1929,
   DoH RFC 8484, DoT RFC 7858, DNS wire format RFC 1035).
2. **Fail closed.** If an anonymizing upstream is unavailable, connections
   are refused. Direct fallback exists only as an explicit user opt-out
   (`strict no-fallback` toggle) and is loudly labeled in the UI.
3. **Loopback-only services.** The SOCKS relay binds to loopback and rejects
   foreign-UID connections where the platform allows verification.
4. **Least privilege.** Permissions are enumerated in README with reasons;
   there is no location, storage, contacts, or telephony access.
5. **Local-only state.** Configuration and diagnostics never leave the device
   without an explicit user action.
6. **Pinned, verified third-party binaries.** Native AARs are fetched by
   `scripts/fetch-native-deps.sh` with SHA-256 verification; coordinates and
   licenses are listed in README. No snapshot dependencies.
7. **Safe parsing.** Wire parsers (DNS, IP, SOCKS5) are defensive, unit
   tested against malformed input, and treat parse failures as drops, never
   as crashes.
8. **Known-broken things are documented, not hidden**: see
   docs/IMPLEMENTATION_STATUS.md.

## Build integrity

- CI builds from source on every push; artifacts are produced by GitHub Actions.
- Release builds are unsigned by default; signing is the responsibility of the
  distributor (F-Droid signs with its own keys, reproducibly).
- We do not claim reproducible builds yet — that work is on the roadmap.
