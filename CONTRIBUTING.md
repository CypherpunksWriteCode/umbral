# Contributing

Thank you for considering a contribution.

## Ground rules

- Small, reviewable, tested changes. Every behavior change ships with a test
  where testable (the routing policy, packet filter, SOCKS/DNS codecs and
  config layers are all pure JVM and cheap to test).
- No new permission without a written justification in README.
- No analytics/tracking/ad SDKs — ever. No new network endpoints without
  adding them to PRIVACY.md.
- No invented cryptography. Standard primitives and formats only.
- Anti-hallucination: verify APIs against the actual dependency version you
  build against; if something is unverified, mark it in the PR and in
  docs/IMPLEMENTATION_STATUS.md.
- Bugs are never papered over: docs/IMPLEMENTATION_STATUS.md tracks honest
  status (`IMPLEMENTED AND TESTED`, `IMPLEMENTED, NOT FULLY TESTED`,
  `PARTIALLY IMPLEMENTED`, `NOT IMPLEMENTED`, `BLOCKED BY PLATFORM LIMITATION`).

## Development

```bash
./scripts/fetch-native-deps.sh
./gradlew test
./gradlew :app:assembleDebug
```

On NixOS: `./scripts/build-nix.sh test` etc. (see README).

## Commit style

Imperative subject line ≤ 72 chars, body explains *why*. No secrets, ever.
