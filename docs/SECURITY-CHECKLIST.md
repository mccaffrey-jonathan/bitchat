# bitchat per-file security checklist

The checklist the automated review sweep applies to one file at a time. It is
derived from the scope declared in `SECURITY.md` and from the properties
`WHITEPAPER.md` claims, so a finding here should map to something the project
actually promises rather than to a generic lint rule.

Every finding must cite a check ID from this file. A finding that cannot cite
one is out of scope — say so and move on.

## How to apply it

Read the whole file first. Then walk the checks below, skipping any category
the file cannot possibly implicate (a pure SwiftUI layout file does not
implicate NOISE-*). For each check that the file *does* implicate, decide one
of three outcomes:

- **pass** — the file handles the concern, cite the line that does it.
- **finding** — the file violates the concern, cite the line and describe the
  attacker action it enables.
- **n/a** — the file does not touch this concern at all.

Report only findings and non-obvious passes. Do not pad the report with `n/a`
rows. Never report style, naming, formatting, or test coverage as a security
finding.

Severity is about what an attacker gains, not how ugly the code is:

- **critical** — plaintext exposure of private message content, private key
  disclosure, or authentication bypass, reachable by a remote or in-radio-range
  attacker without user interaction.
- **high** — the same outcomes but requiring a precondition (a specific state,
  a malicious peer already paired, a race), or a silent downgrade to an
  unencrypted path.
- **medium** — metadata leakage beyond what `PRIVACY_POLICY.md` and
  `docs/privacy-assessment.md` already disclose, remotely triggerable resource
  exhaustion, or incomplete destruction of data the panic wipe claims to erase.
- **low** — defense-in-depth gaps with no demonstrated attacker gain.

If you cannot describe the attacker's concrete gain in one sentence, it is not
a finding. Prefer reporting nothing over reporting speculation — a sweep that
emits five real findings is worth more than one that emits fifty maybes.

## Out of scope — do not report these

`SECURITY.md` documents these as design properties. Reporting them is noise:

- Public visibility of mesh announces, geohash channels, broadcast content,
  nicknames, and public keys.
- The fact that a BLE device is observable to anyone in radio range.
- Mesh flooding and relay amplification inherent to a broadcast mesh.
- Behavior of third-party Nostr relays.
- Denial of service requiring physical proximity, and battery-drain attacks.
- Absence of forward secrecy on store-and-forward mail (documented in the
  whitepaper).

---

## CRYPTO — primitive and key handling

- **CRYPTO-01** Nonce/IV uniqueness. Any counter, random, or derived nonce fed
  to an AEAD must be unique per key. Flag counters that can wrap, reset on
  reconnect, restore from persisted state, or be driven by a peer-supplied
  value.
- **CRYPTO-02** Randomness source. Key material, nonces, ephemeral IDs, and
  padding must come from a CSPRNG (`SecRandomCopyBytes`, `CryptoKit`, or
  `systemRandom`-backed helpers), never `arc4random_uniform` bias patterns,
  `Int.random` seeded fallbacks, or a time-derived value.
- **CRYPTO-03** Constant-time comparison. MAC tags, key fingerprints, auth
  tokens, and PoW targets must not be compared with `==` on `Data`/`String`
  where an early-exit leaks position. Look for a constant-time helper.
- **CRYPTO-04** Key lifetime in memory. Private keys and session secrets should
  be zeroed after use where the language allows, and must not be copied into
  long-lived caches, `String`, or logging interpolation.
- **CRYPTO-05** Algorithm agility / downgrade. A peer-supplied version, suite,
  or algorithm identifier must be validated against an allowlist. Flag any path
  where an unrecognized value falls through to a weaker or plaintext branch.
- **CRYPTO-06** Custom crypto. Hand-rolled padding, KDF, or AEAD composition
  (including `XChaCha20Poly1305Compat`, `Bech32`, `Base64URLCoding`) must match
  its specification exactly. Check length handling and reject-on-malformed.

## NOISE — mesh session security

- **NOISE-01** Handshake state machine. Messages must be rejected when they
  arrive in the wrong state. Flag any transition that accepts a handshake
  message while a session is already established, or that lets a peer reset an
  established session without authentication.
- **NOISE-02** Identity binding. The static key proven in the handshake must be
  bound to the peer ID used for routing and display. Flag any path where a peer
  ID is trusted before the handshake completes.
- **NOISE-03** Replay and reordering. Check for a replay window, a monotonic
  message counter, and rejection of duplicates. Cross-reference
  `NoiseSecurityValidator` and `NoiseSecurityConstants`.
- **NOISE-04** Rate limiting. Handshake initiation and rekey must be bounded
  per peer (`NoiseRateLimiter`), or a peer can force unbounded key agreement
  work.
- **NOISE-05** Error disclosure. `NoiseSecurityError` / `NoiseSessionError`
  values surfaced to a peer or to logs must not distinguish "bad MAC" from
  "unknown peer" in a way that oracles key state.

## NOSTR — internet transport and private envelopes

- **NOSTR-01** Envelope confidentiality. The private-envelope format is
  proprietary and explicitly *not* NIP-17/44/59. Verify the payload is sealed
  before it reaches a relay and that no field outside the seal carries message
  content.
- **NOSTR-02** Ephemeral identity separation. Per-geohash keys
  (`NostrIdentity`, `NostrIdentityBridge`) must not be derivable from, or
  reused across, the mesh identity or another geohash. Flag any shared salt or
  deterministic derivation that links them.
- **NOSTR-03** Relay input validation. Anything parsed from a relay
  (`NostrRelayManager`, `GeoRelayDirectory`, `NostrRelayURL`) is attacker
  controlled. Check bounds, type confusion, and unbounded collection growth.
- **NOSTR-04** PoW handling. `NostrPoW` difficulty must be validated, not
  trusted, and must not allow an attacker to force unbounded local work.
- **NOSTR-05** Relay URL handling. Scheme must be constrained to `wss://`
  (or `ws://` only where explicitly intended); flag redirect-following or
  host confusion that could move traffic off the intended relay.

## TOR — routing integrity

- **TOR-01** No bypass while enabled. Every outbound connection — Nostr
  websockets, media fetch, relay directory refresh, geohash presence — must go
  through the Tor session when the preference is on. Flag any `URLSession`,
  `NWConnection`, or `Network` use that does not route through `TorURLSession`.
- **TOR-02** Fail-closed. If Tor is enabled and unavailable, the code must fail
  the request, not silently fall back to a direct connection.
- **TOR-03** Startup and teardown races. Requests issued before the Tor circuit
  is ready, or during teardown, must be queued or rejected — not sent direct.
- **TOR-04** DNS and side channels. Hostname resolution must not happen outside
  the proxy.

## IDENT — identity, keys at rest, verification

- **IDENT-01** Keychain usage. Items must set an appropriate accessibility
  class (no `kSecAttrAccessibleAlways`), and must not be synchronized to iCloud
  unless intended.
- **IDENT-02** Fingerprint and verification UI. The value shown to the user for
  out-of-band verification must be derived from the key actually used to
  encrypt, with no truncation that makes collisions feasible.
- **IDENT-03** Trust state transitions. A peer's verified state must not be
  inherited by a new key, a rotated peer ID, or a reconnect
  (`SecureIdentityStateManager`, `docs/PEER-ID-ROTATION.md`).
- **IDENT-04** Impersonation via display name. Nicknames are attacker chosen;
  check that trust decisions key on the fingerprint, never the nickname.
- **IDENT-05** Alias/petname storage must not leak the mapping to the network.

## WIPE — panic destruction

- **WIPE-01** Coverage. The wipe must reach every store the file writes to:
  Keychain, `UserDefaults`, Core Data / SQLite, caches, temp files, media on
  disk, and in-memory caches. Flag any store this file creates that the wipe
  path does not clear.
- **WIPE-02** Ordering and completeness. The wipe must not leave a
  partially-cleared state recoverable after a crash mid-wipe.
- **WIPE-03** No resurrection. Nothing may repopulate wiped state from a
  surviving cache, a pending write, or an in-flight task after the wipe.

## PROTO — binary protocol parsing

- **PROTO-01** Bounds and integer safety. Every length, offset, and count read
  from a packet must be range-checked before use. Flag arithmetic on
  peer-supplied lengths that can overflow or produce a negative index.
- **PROTO-02** Allocation bounds. A peer-supplied length must not drive an
  unbounded `Data(count:)`, array reserve, or decompression (LZ4 in particular
  — check the decompressed-size cap).
- **PROTO-03** TTL and relay bounds. Hop limits must be enforced on receive,
  not just on send.
- **PROTO-04** Fragment reassembly. Reassembly buffers must be bounded per peer
  and time-limited, with overlapping/duplicate fragments rejected.
- **PROTO-05** Type confusion. An unknown message type must be dropped, never
  coerced into a neighboring type.

## PRIV — metadata beyond what is documented

- **PRIV-01** Logging. No key material, message plaintext, precise location,
  or stable identifier in logs — including `BitLogger` categories, `os_log`
  format strings, and `print`. Check that redaction is not defeated by string
  interpolation before the call.
- **PRIV-02** Location precision. Geohash precision sent to the network must
  match the precision the user selected; flag any path that transmits finer
  coordinates than the chosen channel implies.
- **PRIV-03** Persistent identifiers. Any identifier that survives a restart
  and is observable on the wire must already be disclosed in
  `docs/privacy-assessment.md`.
- **PRIV-04** Timing and traffic shape. Flag newly introduced request patterns
  that fingerprint a user across geohashes or across transports.
- **PRIV-05** Third-party egress. No analytics, crash reporting, or telemetry
  to any host not already documented.

## DOWNGRADE — silent moves to a weaker path

- **DOWNGRADE-01** Transport selection. The Bluetooth-to-Nostr fallback must
  not move a message from an encrypted path to an unencrypted one without the
  user's knowledge.
- **DOWNGRADE-02** Failure handling. An encryption or handshake failure must
  drop the message, not send it in the clear.
- **DOWNGRADE-03** UI truthfulness. Any indicator claiming a message is
  encrypted or verified must reflect the path actually used.

## SUPPLY — source and vendored binary integrity

- **SUPPLY-01** Vendored binaries. Changes to `arti.xcframework` or any
  binary target must be reflected in `docs/ARTI-BINARY-PROVENANCE.md` and the
  hash manifest.
- **SUPPLY-02** Dependency pinning. New dependencies must be exact-pinned in
  `Package.swift` / `Package.resolved`.
- **SUPPLY-03** Build-time code execution. Flag build plugins, scripts, or
  `Package.swift` logic that fetches or executes anything at build time.

## PLAT — platform and memory safety

- **PLAT-01** Unsafe pointers. `withUnsafeBytes`, `UnsafeRawPointer`,
  `memcpy`, and `assumingMemoryBound` must have provably correct bounds and
  lifetimes.
- **PLAT-02** Force unwraps and `try!` on attacker-controlled input — a remote
  crash is a medium-severity DoS.
- **PLAT-03** Concurrency. Shared mutable state reachable from the BLE
  delegate queue, the Nostr socket queue, and the main actor must be
  synchronized; a data race on session state can produce nonce reuse.
- **PLAT-04** File paths. Any path built from network- or peer-supplied data
  (media filenames in particular) must be sanitized against traversal.
- **PLAT-05** Pasteboard, screenshots, and background snapshots must not expose
  private message content.
