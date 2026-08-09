# Code review — PR #1: Accept compressed payloads up to Android's 10 MiB decompressed ceiling

> **Two passes recorded.** [Pass 2](#pass-2--head-0c93fee) reviews the current head and supersedes pass 1;
> pass 1 is kept below for the history of what was raised and how it was resolved.

---

# Pass 2 — head `0c93fee`

**Target:** `claude/bitchat-top-5-issues-oqdx8h` → `main` (head `0c93fee`, base `1f59e81`)
**Scope:** 4 files, +292/−33 — adds `GossipSyncManager.swift`, `GossipSyncManagerTests.swift`
**Verdict:** Both pass-1 merge gates are genuinely fixed. The fixes introduce one new finding of comparable
severity (#1 below) plus three smaller ones. Not yet mergeable, but closer.

## Pass-1 findings: all four addressed

| # | Pass-1 finding | Status |
|---|---|---|
| 1 | Count-capped `PacketStore` → ~10 GB retained | **Fixed** — `Config.storeByteBudget` (32 MiB per store), byte accounting maintained across insert/replace/remove, `packetStoreEvictsOldestPastByteBudget` covers it |
| 2 | Re-encode black hole via `shouldCompress` heuristic | **Fixed** — `mustCompressToFit` forces compression when the frame can't otherwise fit the wire cap; `cyclicPayloadRoundTripsDespiteHeuristic` pins it |
| 3 | Inaccurate "no compliant decoder accepts" comment | **Fixed** — now documented as necessary-not-sufficient, naming BLE's stricter 1 MiB non-file limit |
| 4 | Rejection warning logged twice per frame | **Fixed** — `decodeCore(_:logRejections:)`, unpad retry suppressed |

The `logRejections: false` suppression is safe: `decodeCore` ignores trailing padding, so the first pass is
the meaningful one and the retry can only re-derive the same verdict.

## New findings

### 1. The byte budget stopped at `PacketStore`; `latestAnnouncementByPeer` is still unbounded (blocker)

`GossipSyncManager.swift:277`

The fix for pass-1 #1 bounded the four `PacketStore` instances. But announcements don't use `PacketStore` —
they land in a plain dictionary with no count cap and no byte budget:

```swift
case .announce:
    guard isPacketFresh(packet) else { return }
    guard isAnnouncementFresh(packet) else { ... }
    let sender = PeerID(hexData: packet.senderID)
    latestAnnouncementByPeer[sender] = packet   // uncapped, retains full payload
```

The key is `packet.senderID` — **unauthenticated**, 8 bytes, attacker-chosen. Each fabricated sender ID
creates a distinct entry retaining a payload of up to the new 10 MiB ceiling, evicted only when it falls out
of the 60-second `stalePeerTimeoutSeconds` window.

What makes this the clearest finding in the PR: the code immediately below it already diagnoses this exact
attack for prekey bundles and defends against it —

```swift
// Key by the bundle's authenticated identity (its noise static key),
// NOT the unauthenticated packet senderID. Otherwise one valid
// bundle re-broadcast under many fabricated sender IDs would create
// one cache entry each and exhaust the per-owner cap...
```

— and the announce path does neither the authenticated keying nor the cap. Before this PR the hole was
bounded at ~1.13 MiB per entry; the ceiling raise multiplies it ~9×, which is the same reasoning that made
pass-1 #1 a blocker.

`latestPrekeyBundleByPeer` is a lesser case of the same gap: count-capped at `prekeyBundleCapacity = 200`
(`GossipSyncManager.swift:105`) but with no byte budget, so 200 × 10 MiB ≈ 2 GB.

*Suggested fix:* apply a byte budget to both maps, and cap announce entries the way prekeys already are.

---

### 2. `mustCompressToFit` widens the documented signing-canonicalization gap

`BinaryProtocol.swift:163`

The compression decision is part of the canonical signing bytes — `toBinaryDataForSigning` re-encodes, so
verification reproduces the sender's compression choice locally. The PR body already documents this class of
problem as pre-existing (upstream #933), and that framing is fair. Worth recording that this change widens it
slightly rather than leaving it flat:

```swift
let mustCompressToFit = payload.count > FileTransferLimits.maxFramedFileBytes
if CompressionUtil.shouldCompress(payload) || mustCompressToFit {
```

The decision now depends on `FileTransferLimits.maxFramedFileBytes` — a **locally computed** constant
(it derives from `UInt16.max`-sized TLV metadata plus header sizes), not a value carried on the wire. Two
peers that disagree on that constant now disagree on the canonical bytes for any payload between the two
values. Previously the decision depended only on payload content, which at least made it derivable from data
both sides hold.

Practical exposure is small — old-code peers reject these frames at decode anyway — so this is a note for the
#933 work, not a merge gate. It does mean `maxFramedFileBytes` is now load-bearing for signature validity and
should not be tuned casually.

---

### 3. Forced compression makes a ~10 KB frame buy up to three 10 MiB codec passes

`BinaryProtocol.swift:164`

With the ceiling at 10 MiB and `mustCompressToFit` in place, one hostile ~10 KB frame at the newly permitted
~1030:1 ratio costs the receiver one 10 MiB inflate, plus a 10 MiB **deflate** on the signature-verify
re-encode and another on the relay re-encode. Deflate at 10 MiB is far more expensive than inflate, and
`mustCompressToFit` means it can no longer be skipped for exactly these oversized payloads.

The byte budget added in this revision bounds *retained memory*, which was the pass-1 concern, but does
nothing for CPU. Sustained at link rate this is a plausible CPU-exhaustion path that was unreachable before
the ceiling raise.

---

### 4. A single 32 MiB budget across all four stores silently shrinks file-transfer backfill

`GossipSyncManager.swift:80`

`storeByteBudget` is applied per store, but it's one value for four stores with very different entry sizes.
`fileTransferCapacity` is 200, yet file payloads are validated at up to 1 MiB — so the byte budget binds
first, at roughly 32 entries. Gossip backfill for file transfers drops ~6× on entirely ordinary traffic, with
no log line marking the change.

That may well be the right trade, but it should be a deliberate per-store number rather than a side effect of
one shared constant.

---

### 5. Minor: the replace path doesn't refresh recency, so the newest-entry invariant can fail

`GossipSyncManager.swift:22`

The comment promises "Never evict the newest entry," and the loop guard `order.count > 1` implements that for
insertions. But the replace branch updates `packets` and byte accounting without moving the key to the tail of
`order`, so a replaced entry keeps its old position and can be evicted on the very next insert.

Not reachable today: `PacketIdUtil.computeId` hashes the payload, so a replace always carries an identical
payload and contributes no new eviction pressure. Worth fixing anyway now that `PacketStore` has been widened
from `private` to internal and is directly unit-tested — the test doesn't cover this path.

---

### 6. Minor: rejection warnings remain unthrottled

`BinaryProtocol.swift:411`

The double-log is fixed, but a burst of malformed frames still writes to the security log at link rate. Same
suggestion as pass 1: rate-limit.

## Recommendation

Resolve #1 (byte-bound `latestAnnouncementByPeer` and `latestPrekeyBundleByPeer`, and cap announces by
authenticated identity as prekeys already are). Decide #4 deliberately. #2, #3, #5, #6 can be follow-ups, with
#3 worth a tracking issue since it's a real consequence of the ceiling raise.

---

# Pass 1 — head `19c35b9`

**Target:** `claude/bitchat-top-5-issues-oqdx8h` → `main` (head `19c35b9`, base `1f59e81`)
**Scope:** 2 files, +160/−6 — `BinaryProtocol.swift`, `BinaryProtocolTests.swift`
**Verdict:** Core change is correct and well-tested. Four findings below; #1 is a merge blocker, #2 is a
correctness regression on the exact packets this PR sets out to admit.
**Outcome:** all four addressed in `17d508d` / `0c93fee` — see the pass-2 table.

---

## What checks out

- **The 1,100:1 ratio bound is safe.** Verified empirically: raw deflate at zlib level ≥5 tops out at
  **1027.6:1** on maximally compressible input, against a format-level maximum of 1032:1. The new bound has
  real headroom and cannot reject a legitimate frame. `payloadAtDecompressedCeilingRoundTrips` exercises
  exactly this boundary at 10 MiB, so the margin is pinned by a test rather than by argument.
- **The dropped `originalSize >= 0` check was dead code.** `originalSize` derives from `read16`/`read32`
  unsigned reads, so it can never be negative. Removing it loses nothing.
- **The hostile-frame tests are honestly constructed.** `compressedPayloadAboveDecompressedCeilingIsRejected`
  builds a *real* deflate stream declaring 10 MiB + 1 — only the ceiling guard can reject it, so the test
  genuinely fails if that guard is removed. It also survives the `unpad` retry path in `decode(_:)`, which is
  easy to get wrong. `oversizedWireFrameIsRejectedOnDecode` pins the wire cap independently.
- **Encode/decode bounds are symmetric at 10 MiB**, and `decompressedCeilingMatchesProtocolContract` pins the
  constant to Android's `MAX_PAYLOAD_LENGTH` so the two independently-defined limits can't drift silently.

---

## Findings

### 1. The 10 MiB ceiling feeds count-capped caches — ~10 GB worst case (blocker)

`BinaryProtocol.swift:397`

The PR body lists burst amplification under "known limitations, out of scope." It shouldn't be out of scope,
because the amplification lands in a cache that this repo controls and that is capped by **count, not bytes**.

`GossipSyncManager.PacketStore` (`bitchat/Sync/GossipSyncManager.swift:14-30`) retains whole `BitchatPacket`
values — decompressed payload included — and evicts only when `order.count > capacity`:

```swift
packets[idHex] = packet
order.append(idHex)
while order.count > capacity {
    let victim = order.removeFirst()
    packets.removeValue(forKey: victim)
}
```

With `seenCapacity = 1000` (`GossipSyncManager.swift:64`), the retained-bytes ceiling is
`1000 × maxDecompressedPayloadBytes` = **~10 GB**. The attacker's cost is the *wire* size: at the newly
permitted ~1030:1 ratio, ~10.2 KB of hostile frame buys 10 MiB of retained RAM, so ~10 MB of transmitted data
pins ~10 GB. Every archive flush then re-encodes the whole set.

Before this PR the same cache was implicitly bounded at `1000 × maxFramedFileBytes` ≈ 1.1 GB — already
uncomfortable, but the change multiplies it ~9×. The ceiling raise and a byte budget on `PacketStore` need to
land together; the parity fix is correct, but it converts a latent bound into an exploitable one.

*Suggested fix:* give `PacketStore.insert` a byte budget alongside `capacity`, evicting on whichever binds
first. That is a contained change and keeps the parity fix intact.

---

### 2. The encoder wire cap makes newly-admitted packets un-relayable and un-persistable

`BinaryProtocol.swift:190`

The new sender-side guard rejects any frame whose `payloadDataSize` exceeds `maxFramedFileBytes` (~1.13 MiB).
The problem is that whether a payload is compressed on the way out is decided by a heuristic that does not
measure compressibility:

```swift
// CompressionUtil.swift:68-71
let uniqueByteCount = Set(data).count
let sampleSize = min(data.count, 256)
let uniqueByteRatio = Double(uniqueByteCount) / Double(sampleSize)
return uniqueByteRatio < 0.9
```

`uniqueByteCount` is computed over the **whole** payload while `sampleSize` saturates at 256. Any payload
containing all 256 byte values therefore scores 1.0 and is declined for compression — regardless of how
compressible it actually is. A 2 MiB payload cycling `0...255` is ~1000:1 compressible and is exactly the kind
of packet this PR exists to accept.

Such a packet decodes fine, and then cannot be re-encoded: `encode` skips compression, `payloadDataSize` stays
at 2 MiB, and the new guard returns `nil`. Every downstream path that re-serializes a decoded packet drops it:

- `BLEService.swift:2104` — `broadcastPacket` → relay dies at this node
- `GossipSyncManager.swift:644` — `.compactMap { $0.toBinaryData(padding: false) }` → silently excluded from sync
- archive persist / `BoardStore`

So the PR admits a class of packet on receive and then makes this node a black hole for it. That is a
*narrower* silent drop than the one being fixed, but it is the same failure mode, newly introduced.

*Suggested fix:* apply the wire cap only to the uncompressed case, or make `shouldCompress` fall back to
trial compression when the payload is large — a 2 MiB payload can afford one compress attempt.

---

### 3. The fail-fast guard's justifying comment is inaccurate

`BinaryProtocol.swift:187`

The comment claims "no compliant decoder accepts a wire frame above the framed-file cap." The receivers are
actually *stricter* and differently-scoped than that:

- BLE reassembly caps non-file packet types at `FileTransferLimits.maxPayloadBytes` = **1 MiB**, not
  `maxFramedFileBytes` ≈ 1.13 MiB.
- Nostr ingest caps the **whole frame**, not `payloadDataSize`.

So there is a band between the guard's bound and the receivers' real limits where the encoder happily emits a
frame that still gets silently dropped — the very outcome the guard advertises as eliminated. The guard is
worth keeping; the comment overstates what it buys, which will mislead the next person who reasons about
these limits from the comment rather than the receivers.

---

### 4. The new rejection warning fires twice per frame, unthrottled

`BinaryProtocol.swift:398`

`decode(_:)` retries through `decodeCore` twice:

```swift
if let pkt = decodeCore(data) { return pkt }
let unpadded = MessagePadding.unpad(data)
if unpadded as NSData === data as NSData { return nil }
return decodeCore(unpadded)
```

A rejected frame whose trailing bytes form valid PKCS#7 padding — the normal case for anything this client
emitted, and trivially attacker-controlled — logs the ceiling warning on both passes. The log line is also
unthrottled, so a hostile burst floods it. Since this logging exists to serve issue #1628 (surface silent
rejections), duplicated and floodable output undercuts the goal.

*Suggested fix:* log at the `decode(_:)` boundary rather than inside `decodeCore`, or rate-limit the warning.

---

## Notes on the PR body's own caveats

The **signing canonicalization** caveat is stated correctly. Verification re-encodes via
`toBinaryDataForSigning` → `BinaryProtocol.encode`, so both new guards sit on that path — but the reasoning in
the PR body holds: any frame whose verification could have passed arrived under the wire cap, and its faithful
re-encoding stays under it. The new guards don't flip a passing verification to failing.

The **burst amplification** caveat is stated accurately but mis-triaged — see finding #1.

---

## Recommendation

Land the parity fix; it is the right change and the tests are unusually good. Before merge, resolve #1 (byte
budget on `PacketStore`) and #2 (re-encode black hole). #3 and #4 are comment/logging cleanups that can ride
along.
