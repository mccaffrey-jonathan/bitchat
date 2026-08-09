# Code review — PR #1: Accept compressed payloads up to Android's 10 MiB decompressed ceiling

**Target:** `claude/bitchat-top-5-issues-oqdx8h` → `main` (head `19c35b9`, base `1f59e81`)
**Scope:** 2 files, +160/−6 — `BinaryProtocol.swift`, `BinaryProtocolTests.swift`
**Verdict:** Core change is correct and well-tested. Four findings below; #1 is a merge blocker, #2 is a
correctness regression on the exact packets this PR sets out to admit.

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
