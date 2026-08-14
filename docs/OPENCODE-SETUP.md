# opencode security sweep

An [opencode](https://opencode.ai) setup that walks the bitchat sources one
file at a time and audits each against `docs/SECURITY-CHECKLIST.md`.

## What is here

| Path | Role |
|---|---|
| `opencode.json` | Provider, model, and a read-only permission profile |
| `.opencode/agent/security-audit.md` | The auditor agent — read-only, one file per session |
| `.opencode/command/audit-file.md` | `/audit-file <path>`, the per-file entry point |
| `docs/SECURITY-CHECKLIST.md` | The checklist, with check IDs and a severity scale |
| `scripts/security-sweep.sh` | Driver: risk-ordered, resumable, one session per file |

## Setup

```sh
npm install -g opencode-ai
export OPENROUTER_API_KEY=sk-or-v1-...      # or: opencode providers login
```

`opencode.json` reads the key from the environment via `{env:OPENROUTER_API_KEY}`,
so no secret is stored in the repository. Confirm the config resolves:

```sh
opencode debug config | grep -E '"model"|openrouter'
opencode agent list | grep security-audit
```

### Model

The configured model is `openrouter/z-ai/glm-5.3`, set in two places in
`opencode.json` (`model` and `small_model`) plus the `provider.openrouter.models`
map. To move to a different GLM revision, change the slug in those three spots,
or override per-run without editing anything:

```sh
scripts/security-sweep.sh --model openrouter/z-ai/glm-4.6
```

Verify the slug against `https://openrouter.ai/models?q=glm` before a full
sweep — an unknown slug fails at the first request, after the sweep has
already started.

The provider is declared explicitly with `npm: "@openrouter/ai-sdk-provider"`
rather than relying on opencode's models.dev catalog lookup, so the config
still resolves on a machine that cannot reach `models.dev`.

### Permissions

`opencode.json` denies `edit` and `webfetch` outright and allows only
read-only bash (`git log`/`show`/`blame`, `rg`, `grep`). The agent has no
write, edit, or patch tool. A sweep cannot modify the working tree, and an
instruction smuggled into a source file cannot talk it into doing so.

## Running

```sh
# See the audit order without spending anything.
scripts/security-sweep.sh --dry-run

# Audit the crypto and transport core first (~40 files).
scripts/security-sweep.sh --filter 'bitchat/(Noise|Nostr|Identity|Protocols)'

# Everything: 290 files, one session each.
scripts/security-sweep.sh -j 4
```

Reports land in `.security-sweep/reports/<path>.md`, with `INDEX.md`
summarising verdicts and per-file stderr in `.security-sweep/logs/`. A file
that already has a non-empty report is skipped, so an interrupted sweep
resumes where it stopped; `--force` re-audits.

One file per session is deliberate — a fresh context per file keeps the
checklist in view and stops findings bleeding between files. The cost is that
shared helpers are re-read for every file that touches them. 290 sessions is a
real bill; start with `--filter` and widen.

For a single file interactively:

```sh
opencode
/audit-file bitchat/Noise/NoiseSession.swift
```

The sweep's output is a triage queue, not a verdict. Every finding needs a
human to confirm it before it becomes an issue, and anything genuinely
exploitable goes through private disclosure per `SECURITY.md` — not a public
issue.

## Running bitchat itself

The sweep is static review. Running the app is a separate problem, and it
needs macOS:

```sh
just check       # verify Xcode is installed and selected
just run         # build and launch the macOS app
just test        # SwiftPM test suite
just test-ios    # tests on the iPhone 17 simulator
```

There is no Linux or container path to a running bitchat, and this is a
property of the codebase rather than a missing tool:

- 49 files import SwiftUI, 23 UIKit, 15 AppKit, 14 CoreBluetooth, and 19
  CryptoKit. None of these exist in the Linux Swift toolchain.
- The Tor dependency is an Apple-only binary target —
  `localPackages/Arti/Frameworks/arti.xcframework` ships `ios-arm64`,
  `ios-arm64_x86_64-simulator`, and `macos-arm64_x86_64` slices, with no Linux
  slice to substitute.
- `BitFoundation` and `BitLogger` are not portable escape hatches either:
  `CourierEnvelope.swift` and `PeerIDRotation.swift` import CryptoKit, and
  `OSLog+Categories.swift` builds on `os.log`.

"Emulator" for this project means the iOS Simulator, which is part of Xcode
and does not run outside macOS. A Linux container can host the sweep, but not
the app.
