#!/usr/bin/env bash
#
# Drive opencode over the bitchat sources one file at a time, auditing each
# against docs/SECURITY-CHECKLIST.md.
#
# One file per opencode session is deliberate: a fresh context per file keeps
# the checklist in view and stops findings from one file bleeding into the
# report for the next. The tradeoff is cost — the sweep re-reads shared
# helpers for every file that touches them.
#
# Usage:
#   scripts/security-sweep.sh [options]
#
#   -o, --out DIR       report directory (default: .security-sweep)
#   -m, --model ID      override the model (default: opencode.json's)
#   -f, --filter REGEX  audit only paths matching this extended regex
#   -n, --limit N       stop after N files
#   -j, --jobs N        concurrent opencode sessions (default: 1)
#       --force         re-audit files that already have a report
#       --dry-run       print the audit order and exit without calling a model
#   -h, --help          this message
#
# Resumable: a file with a non-empty report in the output directory is skipped
# unless --force is passed, so an interrupted sweep continues where it stopped.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir=".security-sweep"
model=""
filter=""
limit=0
jobs=1
force=0
dry_run=0

die() { printf '%s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^#\{1,2\} \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--out)    out_dir="${2:?--out needs a directory}"; shift 2 ;;
        -m|--model)  model="${2:?--model needs a model id}"; shift 2 ;;
        -f|--filter) filter="${2:?--filter needs a regex}"; shift 2 ;;
        -n|--limit)  limit="${2:?--limit needs a number}"; shift 2 ;;
        -j|--jobs)   jobs="${2:?--jobs needs a number}"; shift 2 ;;
        --force)     force=1; shift ;;
        --dry-run)   dry_run=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *)           die "unknown option: $1 (try --help)" ;;
    esac
done

[[ "$limit" =~ ^[0-9]+$ ]] || die "--limit must be a non-negative integer"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer"

if (( ! dry_run )); then
    command -v opencode >/dev/null 2>&1 \
        || die "opencode not found. Install it: npm install -g opencode-ai"
    [[ -n "${OPENROUTER_API_KEY:-}" ]] \
        || die "OPENROUTER_API_KEY is not set. Export it, or run: opencode providers login"
fi

# Risk-ordered directory sweep. Crypto, transport, and identity code is audited
# before presentation code, so an interrupted or budget-capped run still covers
# the parts of the tree where a finding would be critical.
readonly ORDER=(
    bitchat/Noise
    bitchat/Nostr
    bitchat/Identity
    bitchat/Protocols
    bitchat/Sync
    localPackages/BitFoundation/Sources
    bitchat/Services
    bitchat/Models
    bitchat/Utils
    bitchat/Features
    bitchat/ViewModels
    bitchat/App
    bitchat/Views
    localPackages/BitLogger/Sources
    localPackages/Arti/Sources
)

collect_files() {
    local dir
    for dir in "${ORDER[@]}"; do
        [[ -d "$dir" ]] || continue
        find "$dir" -name '*.swift' -type f | LC_ALL=C sort
    done
}

mapfile -t all_files < <(collect_files)
(( ${#all_files[@]} )) || die "no Swift sources found under ${ORDER[*]}"

# Anything under ORDER that find(1) reached twice would be audited twice; the
# directory list is disjoint by construction, but guard it so a future edit to
# ORDER cannot silently double the bill.
mapfile -t all_files < <(printf '%s\n' "${all_files[@]}" | awk '!seen[$0]++')

report_path() { printf '%s/reports/%s.md' "$out_dir" "${1%.swift}"; }

queue=()
skipped=0
for file in "${all_files[@]}"; do
    if [[ -n "$filter" ]] && ! [[ "$file" =~ $filter ]]; then
        continue
    fi
    report="$(report_path "$file")"
    if (( ! force )) && [[ -s "$report" ]]; then
        skipped=$(( skipped + 1 ))
        continue
    fi
    queue+=("$file")
    if (( limit > 0 && ${#queue[@]} >= limit )); then
        break
    fi
done

if (( dry_run )); then
    printf 'audit order (%d file(s), %d already reported):\n' "${#queue[@]}" "$skipped"
    printf '  %s\n' "${queue[@]}"
    exit 0
fi

if (( ${#queue[@]} == 0 )); then
    printf 'nothing to audit (%d file(s) already reported; --force to redo)\n' "$skipped"
    exit 0
fi

mkdir -p "$out_dir/reports" "$out_dir/logs"

audit_one() {
    local file="$1"
    local report log
    report="$(report_path "$file")"
    log="$out_dir/logs/${file//\//_}.log"
    mkdir -p "$(dirname "$report")"

    local -a cmd=(opencode run --agent security-audit --command audit-file)
    [[ -n "$model" ]] && cmd+=(--model "$model")
    cmd+=("$file")

    if "${cmd[@]}" >"$report.tmp" 2>"$log"; then
        if [[ -s "$report.tmp" ]]; then
            mv "$report.tmp" "$report"
            printf 'ok    %s\n' "$file"
        else
            rm -f "$report.tmp"
            printf 'EMPTY %s (see %s)\n' "$file" "$log" >&2
            return 1
        fi
    else
        rm -f "$report.tmp"
        printf 'FAIL  %s (see %s)\n' "$file" "$log" >&2
        return 1
    fi
}

# audit_one runs in subshells under -j, so it and the variables it closes over
# have to be exported for bash -c to see them.
export out_dir model
export -f audit_one report_path

printf 'auditing %d file(s) with %d job(s); %d already reported\n' \
    "${#queue[@]}" "$jobs" "$skipped"

failures=0
if (( jobs > 1 )); then
    printf '%s\0' "${queue[@]}" \
        | xargs -0 -P "$jobs" -I{} bash -c 'audit_one "$@"' _ {} \
        || failures=1
else
    for file in "${queue[@]}"; do
        audit_one "$file" || failures=1
    done
fi

# Index of everything reported so far, not just this run's slice.
index="$out_dir/INDEX.md"
{
    printf '# bitchat security sweep\n\n'
    printf 'Checklist: `docs/SECURITY-CHECKLIST.md`\n'
    printf 'Commit: `%s`\n\n' "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    printf '| file | verdict | checks |\n|---|---|---|\n'
    if [[ -d "$out_dir/reports" ]]; then
        while IFS= read -r r; do
            src="${r#"$out_dir"/reports/}"; src="${src%.md}.swift"
            verdict="$(sed -n 's/^\*\*Verdict:\*\* *//p' "$r" | head -1)"
            checks="$(sed -n 's/^\*\*Checks implicated:\*\* *//p' "$r" | head -1)"
            printf '| `%s` | %s | %s |\n' "$src" "${verdict:-?}" "${checks:-—}"
        done < <(find "$out_dir/reports" -name '*.md' -type f | LC_ALL=C sort)
    fi
} > "$index"

printf 'index written to %s\n' "$index"
exit "$failures"
