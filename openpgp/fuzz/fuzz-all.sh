#!/bin/sh
# Run cargo-fuzz targets across one or more workspace crates.
#
# Modes (FUZZ_MODE):
#   replay  Feed each committed/generated corpus file through the target once
#           (libFuzzer -runs=0).  Deterministic regression check; fast.  Before
#           replaying a crate, its optional fuzz/generate-seeds.sh hook is run so
#           the corpus is populated (see openpgp/fuzz/generate-seeds.sh).
#   timed   Mutate for FUZZ_TIME_PER_TARGET seconds per target (default).
#           Nondeterministic; may discover new crashes.
#
# Crate selection (first match wins):
#   1. positional args          e.g. fuzz-all.sh openpgp ipc
#   2. $FUZZ_CRATES             e.g. FUZZ_CRATES="openpgp ipc"
#   3. the crate of $PWD        (if $PWD contains fuzz/Cargo.toml)
#   4. auto-discover every */fuzz/Cargo.toml under the repository root
#
# Tunables (env):
#   FUZZ_MODE               replay | timed          (default: timed)
#   FUZZ_TIME_PER_TARGET    seconds, timed mode     (default: 60; or $1 if numeric)
#   FUZZ_RSS_LIMIT_MB       libFuzzer RSS ceiling   (default: 2048)
#   CARGO_BUILD_JOBS        compile parallelism / peak-RAM lever (default: 4)
#   FUZZ_SKIP               space-separated target names to skip (e.g. a target
#                           with a known-open bug that would fail the gate)
#   FUZZ_ALLOW_EMPTY_CORPUS replay: warn instead of failing on an empty corpus
#
# Exit status is non-zero if any target crashed (or, in replay mode, had an
# empty corpus without FUZZ_ALLOW_EMPTY_CORPUS).  All targets are attempted.
set -u

: "${FUZZ_MODE:=timed}"
: "${FUZZ_RSS_LIMIT_MB:=2048}"
: "${CARGO_BUILD_JOBS:=4}"
: "${FUZZ_SKIP:=}"
export CARGO_BUILD_JOBS

# In timed mode a bare numeric first argument is the per-target time (keeps the
# historical `fuzz-all.sh 60` invocation working); otherwise positional
# arguments are treated as a crate list.
crates=""
if [ "$#" -gt 0 ]; then
    case "$1" in
        ''|*[!0-9]*) crates="$*" ;;               # non-numeric -> crate list
        *) : "${FUZZ_TIME_PER_TARGET:=$1}" ;;     # numeric -> per-target time
    esac
fi
: "${FUZZ_TIME_PER_TARGET:=60}"

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

# Resolve the list of crate directories to fuzz.
[ -z "$crates" ] && crates="${FUZZ_CRATES:-}"
if [ -z "$crates" ] && [ -f "fuzz/Cargo.toml" ]; then
    crates="$PWD"                                 # invoked from inside a crate
fi
if [ -z "$crates" ]; then
    crates=$(cd "$repo_root" \
        && find . -maxdepth 3 -path '*/fuzz/Cargo.toml' \
             | sed -e 's:/fuzz/Cargo.toml$::' -e 's:^\./::' \
             | sort -u)
fi

is_skipped() {
    for s in $FUZZ_SKIP; do
        [ "$s" = "$1" ] && return 0
    done
    return 1
}

status=0
for crate in $crates; do
    case "$crate" in
        /*) dir="$crate" ;;
        *)  dir="$repo_root/$crate" ;;
    esac
    if [ ! -f "$dir/fuzz/Cargo.toml" ]; then
        echo "SKIP: $crate has no fuzz/Cargo.toml" >&2
        continue
    fi
    cd "$dir" || { status=1; continue; }

    # Populate seeds for replay, if the crate provides a hook.
    if [ "$FUZZ_MODE" = replay ] && [ -x fuzz/generate-seeds.sh ]; then
        echo "----- generating seeds for $crate -----"
        (cd "$repo_root" && "$dir/fuzz/generate-seeds.sh") || status=1
    fi

    for target in $(cargo +nightly fuzz list); do
        if is_skipped "$target"; then
            echo "----- skipping $crate/$target (FUZZ_SKIP) -----"
            continue
        fi
        case "$FUZZ_MODE" in
          replay)
            corpus="fuzz/corpus/$target"
            n=$(find "$corpus" -type f 2>/dev/null | wc -l | tr -d ' ')
            if [ "${n:-0}" -eq 0 ]; then
                if [ -n "${FUZZ_ALLOW_EMPTY_CORPUS:-}" ]; then
                    echo "----- $crate/$target: replay skipped (empty corpus) -----"
                    continue
                fi
                echo "ERROR: $crate/$target has an empty corpus; add a seed/reproducer or set FUZZ_ALLOW_EMPTY_CORPUS=1" >&2
                status=1
                continue
            fi
            echo "----- replaying $crate/$target over $n corpus file(s) -----"
            RUST_BACKTRACE=1 cargo +nightly fuzz run "$target" "$corpus" -- \
                -runs=0 -rss_limit_mb="$FUZZ_RSS_LIMIT_MB" || status=1
            ;;
          timed)
            echo "----- fuzzing $crate/$target for ${FUZZ_TIME_PER_TARGET}s -----"
            RUST_BACKTRACE=1 cargo +nightly fuzz run "$target" -- \
                -max_total_time="$FUZZ_TIME_PER_TARGET" \
                -rss_limit_mb="$FUZZ_RSS_LIMIT_MB" || status=1
            ;;
          *)
            echo "ERROR: unknown FUZZ_MODE='$FUZZ_MODE' (use replay|timed)" >&2
            exit 2
            ;;
        esac
    done
done
exit $status
