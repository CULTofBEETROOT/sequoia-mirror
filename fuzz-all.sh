#!/bin/sh
# Run cargo-fuzz targets across one or more workspace crates.
#
# Modes (FUZZ_MODE):
#   replay  Feed each committed/generated corpus file through the target once
#           (libFuzzer -runs=0).  Deterministic regression check; fast.  Before
#           replaying a crate, this runner looks for a per-crate seed hook at
#           <crate>/fuzz/generate-seeds.sh (a fixed, conventional path, like a
#           Makefile target) and runs it if present.  The hook's *contents* are
#           crate-specific — e.g. openpgp/fuzz/generate-seeds.sh builds OpenPGP
#           seeds — even though the filename is the same across crates.
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
#   FUZZ_CORPUS_ROOT        writable, out-of-tree corpus root
#                           (default: ${CARGO_TARGET_DIR:-<repo>/target}/fuzz-corpus)
#   FUZZ_ARTIFACT_ROOT      out-of-tree crash/OOM/timeout artifact root
#                           (default: ${CARGO_TARGET_DIR:-<repo>/target}/fuzz-artifacts)
#
# Out-of-tree layout: generated seeds and libFuzzer's new finds go under
# FUZZ_CORPUS_ROOT, and crash artifacts under FUZZ_ARTIFACT_ROOT, while each
# crate's committed fuzz/corpus/<target> is used read-only.  Running the fuzzers
# therefore never modifies the source tree.
#
# Exit status is non-zero if any target crashed (or, in replay mode, had an
# empty corpus without FUZZ_ALLOW_EMPTY_CORPUS).  All targets are attempted.
set -u

# Defaults for tunables that may be overridden from the environment.  The
# ${VAR:-} guards let us read a possibly-unset variable without tripping the
# `set -u` above; each is only assigned when unset or empty.
if test -z "${FUZZ_MODE:-}"
then
    FUZZ_MODE=timed
fi
if test -z "${FUZZ_RSS_LIMIT_MB:-}"
then
    FUZZ_RSS_LIMIT_MB=2048
fi
if test -z "${CARGO_BUILD_JOBS:-}"
then
    CARGO_BUILD_JOBS=4
fi
if test -z "${FUZZ_SKIP:-}"
then
    FUZZ_SKIP=
fi
export CARGO_BUILD_JOBS

# In timed mode a bare numeric first argument sets the per-target time;
# otherwise positional arguments are treated as a crate list.
crates=""
if [ "$#" -gt 0 ]; then
    case "$1" in
        ''|*[!0-9]*) crates="$*" ;;               # non-numeric -> crate list
        *)                                        # numeric -> per-target time
            if test -z "${FUZZ_TIME_PER_TARGET:-}"
            then
                FUZZ_TIME_PER_TARGET="$1"
            fi
            ;;
    esac
fi
if test -z "${FUZZ_TIME_PER_TARGET:-}"
then
    FUZZ_TIME_PER_TARGET=60
fi

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

# Generated seeds and libFuzzer's own new inputs are written to an out-of-tree
# corpus so the source tree is never modified; the committed corpus
# (fuzz/corpus/<target>) is only ever read.  Defaults under the cargo target
# directory (or ./target), both git-ignored.
if test -z "${FUZZ_CORPUS_ROOT:-}"
then
    FUZZ_CORPUS_ROOT="${CARGO_TARGET_DIR:-$repo_root/target}/fuzz-corpus"
fi
if test -z "${FUZZ_ARTIFACT_ROOT:-}"
then
    FUZZ_ARTIFACT_ROOT="${CARGO_TARGET_DIR:-$repo_root/target}/fuzz-artifacts"
fi

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

    # Writable, out-of-tree corpus for this crate (generated seeds land here, and
    # libFuzzer writes new finds here).  The committed fuzz/corpus/<target> is
    # added read-only below, so the source tree is never modified.
    crate_name=$(basename "$dir")
    gen_base="$FUZZ_CORPUS_ROOT/$crate_name/corpus"

    # Populate seeds for replay, if the crate provides a hook.  Run via sh so a
    # lost executable bit doesn't silently skip seeding; FUZZ_CORPUS_OUT tells
    # the hook to write into the out-of-tree corpus.
    if [ "$FUZZ_MODE" = replay ] && [ -f fuzz/generate-seeds.sh ]; then
        echo "----- generating seeds for $crate into $gen_base -----"
        (cd "$repo_root" && FUZZ_CORPUS_OUT="$gen_base" sh "$dir/fuzz/generate-seeds.sh") || status=1
    fi

    for target in $(cargo +nightly fuzz list); do
        if is_skipped "$target"; then
            echo "----- skipping $crate/$target (FUZZ_SKIP) -----"
            continue
        fi

        # Primary corpus (writable, out-of-tree) first, committed reproducers
        # (read-only) second.  Left unquoted on the cargo line so each dir is a
        # separate argument.
        gen_corpus="$gen_base/$target"
        mkdir -p "$gen_corpus"
        corpora="$gen_corpus"
        if [ -d "fuzz/corpus/$target" ]; then
            corpora="$corpora fuzz/corpus/$target"
        fi

        # Crash/OOM/timeout artifacts also go out of tree.  cargo-fuzz injects an
        # in-tree -artifact_prefix; libFuzzer honours the last one, so ours wins.
        art_dir="$FUZZ_ARTIFACT_ROOT/$crate_name/$target"
        mkdir -p "$art_dir"

        case "$FUZZ_MODE" in
          replay)
            n=$(find $corpora -type f 2>/dev/null | wc -l | tr -d ' ')
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
            RUST_BACKTRACE=1 cargo +nightly fuzz run "$target" $corpora -- \
                -artifact_prefix="$art_dir/" \
                -runs=0 -rss_limit_mb="$FUZZ_RSS_LIMIT_MB" || status=1
            ;;
          timed)
            echo "----- fuzzing $crate/$target for ${FUZZ_TIME_PER_TARGET}s -----"
            RUST_BACKTRACE=1 cargo +nightly fuzz run "$target" $corpora -- \
                -artifact_prefix="$art_dir/" \
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
