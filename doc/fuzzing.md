# Fuzzing

Sequoia crates ship [`cargo-fuzz`] targets that exercise parsers and other
untrusted-input paths, asserting they never panic or trip a sanitizer.  Each
crate keeps its own targets under `<crate>/fuzz/` (currently `openpgp/fuzz/`);
this document covers the **repo-wide** tooling that runs them.  For the targets
of a specific crate, see that crate's fuzz README (e.g. `openpgp/fuzz/README.md`).

[`cargo-fuzz`]: https://rust-fuzz.github.io/book/cargo-fuzz.html

## Prerequisites

`cargo-fuzz` requires a nightly toolchain:

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
```

Alternatively, use the prebuilt `fuzz` image (nightly + cargo-fuzz) from
[build-docker-image]; this is what CI uses.

[build-docker-image]: https://gitlab.com/sequoia-pgp/build-docker-image

## The runner: `./fuzz-all.sh`

`./fuzz-all.sh` (in the repository root) runs the fuzz targets across crates.
It **auto-discovers** every crate that has a `fuzz/` project, so new crates and
targets are picked up with no change to the script or CI.

It has two modes, selected with `FUZZ_MODE`:

```bash
# replay: (re)generate seeds, then run each corpus file once (libFuzzer
# -runs=0).  Deterministic and fast; a crash here is a reintroduced bug.
FUZZ_MODE=replay ./fuzz-all.sh

# timed: a short mutation run per target.  Nondeterministic; may find new bugs.
FUZZ_MODE=timed FUZZ_TIME_PER_TARGET=30 ./fuzz-all.sh
```

By default it runs every discovered crate.  Crate selection (first match wins):

1. positional arguments — `./fuzz-all.sh openpgp ipc`
2. `$FUZZ_CRATES` — `FUZZ_CRATES="openpgp ipc" ./fuzz-all.sh`
3. the crate of `$PWD`, if it contains `fuzz/Cargo.toml`
4. otherwise, auto-discover every `*/fuzz/Cargo.toml`

A bare numeric first argument sets the per-target time in timed mode
(`./fuzz-all.sh 60`).

### Tunables (environment)

| Variable | Default | Meaning |
|---|---|---|
| `FUZZ_MODE` | `timed` | `replay` or `timed` |
| `FUZZ_TIME_PER_TARGET` | `60` | seconds per target, timed mode |
| `FUZZ_RSS_LIMIT_MB` | `2048` | libFuzzer runtime memory ceiling |
| `CARGO_BUILD_JOBS` | `4` | compile parallelism; the peak-RAM lever for the AddressSanitizer build |
| `FUZZ_SKIP` | — | space-separated target names to skip (e.g. one with a known-open bug) |
| `FUZZ_ALLOW_EMPTY_CORPUS` | — | replay: warn instead of failing when a corpus is empty |
| `FUZZ_CORPUS_ROOT` | `${CARGO_TARGET_DIR:-target}/fuzz-corpus` | writable, out-of-tree corpus (generated seeds + libFuzzer's new finds) |
| `FUZZ_ARTIFACT_ROOT` | `${CARGO_TARGET_DIR:-target}/fuzz-artifacts` | out-of-tree crash/OOM/timeout artifacts |

## Corpus directories

There are two, deliberately kept separate:

- **Committed corpus — `<crate>/fuzz/corpus/<target>/` (tracked in git).** Holds
  the small, curated seeds and regression reproducers (see below).  During a run
  it is used **read-only**.
- **Working corpus — `$FUZZ_CORPUS_ROOT/<crate>/corpus/<target>/` (out of tree,
  git-ignored).** Where the seed hook writes generated seeds and where libFuzzer
  writes newly discovered inputs.  Defaults under the cargo target directory and
  is safe to delete at any time.
- **Artifacts — `$FUZZ_ARTIFACT_ROOT/<crate>/<target>/` (out of tree,
  git-ignored).** Where libFuzzer saves a crash/OOM/timeout reproducer.

`./fuzz-all.sh` runs each target against the working corpus (writable, first)
plus the committed corpus (read-only, second), and directs artifacts to
`$FUZZ_ARTIFACT_ROOT`, so **running the fuzzers never modifies the source
tree.**  The CI jobs upload the artifact directory on failure.

## Seed corpora

We **commit the seed generators, not bulk corpora.**  A large accumulated
corpus is churny and belongs in a CI cache or corpus store, not in git.  What
is worth committing to git:

- the seed *generators* (regenerated on demand, including in CI), and
- minimized **regression reproducers** — the input for a real fixed bug, kept
  so replay proves it stays fixed.  These can't be regenerated.

### The per-crate seed hook

Seeding is crate-specific, so it follows a convention: each fuzzing crate
provides an executable **`<crate>/fuzz/generate-seeds.sh`** that writes seed
files into a corpus.  This is a fixed, conventional path — like a per-crate
`build.rs` — so `./fuzz-all.sh` can find and run it before a replay without
knowing anything crate-specific.  The filename is shared by convention; the
contents are not.

The hook writes to `$FUZZ_CORPUS_OUT` if set, otherwise to the in-tree
`<crate>/fuzz/corpus/`.  `./fuzz-all.sh` sets `FUZZ_CORPUS_OUT` to the
out-of-tree working corpus; run standalone, the hook populates the in-tree
corpus.

`openpgp/fuzz/generate-seeds.sh`, for example, combines two complementary
sources:

```bash
# fresh, self-consistent OpenPGP objects built from a throwaway key:
cargo run -p sequoia-openpgp --example generate_key_seeds
# real-world fixtures copied from openpgp/tests/data:
bash openpgp/fuzz/scripts/populate-parser-corpora.sh
```

## Adding fuzzing to a crate

1. Add a `cargo-fuzz` project under `<crate>/fuzz/` with one or more targets.
2. Provide `<crate>/fuzz/generate-seeds.sh` that writes seeds into
   `${FUZZ_CORPUS_OUT:-fuzz/corpus}/<target>/` — honouring `FUZZ_CORPUS_OUT` so
   the runner can direct them out of tree (and commit any regression
   reproducers under `<crate>/fuzz/corpus/<target>/`).
3. That's it — `./fuzz-all.sh` and the CI jobs discover the crate automatically.

If a target has a known-open bug that would fail the gating replay, add it to
`FUZZ_SKIP` in the CI job until the fix lands.

## Continuous integration

Two jobs run the targets briefly on every pipeline (see `.gitlab-ci.yml`),
using the `fuzz` image:

- **`fuzz-replay`** — regenerates seeds, then replays each corpus file
  (`-runs=0`).  Deterministic, so a crash is a reintroduced bug and it **gates**
  the pipeline.
- **`fuzz-timed`** — a short mutation run.  Nondeterministic, so it is
  `allow_failure`: it surfaces new crashes as a warning rather than blocking an
  unrelated merge request.

Targets build with AddressSanitizer (ASan).  Notes:

- `ASAN_OPTIONS=detect_leaks=0` avoids LeakSanitizer's need for
  `CAP_SYS_PTRACE`; drop it (and grant the capability on the runner) to also
  hunt leaks.
- ASan builds are memory-hungry — tune `CARGO_BUILD_JOBS` to the runner's RAM.

## Reproducing a crash

A crash writes its input to `$FUZZ_ARTIFACT_ROOT/<crate>/<target>/` (CI uploads
these on failure).  To reproduce and minimize, from the crate directory, pass
the artifact path — for example:

```bash
cargo +nightly fuzz run  <target> "$FUZZ_ARTIFACT_ROOT/<crate>/<target>/crash-<hash>"
cargo +nightly fuzz tmin <target> "$FUZZ_ARTIFACT_ROOT/<crate>/<target>/crash-<hash>"
```
