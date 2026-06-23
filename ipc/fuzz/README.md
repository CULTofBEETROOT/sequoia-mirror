# Fuzzing `sequoia-ipc`

This directory contains targets to be used with `cargo fuzz`.

## Prerequisites

Install `cargo-fuzz` if needed:

```bash
cargo install cargo-fuzz
```

`cargo-fuzz` needs the `nightly` toolchain.

## Running fuzz targets

### keybox fuzzer

Make sure to run the test from within the `ipc` subdirectory.

```
cargo fuzz run keybox_from_bytes fuzz/corpus/keybox_from_bytes
```

This fuzzer uses structured corpora from `fuzz/corpus/keybox_from_bytes`.

`.../scripts/generate_keybox.sh` can be used to create new data for the
fuzzing test.
