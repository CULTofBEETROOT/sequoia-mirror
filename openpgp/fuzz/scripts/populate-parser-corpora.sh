#!/usr/bin/env bash
# Populate parser fuzz corpora from existing OpenPGP test fixtures.
#
# Run from the repository root:
#
#   bash openpgp/fuzz/scripts/populate-parser-corpora.sh
#
# The script copies, rather than symlinks, so corpus directories
# remain portable when used by cargo-fuzz, CI jobs, or archived
# crash/corpus bundles.

set -euo pipefail

ROOT="${1:-.}"
DATA="$ROOT/openpgp/tests/data"
CORPUS="$ROOT/openpgp/fuzz/corpus"

if ! test -e "$DATA"
then
    echo "$DATA is missing.  Are you really running the script from the root of the repository?" >&2
    exit 1
fi

copy_seed() {
  local target="$1"
  local src_rel="$2"
  local dst_name="${3:-$(basename "$src_rel")}"

  local src="$DATA/$src_rel"
  local dst_dir="$CORPUS/$target"
  local dst="$dst_dir/$dst_name"

  if [[ ! -f "$src" ]]; then
    echo "missing: $src" >&2
    return 1
  fi

  mkdir -p "$dst_dir"
  cp "$src" "$dst"
  echo "$target <= $src_rel -> $dst_name"
}

# Low-level packet parser: broad packet coverage.
copy_seed packet_pile_from_bytes keys/public-key.pgp
copy_seed packet_pile_from_bytes keys/testy.pgp
copy_seed packet_pile_from_bytes keys/testy-private.pgp
copy_seed packet_pile_from_bytes messages/literal-mode-b.pgp
copy_seed packet_pile_from_bytes messages/literal-mode-t-partial-body.pgp
copy_seed packet_pile_from_bytes messages/compressed-data-algo-0.pgp
copy_seed packet_pile_from_bytes messages/signed.pgp
copy_seed packet_pile_from_bytes messages/signed-2-partial-body.pgp
copy_seed packet_pile_from_bytes messages/encrypted-to-testy.pgp
copy_seed packet_pile_from_bytes messages/signature-with-broken-mpis.sig

# Message parser: message-shaped packet piles.
copy_seed message_from_bytes messages/literal-mode-b.pgp
copy_seed message_from_bytes messages/literal-mode-t-partial-body.pgp
copy_seed message_from_bytes messages/compressed-data-algo-0.pgp
copy_seed message_from_bytes messages/compression-quine.pgp
copy_seed message_from_bytes messages/signed.pgp
copy_seed message_from_bytes messages/signed-1.pgp
copy_seed message_from_bytes messages/signed-2-partial-body.pgp
copy_seed message_from_bytes messages/signed-3-partial-body-multiple-sigs.pgp
copy_seed message_from_bytes messages/encrypted-to-testy.pgp
copy_seed message_from_bytes messages/encrypted-aes256-password-123.pgp

# CertParser: certs, private certs, v3 material, and broken cert fixtures.
copy_seed cert_parser_from_bytes keys/testy.pgp
copy_seed cert_parser_from_bytes keys/testy-new.pgp
copy_seed cert_parser_from_bytes keys/neal.pgp
copy_seed cert_parser_from_bytes keys/lutz.pgp
copy_seed cert_parser_from_bytes keys/dkg.pgp
copy_seed cert_parser_from_bytes keys/testy-private.pgp
copy_seed cert_parser_from_bytes keys/john-v3.pgp
copy_seed cert_parser_from_bytes keys/john-v3-secret.pgp
copy_seed cert_parser_from_bytes keys/testy-broken-no-pk.pgp
copy_seed cert_parser_from_bytes keys/testy-broken-no-uid.pgp

# RawCertParser vs CertParser: valid cert/keyring-shaped inputs only.
copy_seed rawcert_vs_certparser keys/testy.pgp
copy_seed rawcert_vs_certparser keys/testy-new.pgp
copy_seed rawcert_vs_certparser keys/neal.pgp
copy_seed rawcert_vs_certparser keys/lutz.pgp
copy_seed rawcert_vs_certparser keys/dkg.pgp
copy_seed rawcert_vs_certparser keys/testy-private.pgp

echo
echo "Corpus population complete:"
find "$CORPUS" -maxdepth 2 -type f | sort
