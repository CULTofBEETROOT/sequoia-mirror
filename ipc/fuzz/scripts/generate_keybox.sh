#!/usr/bin/bash

#
# Generate a (valid) keybox file as a starting seed for the fuzzer.
#

export GNUPGHOME=$(mktemp -d)
export FUZZER_CORPUS_DIR=$(dirname $0)/../corpus/keybox_from_bytes

mkdir -p $FUZZER_CORPUS_DIR

generate_key() { # localpart
  sq key generate --home none \
    --without-password \
    --shared-key \
    --email $1@example.com \
    --output $GNUPGHOME/$1.pgp \
    --rev-cert /dev/null \
    --overwrite
}

generate_key alice
generate_key bob
generate_key carol

gpg --import $GNUPGHOME/alice.pgp
gpg --import $GNUPGHOME/bob.pgp
gpg --import $GNUPGHOME/carol.pgp

cp $GNUPGHOME/pubring.kbx $FUZZER_CORPUS_DIR
