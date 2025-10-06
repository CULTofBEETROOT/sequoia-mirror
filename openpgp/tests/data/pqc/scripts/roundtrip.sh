#!/usr/bin/bash

### roundtrip test: Generates artifacts (key, certificate
### encrypted message and detached signature) with `sqop` and
### tests if `rsop` and `gosop` can use them.
###
###   USAGE: bash roundtrip.sh [WORKING_DIRECTORY]
###
### Make sure that `sqop`,`rsop` and `gosop` are
### either in your $PATH or are accessible via
### the environment variables $SQOP, $RSOP and $GOSOP
### respectively.

# If there are updates, the list of profiles to test might
# have to be adjusted.

# Any files add to this will be deleted on exit.
CLEANUP=
# Automatically run at exit.
cleanup_at_exit() {
    for d in $CLEANUP
    do
        rm -rf "$d"
    done
}
trap cleanup_at_exit EXIT

cleanup() {
    CLEANUP="$CLEANUP $@"
}

WORKDIR=$1
if test -z $WORKDIR
then
    fmt<<EOF
Warning: Working directory not specified.  Specify a working directory to
preserve the artifacts.

EOF
    WORKDIR=$(mktemp -d)
    CLEANUP="$CLEANUP $WORKDIR"
fi

usage() { # message_string
  echo "Error: $1"
  echo
  sed -n 's/^### \?//p' $0 | fmt
  exit 1
}

if ! [ -d $WORKDIR ] ; then
  mkdir -p $WORKDIR
fi

if [ -z $SQOP ] ; then
  SQOP=$(which sqop)
fi

if [ -z $RSOP ] ; then
  RSOP=$(which rsop)
fi

if [ -z $GOSOP ] ; then
  GOSOP=$(which gosop)
fi

if [ -z $SQOP ] ; then
  usage "Cannot find sqop binary, set SQOP"
fi

if [ -z $RSOP ] ; then
  usage "Cannot find rsop binary, set RSOP"
fi

if [ -z $GOSOP ] ; then
  usage "Cannot find gosop binary, set GOSOP"
fi


USER_ALICE="Alice <alice@example.com>"
USER_BOB="Bob <bob@example.com>"
MESSAGE="Hello World"

produce_consume() {
  for PROFILE in ${PROFILES[@]} ; do
    echo -n $(basename $PRODUCER) ": Profile $PROFILE..."

    echo -n " alice"
    $PRODUCER generate-key --profile $PROFILE "$USER_ALICE" > $WORKDIR/${PROFILE}_alice_sk.pgp
    cat $WORKDIR/${PROFILE}_alice_sk.pgp | $SQOP extract-cert > $WORKDIR/${PROFILE}_alice_pk.pgp

    echo -n " bob"
    $PRODUCER generate-key --profile $PROFILE "$USER_BOB" > $WORKDIR/${PROFILE}_bob_sk.pgp
    cat $WORKDIR/${PROFILE}_bob_sk.pgp | $SQOP extract-cert > $WORKDIR/${PROFILE}_bob_pk.pgp

    echo -n " encrypt"
    echo $MESSAGE | $PRODUCER encrypt --sign-with $WORKDIR/${PROFILE}_alice_sk.pgp $WORKDIR/${PROFILE}_bob_pk.pgp > $WORKDIR/${PROFILE}_message.pgp

    echo -n " sign-detached"
    echo $MESSAGE | $PRODUCER sign $WORKDIR/${PROFILE}_alice_sk.pgp > $WORKDIR/${PROFILE}_detached_sig.pgp
    echo " done."

    # test other binaries

    for CONSUMER in ${CONSUMERS[@]} ; do
      echo -n "  " $(basename $CONSUMER) ":"

      echo -n " decrypt"
      DECRYPTED=$(cat $WORKDIR/${PROFILE}_message.pgp | $CONSUMER decrypt $WORKDIR/${PROFILE}_bob_sk.pgp)
      if [ "$MESSAGE" != "$DECRYPTED" ] ; then
        echo -n " failed"
      else
        echo -n " OK"
      fi

      echo -n " verify"
      if echo "$MESSAGE" | $CONSUMER verify $WORKDIR/${PROFILE}_detached_sig.pgp $WORKDIR/${PROFILE}_alice_pk.pgp > /dev/null 2>&1 ; then
        echo -n " OK"
      else
        echo -n " failed"
      fi

      echo " done."
    done
  done
}

#
# SQOP
#

# sqop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-12
draft-ietf-openpgp-pqc-12-v4-ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-12-v6-ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-12-v6-mldsa65ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-12-v6-mldsa87ed448-mlkem1024x448
draft-ietf-openpgp-pqc-12-v6-slhdsashake128s-mlkem768x25519
draft-ietf-openpgp-pqc-12-v6-slhdsashake128f-mlkem768x25519
draft-ietf-openpgp-pqc-12-v6-slhdsashake256s-mlkem1024x448"
PRODUCER=$SQOP
CONSUMERS=($RSOP $GOSOP)
produce_consume

#
# RSOP
#

# rsop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-08-v4-ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-mldsa65ed25519-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-mldsa87ed448-mlkem1024x448
draft-ietf-openpgp-pqc-08-v6-slhdsashake128s-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-slhdsashake128f-mlkem768x25519
draft-ietf-openpgp-pqc-08-v6-slhdsashake256s-mlkem1024x448"
PRODUCER=$RSOP
CONSUMERS=($SQOP)
produce_consume

#
# GOSOP
#

# gosop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-09
draft-ietf-openpgp-pqc-09-high-security"
PRODUCER=$GOSOP
CONSUMERS=($SQOP)
produce_consume
