#!/usr/bin/bash

#
# generate artifacts
# USAGE: bash generate.sh $TARGET_DIRECTORY
#

WORKDIR=$1

if [ "$WORKDIR" == "" ] ; then
  echo "Usage: $0 [target-directory]"
  exit 0
fi

if ! [ -d $WORKDIR ] ; then
  mkdir -p $WORKDIR
fi

RSOP=/home/malte/src/rsop/target/release/rsop
GOSOP=/home/malte/src/gosop/gosop
SQOP=/home/malte/src/sequoia-sop/target/release/sqop

USER_ALICE="Alice <alice@example.com>"
USER_BOB="Bob <bob@example.com>"
MESSAGE="Hello World"

#
# SQOP
# 

# sqop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-12"

for PROFILE in $PROFILES ; do
  echo -n "sqop: Profile $PROFILE..."

  echo -n " alice"
  $SQOP generate-key --profile $PROFILE "$USER_ALICE" > $WORKDIR/${PROFILE}_alice_sk.pgp
  cat $WORKDIR/${PROFILE}_alice_sk.pgp | $SQOP extract-cert > $WORKDIR/${PROFILE}_alice_pk.pgp

  echo -n " bob"
  $SQOP generate-key --profile $PROFILE "$USER_BOB" > $WORKDIR/${PROFILE}_bob_sk.pgp
  cat $WORKDIR/${PROFILE}_bob_sk.pgp | $SQOP extract-cert > $WORKDIR/${PROFILE}_bob_pk.pgp

  echo -n " encrypt"
  echo $MESSAGE | $SQOP encrypt --sign-with $WORKDIR/${PROFILE}_alice_sk.pgp $WORKDIR/${PROFILE}_bob_pk.pgp > $WORKDIR/${PROFILE}_message.pgp

  echo -n " sign-detached"
  echo $MESSAGE | $SQOP sign $WORKDIR/${PROFILE}_alice_sk.pgp > $WORKDIR/${PROFILE}_detached_sig.pgp
  echo " done."

  # test other binaries

  for SOP in $RSOP $GOSOP ; do
    echo -n $(basename $SOP) ":"

    echo -n " descript"
    DECRYPTED=$(cat $WORKDIR/${PROFILE}_message.pgp | $SOP decrypt $WORKDIR/${PROFILE}_bob_sk.pgp)
    if [ "$MESSAGE" != "$DECRYPTED" ] ; then
      echo -n " failed"
    else 
      echo -n " OK"
    fi

    echo -n " verify"
    if echo "$MESSAGE" | $SOP verify $WORKDIR/${PROFILE}_detached_sig.pgp $WORKDIR/${PROFILE}_alice_pk.pgp > /dev/null 2>&1 ; then
      echo -n " OK"
    else
      echo -n " failed"
    fi

    echo " done."
  done
done
