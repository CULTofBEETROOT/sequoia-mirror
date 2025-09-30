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

USER_ALICE="Alice <alice@example.com>"
USER_BOB="Bob <bob@example.com>"
MESSAGE="Hello World"

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

SUBDIRECTORY="rpgp"

for PROFILE in $PROFILES ; do
  echo -n "rsop: Profile $PROFILE..."
  mkdir -p $WORKDIR/$SUBDIRECTORY

  echo -n " alice"
  $RSOP generate-key --profile $PROFILE "$USER_ALICE" > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp | $RSOP extract-cert > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_pk.pgp

  echo -n " bob"
  $RSOP generate-key --profile $PROFILE "$USER_BOB" > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_sk.pgp | $RSOP extract-cert > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_pk.pgp

  echo -n " encrypt"
  echo $MESSAGE | $RSOP encrypt --sign-with $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_alice_sk.pgp $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_bob_pk.pgp > $WORKDIR/$SUBDIRECTORY/rsop_${PROFILE}_message.pgp
  echo " done."
done

#
# GOSOP
#

# gosop list-profiles generate-key (only PQC profiles)
PROFILES="draft-ietf-openpgp-pqc-09
draft-ietf-openpgp-pqc-09-high-security"

SUBDIRECTORY="gopenpgp"

for PROFILE in $PROFILES ; do
  echo -n "gosop: Profile $PROFILE..."
  mkdir -p $WORKDIR/$SUBDIRECTORY

  echo -n " alice"
  $GOSOP generate-key --profile $PROFILE "$USER_ALICE" > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp | $GOSOP extract-cert > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_pk.pgp

  echo -n " bob"
  $GOSOP generate-key --profile $PROFILE "$USER_BOB" > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_sk.pgp
  cat $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_sk.pgp | $GOSOP extract-cert > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_pk.pgp
  
  echo -n " encrypt"
  echo $MESSAGE | $GOSOP encrypt --sign-with $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_alice_sk.pgp $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_bob_pk.pgp > $WORKDIR/$SUBDIRECTORY/gosop_${PROFILE}_message.pgp
  echo " done."
done

echo "Results stored in $WORKDIR"
