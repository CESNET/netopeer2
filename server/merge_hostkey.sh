#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <sysrepocfg-path> <openssl-path>"
    exit
fi

set -e

SYSREPOCFG=$1
OPENSSL=$2

# generate a new key
PRIVPEM=`$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM 2>/dev/null`
# remove header/footer
PRIVKEY=`grep -v -- "-----" - <<STDIN
$PRIVPEM
STDIN`
# get public key
PUBPEM=`openssl rsa -pubout 2>/dev/null <<STDIN
$PRIVPEM
STDIN`
# remove header/footer
PUBKEY=`grep -v -- "-----" - <<STDIN
$PUBPEM
STDIN`

# generate edit config
CONFIG="<keystore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">
    <asymmetric-keys>
        <asymmetric-key>
            <name>genkey</name>
            <algorithm>rsa2048</algorithm>
            <public-key>$PUBKEY</public-key>
            <private-key>$PRIVKEY</private-key>
        </asymmetric-key>
    </asymmetric-keys>
</keystore>"
TMPFILE=`mktemp -u`
printf -- "$CONFIG" > $TMPFILE
# apply it to startup and running
$SYSREPOCFG --edit=$TMPFILE -d startup -f xml -m ietf-keystore -v2
$SYSREPOCFG -C startup -m ietf-keystore -v2
# remove the tmp file
rm $TMPFILE
