#!/usr/bin/env bash

set -e

# optional env variable override
if [ -n "$SYSREPOCFG_EXECUTABLE" ]; then
    SYSREPOCFG="$SYSREPOCFG_EXECUTABLE"
# avoid problems with sudo PATH
elif [ `id -u` -eq 0 ] && [ -n "$USER" ] && [ `command -v su` ]; then
    SYSREPOCFG=`su -c 'command -v sysrepocfg' -l $USER`
else
    SYSREPOCFG=`command -v sysrepocfg`
fi

if [ -n "$OPENSSL_EXECUTABLE" ]; then
    OPENSSL="$OPENSSL_EXECUTABLE"
elif [ `id -u` -eq 0 ] && [ -n "$USER" ] && [ `command -v su` ]; then
    OPENSSL=`su -c 'command -v openssl' -l $USER`
else
    OPENSSL=`command -v openssl`
fi

# check that there is no SSH key with this name yet
KEYSTORE_KEY=`$SYSREPOCFG -X -x "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='genkey']/name"`
if [ -z "$KEYSTORE_KEY" ]; then

# generate a new key
PRIVPEM=`$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM 2>/dev/null`
# remove header/footer and newlines
PRIVKEY=`echo "$PRIVPEM" | grep -v -- "-----" | tr -d "\n"`

# generate edit config
CONFIG="<keystore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">
    <asymmetric-keys>
        <asymmetric-key>
            <name>genkey</name>
            <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>
            <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>
            <cleartext-private-key>$PRIVKEY</cleartext-private-key>
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

fi
