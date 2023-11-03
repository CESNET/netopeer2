#!/usr/bin/env bash

set -e

# import functions
script_directory=$(dirname "$0")
source "${script_directory}/common.sh"

# get path to sysrepocfg and openssl executables, these will be stored in $SYSREPOCFG and $OPENSSL, respectively
SYSREPOCFG_GET_PATH
OPENSSL_GET_PATH

# check that there is no SSH key with this name yet, if so just exit
KEYSTORE_KEY=$($SYSREPOCFG -X -x "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='genkey']")
if [ -n "$KEYSTORE_KEY" ]; then
    exit 0
fi

# generate a new key
PRIVPEM=$($OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM 2>/dev/null)
# remove header/footer and newlines
PRIVKEY=$(echo "$PRIVPEM" | grep -v -- "-----" | tr -d "\n")

# generate edit config
CONFIG="<keystore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">
    <asymmetric-keys>
        <asymmetric-key>
            <name>genkey</name>
            <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>
            <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>
            <cleartext-private-key>${PRIVKEY}</cleartext-private-key>
        </asymmetric-key>
    </asymmetric-keys>
</keystore>"

# apply it to startup and running
echo "$CONFIG" | "$SYSREPOCFG" --edit -d startup -f xml -m ietf-keystore -v2
"$SYSREPOCFG" -C startup -m ietf-keystore -v2
