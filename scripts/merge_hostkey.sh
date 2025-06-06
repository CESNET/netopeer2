#!/usr/bin/env bash

set -e

# import functions
script_directory=$(dirname "$0")
source "${script_directory}/common.sh"


# temporarily disable "set -e", the script will still exit if any of the executables is not found
set +e

# get path to sysrepocfg executable - stored in $SYSREPOCFG
SYSREPOCFG_GET_PATH

# get paths to crypto key generation executables - stored in $MBEDTLS and $OPENSSL
CRYPTO_KEYGEN_GET_PATHS

# re-enable "set -e"
set -e


# check that there is no SSH key with this name yet, if so just exit
KEYSTORE_KEY=$($SYSREPOCFG -X -x "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='genkey']")
if [ -n "$KEYSTORE_KEY" ]; then
    exit 0
fi

# save the current umask and set it to 077, so that the private key is not readable by others
OLD_UMASK=$(umask)
umask 077

# attempt to generate a private key using mbedtls first
if [ -n "$MBEDTLS" ]; then
    PRIVATE_KEY_FILE="netopeer2_key.pem"
    if "$MBEDTLS" type=rsa rsa_keysize=2048 filename="$PRIVATE_KEY_FILE" format=pem 2>/dev/null; then
        if [ -s "$PRIVATE_KEY_FILE" ]; then
            # key generated successfully, read it
            PRIVPEM=$(cat "$PRIVATE_KEY_FILE")
            # clean up the file
            rm -f "$PRIVATE_KEY_FILE"
        fi
    else
        # cleanup the file on failure
        echo "Failed to generate RSA key with mbedtls." >&2
        rm -f "$PRIVATE_KEY_FILE"
    fi
fi

# restore the original umask
umask "$OLD_UMASK"

# if mbedtls failed or is not available, use openssl
if [ -z "$PRIVPEM" ] && [ -n "$OPENSSL" ]; then
    PRIVPEM=$($OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM 2>/dev/null)
    if [ -z "$PRIVPEM" ]; then
        echo "Failed to generate RSA key with openssl." >&2
        exit 1
    fi
fi

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
