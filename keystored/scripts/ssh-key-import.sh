#!/bin/bash

set -eu -o pipefail

shopt -s failglob

local_path=$(dirname $0)

: ${SYSREPOCFG:=sysrepocfg}
: ${CHMOD:=chmod}
: ${OPENSSL:=openssl}
: ${SSH_KEYGEN:=ssh-keygen}
: ${STOCK_KEY_CONFIG:=$local_path/../stock_key_config.xml}
: ${KEYSTORED_KEYS_DIR:=/etc/keystored/keys}

if [ -n "$($SYSREPOCFG -d startup -f xml --export ietf-keystore)" ]; then
    echo "- Some ietf-keystore configuration set, skipping stock key configuration import."
    exit 0
fi

if [ $KEYSTORED_CHECK_SSH_KEY -eq 0 ]; then
    echo "- Warning: Assuming that an external script will provide the SSH key in a PEM format at \"${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem\"."
    echo "- Importing ietf-keystore stock key configuration..."
    $SYSREPOCFG -d startup -i ${STOCK_KEY_CONFIG} ietf-keystore
else
    if [ -r ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem -a -r ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem.pub ]; then
        echo "- SSH hostkey found, no need to generate a new one."
    else
        echo "- SSH hostkey not found, generating a new one..."
        $SSH_KEYGEN -m pem -t rsa -q -N "" -f ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem
        # public key format cannot be specified, it is always in the openssh format
        # force convert it to PEM as well
        $CHMOD go-rw ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem.pub
        $SSH_KEYGEN -e -m pem -f ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem.pub > ${KEYSTORED_KEYS_DIR}/pub.pem
        mv -f ${KEYSTORED_KEYS_DIR}/pub.pem ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem.pub
    fi
    $CHMOD go-rw ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem
    $CHMOD go+r ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem.pub
    echo "- Importing ietf-keystore stock key configuration..."
    $SYSREPOCFG -d startup -i ${STOCK_KEY_CONFIG} ietf-keystore
fi
