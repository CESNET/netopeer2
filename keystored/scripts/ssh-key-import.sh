#!/bin/bash

set -eu -o pipefail

shopt -s failglob

local_path=$(dirname $0)

: ${SYSREPOCFG:=sysrepocfg}
: ${CHMOD:=chmod}
: ${OPENSSL:=openssl}
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
elif [ -r /etc/ssh/ssh_host_rsa_key ]; then
    cp /etc/ssh/ssh_host_rsa_key ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem
    $CHMOD go-rw ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem
    $OPENSSL rsa -pubout -in ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem \
        -out ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pub.pem
    echo "- Importing ietf-keystore stock key configuration..."
    $SYSREPOCFG -d startup -i ${STOCK_KEY_CONFIG} ietf-keystore
else
    echo "- Warning: Cannot read the SSH hostkey at /etc/ssh/ssh_host_rsa_key, skipping."
fi
