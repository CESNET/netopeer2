#!/bin/bash

set -eux -o pipefail

shopt -s failglob

local_path=$(dirname $0)

: ${SYSREPOCFG:=sysrepocfg}
: ${CHMOD:=chmod}
: ${OPENSSL:=openssl}
: ${STOCK_KEY_CONFIG:=$local_path/../stock_key_config.xml}
: ${KEYSTORED_KEYS_DIR:=/etc/keystored/keys}

if [ -n "$($SYSREPOCFG -d startup --export ietf-keystore)" ]; then
    exit 0
fi

if [ -f /etc/ssh/ssh_host_rsa_key ]; then
    cp /etc/ssh/ssh_host_rsa_key ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem
    $CHMOD go-rw ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem
    $OPENSSL rsa -pubout -in ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pem \
        -out ${KEYSTORED_KEYS_DIR}/ssh_host_rsa_key.pub.pem
    $SYSREPOCFG -d startup -i ${STOCK_KEY_CONFIG} ietf-keystore
fi
