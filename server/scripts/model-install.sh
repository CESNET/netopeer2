#!/bin/bash

set -eux -o pipefail

shopt -s failglob

local_path=$(dirname $0)

: ${SYSREPOCTL:=sysrepoctl}
: ${SYSREPOCFG:=sysrepocfg}
: ${SYSREPOCTL_ROOT_PERMS:=-o root:root -p 600}
: ${STOCK_CONFIG:=$local_path/../stock_config.xml}
: ${YANG_DIR:=$local_path/../../modules}

install_yang_module() {
    module=$1

    if ! $SYSREPOCTL -l | grep "$module[^|]*|[^|]*| Installed[^\\n]*"; then
        $SYSREPOCTL -i -g ${YANG_DIR}/$module.yang $SYSREPOCTL_ROOT_PERMS
    fi
}

if ! $SYSREPOCTL -l | grep "ietf-keystore [^\\n]*"; then
    exit 0
fi

install_yang_module ietf-netconf-server
for f in listen ssh-listen tls-listen call-home ssh-call-home tls-call-home; do
    $SYSREPOCTL -m ietf-netconf-server -e $f
done

install_yang_module ietf-system
for f in authentication local-users; do
    $SYSREPOCTL -m ietf-system -e $f
done

if [ -n "$($SYSREPOCFG -d startup -f xml --export ietf-netconf-server)" ]; then
    exit 0
fi

$SYSREPOCFG -d startup -i $STOCK_CONFIG ietf-netconf-server
