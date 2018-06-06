#!/bin/bash

set -eux -o pipefail

shopt -s failglob

local_path=$(dirname $0)

: ${SYSREPOCTL:=sysrepoctl}
: ${SYSREPOCTL_ROOT_PERMS:=-o root:root -p 600}
: ${YANG_DIR:=$local_path/../../modules}

install_yang_module() {
    module=$1

    if ! $SYSREPOCTL -l | grep "$module[^|]*|[^|]*| Installed[^\\n]*"; then
        $SYSREPOCTL -i -g ${YANG_DIR}/$module.yang $SYSREPOCTL_ROOT_PERMS
    fi
}

install_yang_module ietf-x509-cert-to-name
install_yang_module ietf-keystore
