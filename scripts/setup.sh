#!/bin/bash

# env variables NP2_MODULE_DIR, NP2_MODULE_PERMS must be defined and NP2_MODULE_OWNER, NP2_MODULE_GROUP will be used if
# defined when executing this script!
if [ -z "$NP2_MODULE_DIR" -o -z "$NP2_MODULE_PERMS" ]; then
    echo "Required environment variables not defined!"
    exit 1
fi

# avoid problems with sudo PATH
if [ $(id -u) -eq 0 ]; then
    SYSREPOCTL=$(su -c 'which sysrepoctl' -l "$USER")
else
    SYSREPOCTL=$(which sysrepoctl)
fi
MODDIR=${DESTDIR}${NP2_MODULE_DIR}
PERMS=${NP2_MODULE_PERMS}
OWNER=${NP2_MODULE_OWNER}
GROUP=${NP2_MODULE_GROUP}

# array of modules to install
MODULES=(
"ietf-netconf-acm@2018-02-14.yang"
"ietf-netconf@2013-09-29.yang writable-running candidate rollback-on-error validate startup url xpath"
"ietf-netconf-monitoring@2010-10-04.yang"
"ietf-netconf-nmda@2019-01-07.yang origin with-defaults"
"nc-notifications@2008-07-14.yang"
"notifications@2008-07-14.yang"
"ietf-x509-cert-to-name@2014-12-10.yang"
"ietf-crypto-types@2019-07-02.yang"
"ietf-keystore@2019-07-02.yang keystore-supported"
"ietf-truststore@2019-07-02.yang truststore-supported x509-certificates"
"ietf-tcp-common@2019-07-02.yang keepalives-supported"
"ietf-ssh-server@2019-07-02.yang local-client-auth-supported"
"ietf-tls-server@2019-07-02.yang local-client-auth-supported"
"ietf-netconf-server@2019-07-02.yang ssh-listen tls-listen ssh-call-home tls-call-home"
)

# functions
INSTALL_MODULE() {
    CMD="'$SYSREPOCTL' -a -i $MODDIR/$1 -s '$MODDIR' -p '$PERMS' -v2"
    if [ -n "${OWNER}" ]; then
        CMD="$CMD -o '$OWNER'"
    fi
    if [ -n "${GROUP}" ]; then
        CMD="$CMD -g '$GROUP'"
    fi
    eval "$CMD"
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

UPDATE_MODULE() {
    CMD="'$SYSREPOCTL' -a -U $MODDIR/$1 -s '$MODDIR' -p '$PERMS' -v2"
    if [ -n "${OWNER}" ]; then
        CMD="$CMD -o '$OWNER'"
    fi
    if [ -n "${GROUP}" ]; then
        CMD="$CMD -g '$GROUP'"
    fi
    eval "$CMD"
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

ENABLE_FEATURE() {
    "$SYSREPOCTL" -a -c "$1" -e "$2" -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

ENABLE_FEATURES() {
    # parse sysrepoctl features and add extra space at the end for easier matching
    local sctl_features="$(echo "$SCTL_MODULE" | sed 's/\([^|]*|\)\{6\}\(.*\)/\2/') "
    # parse features we want to enable
    local features=$(echo "$i" | sed 's/[^ ]* \(.*\)/\1/')
    # parse feature
    local feature=$(echo "$features" | sed 's/\([^[:space:]]*\).*/\1/')
    # enable feature if not already
    sctl_feature=$(echo "$sctl_features" | grep " ${feature} ")
    if [ -z "$sctl_feature" ]; then
        # enable feature
	    ENABLE_FEATURE "$name" "$feature"
    fi
        # next iteration, skip this feature
        features=$(echo "$features" | sed 's/[^[:space:]]* \(.*\)/\1/')
    done
}

# get current modules
SCTL_MODULES=$($SYSREPOCTL -l)

for i in "${MODULES[@]}"; do
    name=$(echo "$i" | sed 's/\([^@]*\).*/\1/')

    SCTL_MODULE=$(echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I")
    if [ -z "$SCTL_MODULE" ]; then
        # install module with all its features
        INSTALL_MODULE "$i"
        ENABLE_FEATURES "$i"
        continue
    fi

    sctl_revision=$(echo "$SCTL_MODULE" | sed 's/[^|]*| \([^ ]*\).*/\1/')
    revision=$(echo "$i" | sed 's/[^@]*@\([^\.]*\).*/\1/')
    if [ "$sctl_revision" \< "$revision" ]; then
        # update module without any features
        file=$(echo "$i" | cut -d' ' -f 1)
        UPDATE_MODULE "$file"
    fi

    ENABLE_FEATURES "$i"
done
