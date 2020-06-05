#!/bin/bash

# env variables NP2_MODULE_DIR, NP2_MODULE_PERMS, NP2_MODULE_OWNER, NP2_MODULE_GROUP must be defined when executing this script!
if [ -z "$NP2_MODULE_DIR" -o -z "$NP2_MODULE_PERMS" -o -z "$NP2_MODULE_OWNER" -o -z "$NP2_MODULE_GROUP" ]; then
    echo "Required environment variables not defined!"
    exit 1
fi

# avoid problems with sudo path
SYSREPOCTL=`su -c "PATH=$PATH which sysrepoctl" $USER`
MODDIR=${NP2_MODULE_DIR}
PERMS=${NP2_MODULE_PERMS}
OWNER=${NP2_MODULE_OWNER}
GROUP=${NP2_MODULE_GROUP}

# array of modules to install
MODULES=(
"ietf-netconf-acm@2018-02-14.yang"
"ietf-netconf@2013-09-29.yang -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath"
"ietf-netconf-monitoring@2010-10-04.yang"
"ietf-netconf-nmda@2019-01-07.yang -e origin -e with-defaults"
"nc-notifications@2008-07-14.yang"
"notifications@2008-07-14.yang"
"ietf-x509-cert-to-name@2014-12-10.yang"
"ietf-crypto-types@2019-07-02.yang"
"ietf-keystore@2019-07-02.yang -e keystore-supported"
"ietf-truststore@2019-07-02.yang -e truststore-supported -e x509-certificates"
"ietf-tcp-common@2019-07-02.yang -e keepalives-supported"
"ietf-ssh-server@2019-07-02.yang -e local-client-auth-supported"
"ietf-tls-server@2019-07-02.yang -e local-client-auth-supported"
"ietf-netconf-server@2019-07-02.yang -e ssh-listen -e tls-listen -e ssh-call-home -e tls-call-home"
)

# functions
INSTALL_MODULE() {
    "$SYSREPOCTL" -a -i $MODDIR/$1 -s "$MODDIR" -p "$PERMS" -o "$OWNER" -g "$GROUP" -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

UPDATE_MODULE() {
    "$SYSREPOCTL" -a -U $MODDIR/$1 -s "$MODDIR" -p "$PERMS" -o "$OWNER" -g "$GROUP" -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

ENABLE_FEATURE() {
    "$SYSREPOCTL" -a -c $1 -e $2 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

for i in "${MODULES[@]}"; do
    name=`echo "$i" | sed 's/\([^@]*\).*/\1/'`

    SCTL_MODULE=`echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I"`
    if [ -z "$SCTL_MODULE" ]; then
        # install module with all its features
        INSTALL_MODULE "$i"
        continue
    fi

    sctl_revision=`echo "$SCTL_MODULE" | sed 's/[^|]*| \([^ ]*\).*/\1/'`
    revision=`echo "$i" | sed 's/[^@]*@\([^\.]*\).*/\1/'`
    if [ "$sctl_revision" \< "$revision" ]; then
        # update module without any features
        file=`echo "$i" | cut -d' ' -f 1`
        UPDATE_MODULE "$file"
    fi

    # parse sysrepoctl features and add extra space at the end for easier matching
    sctl_features="`echo "$SCTL_MODULE" | sed 's/\([^|]*|\)\{6\}\(.*\)/\2/'` "
    # parse features we want to enable
    features=`echo "$i" | sed 's/[^ ]* \(.*\)/\1/'`
    while [ "${features:0:3}" = "-e " ]; do
        # skip "-e "
        features=${features:3}
        # parse feature
        feature=`echo "$features" | sed 's/\([^[:space:]]*\).*/\1/'`

        # enable feature if not already
        sctl_feature=`echo "$sctl_features" | grep " ${feature} "`
        if [ -z "$sctl_feature" ]; then
            # enable feature
            ENABLE_FEATURE "$name" "$feature"
        fi

        # next iteration, skip this feature
        features=`echo "$features" | sed 's/[^[:space:]]* \(.*\)/\1/'`
    done
done
