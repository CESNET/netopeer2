#!/usr/bin/env bash

# env variables NP2_MODULE_DIR, NP2_MODULE_PERMS and LN2_MODULE_DIR must be defined and NP2_MODULE_OWNER, NP2_MODULE_GROUP will be used if
# defined when executing this script!
if [ -z "$NP2_MODULE_DIR" -o -z "$NP2_MODULE_PERMS" -o -z "$LN2_MODULE_DIR" ]; then
    echo "Required environment variables not defined!"
    exit 1
fi

# optional env variable override
if [ -n "$SYSREPOCTL_EXECUTABLE" ]; then
    SYSREPOCTL="$SYSREPOCTL_EXECUTABLE"
# avoid problems with sudo PATH
elif [ `id -u` -eq 0 ] && [ -n "$USER" ] && [ `command -v su` ]; then
    SYSREPOCTL=`su -c 'command -v sysrepoctl' -l $USER`
else
    SYSREPOCTL=`command -v sysrepoctl`
fi

NP2_MODDIR=${DESTDIR}${NP2_MODULE_DIR}
LN2_MODDIR=${DESTDIR}${LN2_MODULE_DIR}
PERMS=${NP2_MODULE_PERMS}
OWNER=${NP2_MODULE_OWNER}
GROUP=${NP2_MODULE_GROUP}

# arrays of modules to install
NP2_MODULES=(
"ietf-netconf@2013-09-29.yang -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath -e confirmed-commit"
"ietf-netconf-monitoring@2010-10-04.yang"
"ietf-netconf-nmda@2019-01-07.yang -e origin -e with-defaults"
"nc-notifications@2008-07-14.yang"
"notifications@2008-07-14.yang"
"ietf-interfaces@2018-02-20.yang"
"ietf-ip@2018-02-22.yang"
"ietf-subscribed-notifications@2019-09-09.yang -e encode-xml -e replay -e subtree -e xpath"
"ietf-yang-push@2019-09-09.yang -e on-change"
)

LN2_MODULES=(
"iana-ssh-encryption-algs@2022-06-16.yang"
"iana-ssh-key-exchange-algs@2022-06-16.yang"
"iana-ssh-mac-algs@2022-06-16.yang"
"iana-ssh-public-key-algs@2022-06-16.yang"
"iana-tls-cipher-suite-algs@2022-06-16.yang"
"ietf-x509-cert-to-name@2014-12-10.yang"
"iana-crypt-hash@2014-04-04.yang -e crypt-hash-md5 -e crypt-hash-sha-256 -e crypt-hash-sha-512"
"ietf-crypto-types@2023-04-17.yang -e cleartext-passwords -e cleartext-private-keys"
"ietf-keystore@2023-04-17.yang -e central-keystore-supported -e inline-definitions-supported -e asymmetric-keys"
"ietf-truststore@2023-04-17.yang -e central-truststore-supported -e inline-definitions-supported -e certificates -e public-keys"
"ietf-tcp-common@2023-04-17.yang -e keepalives-supported"
"ietf-tcp-server@2023-04-17.yang -e tcp-server-keepalives"
"ietf-tcp-client@2023-04-17.yang -e local-binding-supported -e tcp-client-keepalives"
"ietf-ssh-common@2023-04-17.yang -e transport-params"
"ietf-ssh-server@2023-04-17.yang -e local-users-supported -e local-user-auth-publickey -e local-user-auth-password -e local-user-auth-none"
"ietf-tls-common@2023-04-17.yang -e tls10 -e tls11 -e tls12 -e tls13 -e hello-params"
"ietf-tls-server@2023-04-17.yang -e server-ident-x509-cert -e client-auth-supported -e client-auth-x509-cert"
"ietf-netconf-server@2023-04-17.yang -e ssh-listen -e tls-listen -e ssh-call-home -e tls-call-home -e central-netconf-server-supported"
"libnetconf2-netconf-server@2023-09-07.yang"
)

CMD_INSTALL=

# functions
INSTALL_MODULE_CMD() {
    if [ -z "${CMD_INSTALL}" ]; then
        CMD_INSTALL="'$SYSREPOCTL' -s '$1' -v2"
    fi

    CMD_INSTALL="$CMD_INSTALL -i $1/$2 -p '$PERMS'"
    if [ ! -z "${OWNER}" ]; then
        CMD_INSTALL="$CMD_INSTALL -o '$OWNER'"
    fi
    if [ ! -z "${GROUP}" ]; then
        CMD_INSTALL="$CMD_INSTALL -g '$GROUP'"
    fi
}

UPDATE_MODULE() {
    CMD="'$SYSREPOCTL' -U $1/$2 -s '$1' -v2"
    eval $CMD
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

CHANGE_PERMS() {
    CMD="'$SYSREPOCTL' -c $1 -p '$PERMS' -v2"
    if [ ! -z "${OWNER}" ]; then
        CMD="$CMD -o '$OWNER'"
    fi
    if [ ! -z "${GROUP}" ]; then
        CMD="$CMD -g '$GROUP'"
    fi
    eval $CMD
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

ENABLE_FEATURE() {
    "$SYSREPOCTL" -c $1 -e $2 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

SETUP_CMD() {
    module_dir="$1"     # first argument - module directory
    shift               # shift all args to the left
    modules=("$@")      # the rest of the arguments are module names (and their features)
    for i in "${modules[@]}"; do
        name=`echo "$i" | sed 's/\([^@]*\).*/\1/'`
        SCTL_MODULE=`echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I"`
        if [ -z "$SCTL_MODULE" ]; then
            # prepare command to install module with all its features
            INSTALL_MODULE_CMD "$module_dir" "$i"
            continue
        fi

        sctl_revision=`echo "$SCTL_MODULE" | sed 's/[^|]*| \([^ ]*\).*/\1/'`
        revision=`echo "$i" | sed 's/[^@]*@\([^\.]*\).*/\1/'`
        if [ "$sctl_revision" \< "$revision" ]; then
            # update module without any features
            file=`echo "$i" | cut -d' ' -f 1`
            UPDATE_MODULE "$module_dir" "$file"
        fi

        sctl_owner=`echo "$SCTL_MODULE" | sed 's/\([^|]*|\)\{3\} \([^:]*\).*/\2/'`
        sctl_group=`echo "$SCTL_MODULE" | sed 's/\([^|]*|\)\{3\}[^:]*:\([^ ]*\).*/\2/'`
        sctl_perms=`echo "$SCTL_MODULE" | sed 's/\([^|]*|\)\{4\} \([^ ]*\).*/\2/'`
        if [ "$sctl_perms" != "$PERMS" ] || [ ! -z "${OWNER}" -a "$sctl_owner" != "$OWNER" ] || [ ! -z "${GROUP}" -a "$sctl_group" != "$GROUP" ]; then
            # change permissions/owner
            CHANGE_PERMS "$name"
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
                ENABLE_FEATURE $name $feature
            fi

            # next iteration, skip this feature
            features=`echo "$features" | sed 's/[^[:space:]]* \(.*\)/\1/'`
        done
    done
}

SETUP_CMD "$NP2_MODDIR" "${NP2_MODULES[@]}"

SETUP_CMD "$LN2_MODDIR" "${LN2_MODULES[@]}"

# install all the new modules
if [ ! -z "${CMD_INSTALL}" ]; then
    eval $CMD_INSTALL
    rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
fi
