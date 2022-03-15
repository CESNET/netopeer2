#!/usr/bin/env bash
# {% raw %} - jinja2 command to not process "{#" in the script

# optional env variable override
if [ -n "$SYSREPOCTL_EXECUTABLE" ]; then
    SYSREPOCTL="$SYSREPOCTL_EXECUTABLE"
# avoid problems with sudo PATH
elif [ `id -u` -eq 0 ]; then
    SYSREPOCTL=`su -c 'command -v sysrepoctl' -l $USER`
else
    SYSREPOCTL=`command -v sysrepoctl`
fi

# array of modules to remove, exact same as setup.sh
MODULES=(
"ietf-netconf@2013-09-29.yang -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath -e confirmed-commit"
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
"ietf-interfaces@2018-02-20.yang"
"ietf-ip@2018-02-22.yang"
"ietf-network-instance@2019-01-21.yang"
"ietf-subscribed-notifications@2019-09-09.yang -e encode-xml -e replay -e subtree -e xpath"
"ietf-yang-push@2019-09-09.yang -e on-change"
)

# functions
UNINSTALL_MODULE() {
    "$SYSREPOCTL" -u $1 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

DISABLE_FEATURE() {
    "$SYSREPOCTL" -c $1 -d $2 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

DISABLE_MODULE_FEATURES() {
    name=$1
    sctl_module=$2
    module=$3

    # parse sysrepoctl features and add extra space at the end for easier matching
    sctl_features="`echo "$sctl_module" | sed 's/\([^|]*|\)\{6\}\(.*\)/\2/'` "

    # parse feature into an array and iterate them backwards
    features=($module)
    feat_len=${#features[@]}
    for (( j = 0; j < $feat_len - 1; j=$j + 2 )); do
        feature=${features[$feat_len - ($j + 1)]}

        # disable feature if enabled
        sctl_feature=`echo "$sctl_features" | grep " ${feature} "`
        if [ -n "$sctl_feature" ]; then
            DISABLE_FEATURE $name $feature
        fi
    done
}

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

MODULES_LEN=${#MODULES[@]}
for (( i = 0; i < $MODULES_LEN; i++ )); do
    # backwards iteration to avoid module dependencies
    module=${MODULES[$MODULES_LEN - ($i + 1)]}
    name=`echo "$module" | sed 's/\([^@]*\).*/\1/'`

    SCTL_MODULE=`echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I"`
    if [ -n "$SCTL_MODULE" ]; then
        if [ "$name" = "ietf-netconf" ]; then
            # internal module, we can only disable features
            DISABLE_MODULE_FEATURES $name "$SCTL_MODULE" "$module"
        else
            # uninstall module
            UNINSTALL_MODULE "$name"
        fi
        continue
    fi
done

# {% endraw %}
