#!/usr/bin/env bash

if [ -z "$NP2_SCRIPTS_DIR" ]; then
    echo "$0: Required environment variable NP2_SCRIPTS_DIR not set." >&2
    exit 1
fi

# import functions and modules arrays
source "${NP2_SCRIPTS_DIR}/common.sh"

# get path to sysrepoctl executable, this will be stored in $SYSREPOCTL
SYSREPOCTL_GET_PATH

# functions
function UNINSTALL_MODULE_QUIET() {
    "$SYSREPOCTL" -u $1 &> /dev/null
}

function DISABLE_FEATURE() {
    "$SYSREPOCTL" -c $1 -d $2 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

function DISABLE_MODULE_FEATURES() {
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


function UNINSTALL_CMD() {
    modules=("$@")
    nmodules=${#modules[@]}
    for (( i = 0; i < $nmodules; i++ )); do
        module=${modules[$nmodules - ($i + 1)]}
        name=$(echo "$module" | sed 's/\([^@]*\).*/\1/')

        sctl_module=$(echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I")
        if [ -n "$sctl_module" ]; then
            if [ "$name" = "ietf-netconf" ]; then
                # internal module, we can only disable features
                DISABLE_MODULE_FEATURES $name "$sctl_module" "$module"
            else
                # uninstall module and ignore the result, there may be new modules depending on this one
                UNINSTALL_MODULE_QUIET "$name"
            fi
            continue
        fi
    done
}

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

# uninstall np2 and ln2 modules
UNINSTALL_CMD "${NP2_MODULES[@]}"
UNINSTALL_CMD "${LN2_MODULES[@]}"
