#!/usr/bin/env bash

# env variables NP2_MODULE_DIR, NP2_MODULE_PERMS and LN2_MODULE_DIR must be defined
# and NP2_MODULE_OWNER, NP2_MODULE_GROUP will be used if defined when executing this script!

if [ -z "$NP2_MODULE_DIR" -o -z "$NP2_MODULE_PERMS" -o -z "$LN2_MODULE_DIR" ]; then
    echo "Required environment variables not defined!"
    exit 1
fi

# import functions and modules arrays
script_directory=$(dirname "$0")
source "${script_directory}/common.sh"

# get path to sysrepoctl executable, this will be stored in $SYSREPOCTL
SYSREPOCTL_GET_PATH

NP2_MODDIR=${DESTDIR}${NP2_MODULE_DIR}
LN2_MODDIR=${DESTDIR}${LN2_MODULE_DIR}
PERMS=${NP2_MODULE_PERMS}
OWNER=${NP2_MODULE_OWNER}
GROUP=${NP2_MODULE_GROUP}

# functions
function INSTALL_MODULE_CMD() {
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

function UPDATE_MODULE() {
    CMD="'$SYSREPOCTL' -U $1/$2 -s '$1' -v2"
    eval "$CMD"
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

function CHANGE_PERMS() {
    CMD="'$SYSREPOCTL' -c $1 -p '$PERMS' -v2"
    if [ ! -z "${OWNER}" ]; then
        CMD="$CMD -o '$OWNER'"
    fi
    if [ ! -z "${GROUP}" ]; then
        CMD="$CMD -g '$GROUP'"
    fi

    eval "$CMD"
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

function ENABLE_FEATURE() {
    "$SYSREPOCTL" -c $1 -e $2 -v2
    local rc=$?
    if [ $rc -ne 0 ]; then
        exit $rc
    fi
}

function SETUP_CMD() {
    module_dir="$1"     # first argument - module directory
    shift               # shift all args to the left
    modules=("$@")      # the rest of the arguments are module names (and their features)
    for i in "${modules[@]}"; do
        name=$(echo "$i" | sed 's/\([^@]*\).*/\1/')
        sctl_module=$(echo "$SCTL_MODULES" | grep "^$name \+|[^|]*| I")
        if [ -z "$sctl_module" ]; then
            # prepare command to install module with all its features
            INSTALL_MODULE_CMD "$module_dir" "$i"
            continue
        fi

        sctl_revision=$(echo "$sctl_module" | sed 's/[^|]*| \([^ ]*\).*/\1/')
        revision=$(echo "$i" | sed 's/[^@]*@\([^\.]*\).*/\1/')
        if [ "$sctl_revision" \< "$revision" ]; then
            # update module without any features
            file=$(echo "$i" | cut -d' ' -f 1)
            UPDATE_MODULE "$module_dir" "$file"
        fi

        sctl_owner=$(echo "$sctl_module" | sed 's/\([^|]*|\)\{3\} \([^:]*\).*/\2/')
        sctl_group=$(echo "$sctl_module" | sed 's/\([^|]*|\)\{3\}[^:]*:\([^ ]*\).*/\2/')
        sctl_perms=$(echo "$sctl_module" | sed 's/\([^|]*|\)\{4\} \([^ ]*\).*/\2/')
        if [ "$sctl_perms" != "$PERMS" ] || [ ! -z "${OWNER}" -a "$sctl_owner" != "$OWNER" ] || [ ! -z "${GROUP}" -a "$sctl_group" != "$GROUP" ]; then
            # change permissions/owner
            CHANGE_PERMS "$name"
        fi

        # parse sysrepoctl features and add extra space at the end for easier matching
        sctl_features="`echo "$sctl_module" | sed 's/\([^|]*|\)\{6\}\(.*\)/\2/'` "
        # parse features we want to enable
        features=$(echo "$i" | sed 's/[^ ]* \(.*\)/\1/')
        while [ "${features:0:3}" = "-e " ]; do
            # skip "-e "
            features=${features:3}
            # parse feature
            feature=$(echo "$features" | sed 's/\([^[:space:]]*\).*/\1/')

            # enable feature if not already
            sctl_feature=$(echo "$sctl_features" | grep " ${feature} ")
            if [ -z "$sctl_feature" ]; then
                # enable feature
                ENABLE_FEATURE $name $feature
            fi

            # next iteration, skip this feature
            features=$(echo "$features" | sed 's/[^[:space:]]* \(.*\)/\1/')
        done
    done
}

# get current modules
SCTL_MODULES=`$SYSREPOCTL -l`

# the install command will be stored in this variable
CMD_INSTALL=

# setup the cmd for install, modules are listed in common.sh
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
