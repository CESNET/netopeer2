# common.sh - contains common functions and variables for the scripts

# arrays of modules to (un)install
NP2_MODULES=(
"ietf-interfaces@2018-02-20.yang"
"ietf-ip@2018-02-22.yang"
"ietf-netconf@2013-09-29.yang -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath -e confirmed-commit"
"ietf-netconf-nmda@2019-01-07.yang -e origin -e with-defaults"
"notifications@2008-07-14.yang"
"nc-notifications@2008-07-14.yang"
"ietf-netconf-monitoring@2010-10-04.yang"
"ietf-network-instance@2019-01-21.yang"
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
"ietf-crypto-types@2023-12-28.yang -e cleartext-passwords -e cleartext-private-keys"
"ietf-keystore@2023-12-28.yang -e central-keystore-supported -e inline-definitions-supported -e asymmetric-keys"
"ietf-truststore@2023-12-28.yang -e central-truststore-supported -e inline-definitions-supported -e certificates -e public-keys"
"ietf-tcp-common@2023-12-28.yang -e keepalives-supported"
"ietf-tcp-server@2023-12-28.yang -e tcp-server-keepalives"
"ietf-tcp-client@2023-12-28.yang -e local-binding-supported -e tcp-client-keepalives"
"ietf-ssh-common@2023-12-28.yang -e transport-params"
"ietf-ssh-server@2023-12-28.yang -e local-users-supported -e local-user-auth-publickey -e local-user-auth-password -e local-user-auth-none"
"ietf-tls-common@2023-12-28.yang -e tls10 -e tls11 -e tls12 -e tls13 -e hello-params"
"ietf-tls-server@2023-12-28.yang -e server-ident-x509-cert -e client-auth-supported -e client-auth-x509-cert"
"ietf-netconf-server@2023-12-28.yang -e ssh-listen -e tls-listen -e ssh-call-home -e tls-call-home -e central-netconf-server-supported"
"libnetconf2-netconf-server@2024-01-15.yang"
)

# get path to the sysrepocfg executable
function SYSREPOCFG_GET_PATH() {
    if [ -n "$SYSREPOCFG_EXECUTABLE" ]; then
        # from env
        SYSREPOCFG="$SYSREPOCFG_EXECUTABLE"
    elif [ $(id -u) -eq 0 ] && [ -n "$USER" ] && [ $(command -v su) ]; then
        # running as root, avoid problems with sudo PATH ("|| true" used because "set -e" is applied)
        SYSREPOCFG=$(su -c 'command -v sysrepocfg' -l "$USER") || true
    else
        # normal user
        SYSREPOCFG=$(command -v sysrepocfg) || true
    fi

    if [ -z "$SYSREPOCFG" ]; then
        echo "$0: Unable to find sysrepocfg executable." >&2
        exit 1
    fi
}

# get path to the sysrepoctl executable
function SYSREPOCTL_GET_PATH() {
    if [ -n "$SYSREPOCTL_EXECUTABLE" ]; then
        # from env
        SYSREPOCTL="$SYSREPOCTL_EXECUTABLE"
    elif [ $(id -u) -eq 0 ] && [ -n "$USER" ] && [ $(command -v su) ]; then
        # running as root, avoid problems with sudo PATH
        SYSREPOCTL=$(su -c 'command -v sysrepoctl' -l "$USER") || true
    else
        # normal user
        SYSREPOCTL=$(command -v sysrepoctl) || true
    fi

    if [ -z "$SYSREPOCTL" ]; then
        echo "$0: Unable to find sysrepoctl executable." >&2
        exit 1
    fi
}

# get path to the openssl executable
function OPENSSL_GET_PATH() {
    if [ -n "$OPENSSL_EXECUTABLE" ]; then
        # from env
        OPENSSL="$OPENSSL_EXECUTABLE"
    elif [ $(id -u) -eq 0 ] && [ -n "$USER" ] && [ $(command -v su) ]; then
        # running as root, avoid problems with sudo PATH
        OPENSSL=$(su -c 'command -v openssl' -l "$USER") || true
    else
        # normal user
        OPENSSL=$(command -v openssl) || true
    fi

    if [ -z "$OPENSSL" ]; then
        echo "$0: Unable to find openssl executable." >&2
        exit 1
    fi
}
