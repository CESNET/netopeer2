#!/usr/bin/env bash

set -e

# import functions
script_directory=$(dirname "$0")
source "${script_directory}/common.sh"

# get path to sysrepocfg executable, this will be stored in $SYSREPOCFG
SYSREPOCFG_GET_PATH

# check that there is no listen/Call Home configuration yet
SERVER_CONFIG=$($SYSREPOCFG -X -x "/ietf-netconf-server:netconf-server/listen/endpoint | /ietf-netconf-server:netconf-server/call-home/netconf-client")
if [ -n "$SERVER_CONFIG" ]; then
    # the server is configured, just exit
    exit 0
fi

# get the user who invoked the script
CURRENT_USER="$SUDO_USER"
if [ -z "$CURRENT_USER" ]; then
    # the script was not invoked with sudo
    if [ "$(id -u)" -eq 0 ] && [ -n "$USER" ]; then
        # the script was invoked with su, get the target user
        CURRENT_USER="$USER"
    else
        # the script was not invoked with sudo or su, get the current user
        CURRENT_USER=$(whoami)
    fi
fi

# get his home dir
CURRENT_USER_HOME=$(eval echo "~$CURRENT_USER")
# try to get his authorized_keys file
AUTHORIZED_KEYS_FILE="$CURRENT_USER_HOME/.ssh/authorized_keys"
# check if the authorized keys file exists
if [ -f "$AUTHORIZED_KEYS_FILE" ]; then
    # it exists, create public keys that are authorized in the server's configuration
    AUTH_CONFIG="
                        <public-keys>
                            <inline-definition>"

    IDX=0
# read lines from authorized_keys
    while IFS= read -r LINE; do
        # check if the line is empty or starts with a comment (#)
        if [[ -n "$LINE" && ! "$LINE" =~ ^\s*# ]]; then
            # extract the base64 public key
            PUB_BASE64=$(echo "$LINE" | awk '{print $2}')

            NEW_PUBKEY_ENTRY="  <public-key>
                                    <name>authorized_key_${IDX}</name>
                                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>
                                    <public-key>${PUB_BASE64}</public-key>
                                </public-key>"
            # append
            AUTH_CONFIG="${AUTH_CONFIG}${NEW_PUBKEY_ENTRY}"
            IDX=$((IDX + 1))
        fi
    done < "$AUTHORIZED_KEYS_FILE"

    # append the ending tags
    AUTH_CONFIG="${AUTH_CONFIG}
                            </inline-definition>
                        </public-keys>"

    echo "--"
    echo "-- Added user \"${CURRENT_USER}\" that can authenticate with a key pair from his authorized_keys to the server configuration..."
    echo "--"
else
    # authorized_keys file doesn't exist, leave the authentication to the system
    AUTH_CONFIG="<keyboard-interactive xmlns=\"urn:cesnet:libnetconf2-netconf-server\">
                    <use-system-auth/>
                 </keyboard-interactive>"
    echo "--"
    echo "-- Added user \"${CURRENT_USER}\" that can authenticate with his password to the server configuration..."
    echo "--"
fi

if [ -n "$AUTH_CONFIG" ]; then
    # if we have some authentication configuration, add it to the users config
    USERS_CONFIG="<users>
                    <user>
                        <name>${CURRENT_USER}</name>
                        ${AUTH_CONFIG}
                    </user>
                </users>"
fi

# import default config
CONFIG="<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\">
    <listen>
        <endpoint>
            <name>default-ssh</name>
            <ssh>
                <tcp-server-parameters>
                    <local-address>0.0.0.0</local-address>
                    <keepalives>
                        <idle-time>1</idle-time>
                        <max-probes>10</max-probes>
                        <probe-interval>5</probe-interval>
                    </keepalives>
                </tcp-server-parameters>
                <ssh-server-parameters>
                    <server-identity>
                        <host-key>
                            <name>default-key</name>
                            <public-key>
                                <keystore-reference>genkey</keystore-reference>
                            </public-key>
                        </host-key>
                    </server-identity>
                    <client-authentication>
                        ${USERS_CONFIG}
                    </client-authentication>
                </ssh-server-parameters>
            </ssh>
        </endpoint>
    </listen>
</netconf-server>"

# apply it to startup and running
echo "$CONFIG" | "$SYSREPOCFG" --edit -d startup -f xml -m ietf-netconf-server -v2
"$SYSREPOCFG" -C startup -m ietf-netconf-server -v2
