#!/usr/bin/env bash

set -e

# import functions
script_directory=$(dirname "$0")
source "${script_directory}/common.sh"

# temporarily disable "set -e", the script will still exit if sysrepocfg is not found
set +e

# get path to sysrepocfg executable, this will be stored in $SYSREPOCFG
SYSREPOCFG_GET_PATH

# re-enable "set -e"
set -e

# check that there is no listen/Call Home configuration yet
SERVER_CONFIG=$($SYSREPOCFG -X -x "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint | /ietf-netconf-server:netconf-server/call-home/netconf-client")
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
    # it exists, use the keys in the file
    AUTH_CONFIG="<public-keys>
                    <use-system-keys xmlns=\"urn:cesnet:libnetconf2-netconf-server\"/>
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

SSH_BANNER=""
# check if the NP2_VERSION environment variable is set
if [ -n "$NP2_VERSION" ]; then
    # get the banner from the NP2_VERSION environment variable
    SSH_BANNER="<banner xmlns=\"urn:cesnet:libnetconf2-netconf-server\">netopeer2-netconf-server-${NP2_VERSION}</banner>"
fi

# import default config
CONFIG="<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\">
    <listen>
        <endpoints>
            <endpoint>
                <name>default-ssh</name>
                <ssh>
                    <tcp-server-parameters>
                        <local-bind>
                            <local-address>0.0.0.0</local-address>
                        </local-bind>
                    </tcp-server-parameters>
                    <ssh-server-parameters>
                        <server-identity>
                            ${SSH_BANNER}
                            <host-key>
                                <name>default-key</name>
                                <public-key>
                                    <central-keystore-reference>genkey</central-keystore-reference>
                                </public-key>
                            </host-key>
                        </server-identity>
                        <client-authentication>
                            ${USERS_CONFIG}
                        </client-authentication>
                    </ssh-server-parameters>
                </ssh>
            </endpoint>
        </endpoints>
    </listen>
</netconf-server>"

# apply it to startup and running
echo "$CONFIG" | "$SYSREPOCFG" --edit -d startup -f xml -m ietf-netconf-server -v2
"$SYSREPOCFG" -C startup -m ietf-netconf-server -v2
