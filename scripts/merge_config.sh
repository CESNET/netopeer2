#!/usr/bin/env bash

set -e

if [ -z "$NP2_SCRIPTS_DIR" ]; then
    echo "$0: Required environment variable NP2_SCRIPTS_DIR not set." >&2
    exit 1
fi

# import functions
source "${NP2_SCRIPTS_DIR}/common.sh"

# get path to sysrepocfg executable, this will be stored in $SYSREPOCFG
SYSREPOCFG_GET_PATH

# check that there is no listen/Call Home configuration yet
SERVER_CONFIG=$($SYSREPOCFG -X -x "/ietf-netconf-server:netconf-server/listen/endpoint | /ietf-netconf-server:netconf-server/call-home/netconf-client")
if [ -n "$SERVER_CONFIG" ]; then
    # the server is configured, just exit
    exit 0
fi

# get the user who invoked the script and his password hash, use it to create an SSH user in the default config
CURRENT_USER="$SUDO_USER"
CURRENT_USER_PW_HASH=$(awk -v user="$CURRENT_USER" -F':' '$1 == user {print $2}' /etc/shadow)

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
                        <users>
                            <user>
                                <name>${CURRENT_USER}</name>
                                <password>${CURRENT_USER_PW_HASH}</password>
                            </user>
                        </users>
                    </client-authentication>
                </ssh-server-parameters>
            </ssh>
        </endpoint>
    </listen>
</netconf-server>"

# apply it to startup and running
echo "$CONFIG" | "$SYSREPOCFG" --edit -d startup -f xml -m ietf-netconf-server -v2
"$SYSREPOCFG" -C startup -m ietf-netconf-server -v2
