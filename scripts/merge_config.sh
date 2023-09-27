#!/usr/bin/env bash

set -e

# optional env variable override
if [ -n "$SYSREPOCFG_EXECUTABLE" ]; then
    SYSREPOCFG="$SYSREPOCFG_EXECUTABLE"
# avoid problems with sudo PATH
elif [ `id -u` -eq 0 ] && [ -n "$USER" ] && [ `command -v su` ]; then
    SYSREPOCFG=`su -c 'command -v sysrepocfg' -l $USER`
else
    SYSREPOCFG=`command -v sysrepocfg`
fi
KS_KEY_NAME=genkey

# check that there is no listen/Call Home configuration yet
SERVER_CONFIG=`$SYSREPOCFG -X -x "/ietf-netconf-server:netconf-server/listen/endpoint[1]/name | /ietf-netconf-server:netconf-server/call-home/netconf-client[1]/name"`
if [ -z "$SERVER_CONFIG" ]; then

# get the user who invoked the script and his password, use it to create an SSH user in the default config
CURRENT_USER="$SUDO_USER"
CURRENT_USER_PASSWORD=$(awk -v user="$CURRENT_USER" -F':' '$1 == user {print $2}' /etc/shadow)

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
                                <keystore-reference>$KS_KEY_NAME</keystore-reference>
                            </public-key>
                        </host-key>
                    </server-identity>
                    <client-authentication>
                        <users>
                            <user>
                                <name>$CURRENT_USER</name>
                                <password>$CURRENT_USER_PASSWORD</password>
                            </user>
                        </users>
                    </client-authentication>
                </ssh-server-parameters>
            </ssh>
        </endpoint>
    </listen>
</netconf-server>"
TMPFILE=`mktemp -u`
printf -- "$CONFIG" > $TMPFILE
# apply it to startup and running
$SYSREPOCFG --edit=$TMPFILE -d startup -f xml -m ietf-netconf-server -v2
$SYSREPOCFG -C startup -m ietf-netconf-server -v2
# remove the tmp file
rm $TMPFILE

fi
