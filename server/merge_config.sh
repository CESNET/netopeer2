#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <sysrepocfg-path> <keystore-key-name>"
    exit
fi

set -e

SYSREPOCFG=$1
KS_KEY_NAME=$2

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
                        <supported-authentication-methods>
                            <publickey/>
                            <passsword/>
                            <other>interactive</other>
                        </supported-authentication-methods>
                        <users/>
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
