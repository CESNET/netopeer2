#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <sysrepocfg-path> <openssl-path>"
    exit
fi

set -e

SYSREPOCFG=$1
OPENSSL=$2

# generate a new key
PRIVPEM=`${OPENSSL} genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform PEM 2>/dev/null`
# remove header/footer
PRIVKEY=`grep -v -- "-----" - <<STDIN
${PRIVPEM}
STDIN`
# get public key
PUBPEM=`openssl rsa -pubout 2>/dev/null <<STDIN
${PRIVPEM}
STDIN`
# remove header/footer
PUBKEY=`grep -v -- "-----" - <<STDIN
${PUBPEM}
STDIN`

# generate edit config
CONFIG="<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\">
    <listen>
        <endpoint>
            <name>default</name>
            <ssh>
                <ssh-server-parameters>
                    <server-identity>
                        <host-key xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" nc:operation=\"remove\">
                            <name>none</name>
                        </host-key>
                        <host-key>
                            <name>genkey</name>
                            <public-key>
                                <local-definition>
                                    <algorithm xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa2048</algorithm>
                                    <public-key>${PUBKEY}</public-key>
                                    <private-key>${PRIVKEY}</private-key>
                                </local-definition>
                            </public-key>
                        </host-key>
                    </server-identity>
                </ssh-server-parameters>
            </ssh>
        </endpoint>
    </listen>
</netconf-server>"
TMPFILE=`mktemp -u`
printf -- "${CONFIG}" > ${TMPFILE}
# apply it
${SYSREPOCFG} -E${TMPFILE} -d startup -f xml
# remove the tmp file
rm ${TMPFILE}
