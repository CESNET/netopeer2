#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <sysrepoctl-path> <sysrepocfg-path> <netopeer2-modules-directory> [<module-owner>]"
    exit
fi

set -e

SYSREPOCTL=$1
SYSREPOCFG=$2
MODDIR=$3
OWNER=${4:-`id -un`}
GROUP=`id -gn $OWNER`

# ietf-netconf-acm
$SYSREPOCTL -i $MODDIR/ietf-netconf-acm@2018-02-14.yang
# ietf-netconf
$SYSREPOCTL -U $MODDIR/ietf-netconf@2013-09-29.yang -s $MODDIR
$SYSREPOCTL -c ietf-netconf -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath -o $OWNER -g $GROUP
# ietf-netconf-monitoring
$SYSREPOCTL -i $MODDIR/ietf-netconf-monitoring@2010-10-04.yang
$SYSREPOCTL -c ietf-netconf-monitoring -o $OWNER -g $GROUP
# notification modules
$SYSREPOCTL -i $MODDIR/nc-notifications@2008-07-14.yang -s $MODDIR
$SYSREPOCTL -c nc-notifications -o $OWNER -g $GROUP
$SYSREPOCTL -i $MODDIR/notifications@2008-07-14.yang
$SYSREPOCTL -c notifications -o $OWNER -g $GROUP
# ietf-netconf-server modules
$SYSREPOCTL -i $MODDIR/ietf-x509-cert-to-name@2014-12-10.yang
$SYSREPOCTL -i $MODDIR/ietf-crypto-types@2019-04-29.yang
$SYSREPOCTL -i $MODDIR/ietf-keystore@2019-04-29.yang -e local-keys-supported -s $MODDIR
$SYSREPOCTL -i $MODDIR/ietf-ssh-server@2019-04-29.yang -e local-client-auth-supported -e ssh-server-keepalives -s $MODDIR
$SYSREPOCTL -i $MODDIR/ietf-netconf-server@2019-04-29.yang -e ssh-listen -e ssh-call-home -s $MODDIR

# import default config
CONFIG="<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\">
    <listen>
        <endpoint>
            <name>default</name>
            <ssh>
                <tcp-server-parameters>
                    <local-address>0.0.0.0</local-address>
                </tcp-server-parameters>
                <ssh-server-parameters>
                    <server-identity>
                        <host-key>
                            <name>none</name>
                            <public-key>
                                <local-definition/>
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
                    <keepalives/>
                </ssh-server-parameters>
            </ssh>
        </endpoint>
    </listen>
</netconf-server>"
TMPFILE=`mktemp -u`
printf -- "$CONFIG" > $TMPFILE
# apply it to startup and running
$SYSREPOCFG --import=$TMPFILE -d startup -f xml
$SYSREPOCFG -C startup -m ietf-netconf-server
# remove the tmp file
rm $TMPFILE
