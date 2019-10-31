#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <sysrepoctl-path> <netopeer2-modules-directory> [<module-owner>]"
    exit
fi

set -e

SYSREPOCTL=$1
MODDIR=$2
OWNER=${3:-`id -un`}
GROUP=`id -gn $OWNER`

# ietf-netconf-acm
$SYSREPOCTL -i $MODDIR/ietf-netconf-acm@2018-02-14.yang -v2
# ietf-netconf
$SYSREPOCTL -U $MODDIR/ietf-netconf@2013-09-29.yang -s $MODDIR -v2
$SYSREPOCTL -c ietf-netconf -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath -o $OWNER -g $GROUP -v2
# ietf-netconf-monitoring
$SYSREPOCTL -i $MODDIR/ietf-netconf-monitoring@2010-10-04.yang -v2
$SYSREPOCTL -c ietf-netconf-monitoring -o $OWNER -g $GROUP -v2
# ietf-datastores
$SYSREPOCTL -i $MODDIR/ietf-datastores@2017-08-17.yang -v2
# ietf-netconf-nmda
$SYSREPOCTL -i $MODDIR/ietf-netconf-nmda@2019-01-07.yang -e origin -e with-defaults -s $MODDIR -v2
# notification modules
$SYSREPOCTL -i $MODDIR/nc-notifications@2008-07-14.yang -s $MODDIR -v2
$SYSREPOCTL -c nc-notifications -o $OWNER -g $GROUP -v2
$SYSREPOCTL -i $MODDIR/notifications@2008-07-14.yang -v2
$SYSREPOCTL -c notifications -o $OWNER -g $GROUP -v2
# ietf-netconf-server modules
$SYSREPOCTL -i $MODDIR/ietf-x509-cert-to-name@2014-12-10.yang -v2
$SYSREPOCTL -i $MODDIR/ietf-crypto-types@2019-07-02.yang -v2
$SYSREPOCTL -i $MODDIR/ietf-keystore@2019-07-02.yang -e keystore-supported -s $MODDIR -v2
$SYSREPOCTL -i $MODDIR/ietf-truststore@2019-07-02.yang -e truststore-supported -e x509-certificates -s $MODDIR -v2
$SYSREPOCTL -i $MODDIR/ietf-tcp-common@2019-07-02.yang -e keepalives-supported -s $MODDIR -v2
$SYSREPOCTL -i $MODDIR/ietf-ssh-server@2019-07-02.yang -e local-client-auth-supported -s $MODDIR -v2
$SYSREPOCTL -i $MODDIR/ietf-tls-server@2019-07-02.yang -e local-client-auth-supported -s $MODDIR -v2
$SYSREPOCTL -i $MODDIR/ietf-netconf-server@2019-07-02.yang -e ssh-listen -e tls-listen -e ssh-call-home -e tls-call-home -s $MODDIR -v2
