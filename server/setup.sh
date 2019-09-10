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
$SYSREPOCTL -i $MODDIR/ietf-crypto-types@2019-07-02.yang
$SYSREPOCTL -i $MODDIR/ietf-keystore@2019-07-02.yang -e keystore-supported -s $MODDIR
$SYSREPOCTL -i $MODDIR/ietf-ssh-server@2019-07-02.yang -e local-client-auth-supported -e ssh-server-keepalives -s $MODDIR
$SYSREPOCTL -i $MODDIR/ietf-netconf-server@2019-07-02.yang -e ssh-listen -e ssh-call-home -s $MODDIR
