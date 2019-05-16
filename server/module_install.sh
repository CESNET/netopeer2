#!/bin/bash

if [ $# -lt 2 ]; then
    echo "Usage $0 <sysrepoctl-path> <netopeer2-modules-directory> [<module-owner>]"
    exit
fi

SYSREPOCTL=$1
MODDIR=$2
OWNER=${3:-`id -un`}
GROUP=`id -gn $OWNER`

$SYSREPOCTL -U $MODDIR/ietf-netconf.yang -s $MODDIR &&
$SYSREPOCTL -c ietf-netconf -e writable-running -e candidate -e rollback-on-error -e validate -e startup -e url -e xpath -o $OWNER -g $GROUP &&
$SYSREPOCTL -i $MODDIR/ietf-netconf-monitoring.yang &&
$SYSREPOCTL -c ietf-netconf-monitoring -o $OWNER -g $GROUP &&
$SYSREPOCTL -i $MODDIR/nc-notifications.yang -s $MODDIR &&
$SYSREPOCTL -c nc-notifications -o $OWNER -g $GROUP &&
$SYSREPOCTL -i $MODDIR/notifications.yang &&
$SYSREPOCTL -c notifications -o $OWNER -g $GROUP &&
echo "No sysrepo clients can be running as its shared memory was reset!" &&
rm /dev/shm/sr_ext_main /dev/shm/sr_main
