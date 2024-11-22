#!/usr/bin/env bash
NP2_TEST_ROOT_DIR="/home/netconf/netopeer2-1/build/repos"
[ -z "$NP2_TEST_ROOT_DIR" ] &&
        echo "Expected an argument with to the test directory" &&
        exit 1

for pidfile in $NP2_TEST_ROOT_DIR/*/np2.pid
do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")"
done
exit 0
