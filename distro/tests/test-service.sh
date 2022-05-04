#!/bin/bash
set -ex

systemctl list-unit-files | grep 'netopeer2-server'
