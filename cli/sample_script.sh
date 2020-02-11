#!/bin/bash
netopeer2-cli <<END
connect
get-config --source running --out out.xml
disconnect
END
echo ""
exit 0
