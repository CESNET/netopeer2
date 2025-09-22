#!/bin/bash
# create archive from current source using git

VERSION=$(grep set\(NP2SRV_VERSION CMakeLists.txt | cut -d ' ' -f 2 | tr -d ')')

NAMEVER=netopeer2-$VERSION
ARCHIVE=$NAMEVER.tar.gz

git archive --format tgz --output $ARCHIVE --prefix $NAMEVER/ HEAD
mkdir -p pkg/archives/dev/
mv $ARCHIVE pkg/archives/dev/

# apkg expects stdout to list archive files
echo pkg/archives/dev/$ARCHIVE
