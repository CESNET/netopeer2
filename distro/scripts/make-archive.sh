#!/bin/bash
# create archive from current source using git

VERSION=$(git describe --tags --always)
# skip "v" from start of version number (if it exists) and replace - with .
VERSION=${VERSION#v}
VERSION=${VERSION//[-]/.}

NAMEVER=netopeer2-$VERSION
ARCHIVE=$NAMEVER.tar.gz

git archive --format tgz --output $ARCHIVE --prefix $NAMEVER/ HEAD
mkdir -p pkg/archives/dev/
mv $ARCHIVE pkg/archives/dev/

# apkg expects stdout to list archive files
echo pkg/archives/dev/$ARCHIVE
