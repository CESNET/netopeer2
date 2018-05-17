#!/bin/sh

if [[ (( "$TRAVIS_BRANCH" == *"master"* )) || (( "$TRAVIS_TAG" =~ "v"[0-9]+"."[0-9]+"."[0-9]+ )) ]]; then
    BRANCH="master"
else
    BRANCH="devel"
fi

sudo apt-get update -qq
sudo apt-get install -y zlib1g-dev libssl-dev
sudo apt-get install -y --force-yes libavl-dev libev-dev coreutils acl valgrind

if [ ! -d "cmocka-1.1.1/build" ]; then
    echo "Building cmocka from source."
    wget https://cmocka.org/files/1.1/cmocka-1.1.1.tar.xz
    tar -xJvf cmocka-1.1.1.tar.xz
    cd cmocka-1.1.1 && mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
    cd ../..
else
    echo "Using cmocka from cache."
    cd cmocka-1.1.1/build
    sudo make install
    cd ../..
fi

git clone -b $BRANCH https://github.com/CESNET/libyang.git
cd libyang; mkdir build; cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..
make -j2 && sudo make install
cd ../..

if [ ! -d "libssh-0.7.5/build" ]; then
    echo "Building libssh from source."
    wget https://git.libssh.org/projects/libssh.git/snapshot/libssh-0.7.5.tar.gz
    tar -xzf libssh-0.7.5.tar.gz
    mkdir libssh-0.7.5/build && cd libssh-0.7.5/build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
    cd ../..
else
    echo "Using libssh from cache."
    cd libssh-0.7.5/build
    sudo make install
    cd ../..
fi

git clone -b $BRANCH https://github.com/CESNET/libnetconf2.git
cd libnetconf2; mkdir build; cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..
make -j2 && sudo make install
cd ../..

if [ ! -f "protobuf/Makefile" ]; then
    echo "Building protobuf from source."
    wget https://github.com/google/protobuf/archive/v3.2.0.tar.gz
    tar -xzf v3.2.0.tar.gz
    cd protobuf-3.2.0
    ./autogen.sh && ./configure --prefix=/usr && make -j2 && sudo make install
    cd ..
else
    echo "Using protobuf from cache."
    cd protobuf
    sudo make install
    cd ..
fi

if [ ! -f "protobuf-c/Makefile" ]; then
    echo "Building protobuf-c from source."
    wget https://github.com/protobuf-c/protobuf-c/archive/v1.2.1.tar.gz
    tar -xzf v1.2.1.tar.gz
    cd protobuf-c-1.2.1
    ./autogen.sh && ./configure --prefix=/usr && make -j2 && sudo make install
    cd ..
else
    echo "Using protobuf-c from cache."
    cd protobuf-c
    sudo make install
    cd ..
fi

git clone -b $BRANCH https://github.com/sysrepo/sysrepo.git
cd sysrepo; mkdir build; cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=/usr -DBUILD_EXAMPLES=False -DENABLE_TESTS=False -DGEN_LANGUAGE_BINDINGS=0 -DREPOSITORY_LOC:PATH=/ets/sysrepo ..
make -j2 && sudo make install
cd ../..

if [ "${CC}" = "gcc" ]; then pip install --user codecov; export CFLAGS="-coverage"; fi
