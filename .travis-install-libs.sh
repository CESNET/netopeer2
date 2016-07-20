#!/bin/sh

sudo apt-get update -qq
sudo apt-get install -y libavl-dev libev-dev
sudo apt-get install -y zlib1g-dev libssl-dev
sudo apt-get install -y valgrind

if [ ! -d "$PWD/cmocka-1.0.1" ]; then
    echo "Building cmocka from source."
    wget https://cmocka.org/files/1.0/cmocka-1.0.1.tar.xz
    tar -xJvf cmocka-1.0.1.tar.xz
    cd cmocka-1.0.1 && mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
    cd ../..
else
    echo "Using cmocka from cache."
    cd cmocka-1.0.1/build
    sudo make install
    cd ../..
fi

git clone -b devel https://github.com/CESNET/libyang.git
cd libyang; mkdir build; cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..
make -j2 && sudo make install
cd ../..

if [ ! -d "$PWD/libssh-0.7.3" ]; then
    echo "Building libssh from source."
    wget https://git.libssh.org/projects/libssh.git/snapshot/libssh-0.7.3.tar.bz2
    tar -xjf libssh-0.7.3.tar.bz2
    cd libssh-0.7.3 && mkdir build && cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr .. && make -j2 && sudo make install
    cd ../..
else
    echo "Using libssh from cache."
    cd libssh-0.7.3/build
    sudo make install
    cd ../..
fi

git clone -b devel https://github.com/CESNET/libnetconf2.git
cd libnetconf2; mkdir build; cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..
make -j2 && sudo make install
cd ../..

if [ ! -d "$PWD/protobuf" ]; then
    echo "Building protobuf from source."
    git clone https://github.com/google/protobuf.git
    cd protobuf
    ./autogen.sh && ./configure --prefix=/usr && make -j2 && sudo make install
    cd ..
else
    echo "Using protobuf from cache."
    cd protobuf
    sudo make install
    cd ..
fi

if [ ! -d "$PWD/protobuf-c" ]; then
    echo "Building protobuf-c from source."
    git clone https://github.com/protobuf-c/protobuf-c.git
    cd protobuf-c
    ./autogen.sh && ./configure --prefix=/usr && make -j2 && sudo make install
    cd ..
else
    echo "Using protobuf-c from cache."
    cd protobuf-c
    sudo make install
    cd ..
fi

git clone https://github.com/sysrepo/sysrepo.git
cd sysrepo; mkdir build; cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX:PATH=/usr -DENABLE_TESTS=False -DREPOSITORY_LOC:PATH=/ets/sysrepo ..
make -j2 && sudo make install
cd ../..

if [ "${CC}" = "gcc" ]; then pip install --user codecov; export CFLAGS="-coverage"; fi
