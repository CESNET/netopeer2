#!/bin/sh

sudo apt-get update -qq
sudo apt-get install -y zlib1g-dev libssl-dev

git clone -b devel https://github.com/CESNET/libyang.git
cd libyang; mkdir build; cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_BUILD_TYPE=Release ..
make -j2 && sudo make install
cd ../..

if [  -d "libssh-0.7.3" ]; then
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
