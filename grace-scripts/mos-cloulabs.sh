#! /bin/bash

sudo apt-get update
sudo apt-get install libnuma-dev
sudo apt-get install vim
sudo apt-get install iperf
sudo ./hyper.sh 16 39 0

git clone https://github.com/ndsl-kaist/mOS-networking-stack.git
cd mOS-networking-stack/
./setup.sh --compile-dpdk
./setup.sh --run-dpdk
