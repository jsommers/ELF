#!/bin/bash -x

sudo apt-get update && sudo apt-get install -y build-essential cmake git golang mtr linux-headers-$(uname -r) python3-pyroute2 python3-dev python3-pandas 
go get -v github.com/m-lab/ndt7-client-go/cmd/ndt7-client
go get -v github.com/jsommers/someta
sudo apt-get -y install bison build-essential cmake flex git libedit-dev llvm-dev libclang-dev python zlib1g-dev libelf-dev 
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake .. -DPYTHON_CMD=python3 -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install

