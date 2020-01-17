# someta_ebpf

This is a repo for experimentation with active network measurement metadata
capture facilitated through the extended Berkeley Packet Filter (eBPF).

# Installation

Follow procedures for "Upstream Stable and Signed Packages" (i.e., don't use
ubuntu packages)
https://github.com/iovisor/bcc/blob/master/INSTALL.md

sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r) python-bcc python3-bcc python3-pyroute2

