# nflog-go
nflog-go implements a go native implementation for the nflog netlink interface provided by Linux to the in-kernel packets logged by the kernel packet filter.

The library implements a subset of the functionality provided by
https://www.netfilter.org/projects/libnetfilter_log/

The library implements the following APIs
- Receiving logs (packets) from kernel based on groups and chains from iptables
