# conntrack-go
conntrack-go implements a go native implementation for the conntrack netlink interface provided by Linux to the in-kernel connection tracking state table.

The library implements a subset of the functionality provided by
https://www.netfilter.org/projects/libnetfilter_conntrack/

The library implements the following APIs
 - Listing/flushing Conntrack entries from kernel connection tracking table
 - Updating entries from kernel connection tracking table (currently supports Mark and Labels*)
