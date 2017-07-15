# nfqueue-go
Nfqueue-go implements a go native implementation for the nfqueue netlink interface provided by Linux to process packets capture by a linux kernel filter.

The library implements a subset of the functionality provided by
https://www.netfilter.org/projects/libnetfilter_queue/

The library implements the following APIs 
 - create queue 
 - process packets from the queue that are punted to it from the iptables match criteria.
 
It does not yet implememt parsing methods to get indev,physdev,outdev,outphysdev,indevnames,outdevnames,timestamp. 



