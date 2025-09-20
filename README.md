ASSIGNMENT 1: ROUTER IMPLEMENTATION
Stancu David-Ioan 322CA (year 2024-2025)

The purpose of the assignment is to implement a router capable of processing Ethernet frames,
handling both IPv4 protocols and ARP ones, as well as treating a couple of usually encountered 
errors, using ICMP protocols for timeout and unreachable host.

Core components:
1. Routing table: contains elements loaded from the given file
2. ARP table: stores the IP-MAC maps user for packet forwarding
3. Packet queue: stores the delayed packets and ensures their ARP handling 

Steps taken for each packet type
1. IPv4 packets
    - verification preocess: ensures the invalid packets are dropped
    - checksum check: checks if the checksum is valid
    - ICMP handling: depending on the error, generates a different message:
        * basic request: responds wqith an ECHO reply
        * TTL expired: generates a ICMP timeout message
        * route not found: generatea a destination unreachable message
    - updating TTL and checksum: done to ensure packet integrity and simulate the next hop
    - rerouting: finds best route uring LPM and searches for the next valid hop
    - package sending: updates ethernet header with the source and destination MAC addresses;
                       sends the packet afterwards 

2. ARP packets
    - verification process: checks what type of ARP opreation should be done: request of reply
    - correct building of the packet: ensures packets are built correctly based on type
    - queueing unresolved entries: when packets have an invalid MAC address for the next hop, 
                                   it gets sent to the packets queue by updating its information

