#ifndef INC_GLOBAL_H
#define INC_GLOBAL_H

#define IP "192.168.31.222"
#define HOST_MAC "2C-6D-C1-66-87-94"
#define  ETH_II_TYPE_IPV4 0x800
#define  ETH_II_TYPE_IPV6 0x86dd
#define  ETH_II_TYPE_ARP 0x806
#define  ETH_II_TYPE_VLAN 0x8100

#define IP_TOP_TCP 6
#define IP_TOP_UDP 17
#define IP_TOP_ICMP 1

// 协议栈中的类型
#define SP_NULL     0
#define SP_ETH      1
#define SP_ARP      2
#define SP_IPv4     3
#define SP_IPv6     4
#define SP_ICMP     5
#define SP_TCP      6
#define SP_UDP      7
#define SP_VLAN     8

#endif
