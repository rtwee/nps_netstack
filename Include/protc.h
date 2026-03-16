#ifndef ETHII_HDR_H
#define ETHII_HDR_H
#include <pcap.h>
#include "hdr.h"
#include <stdio.h>

// 网络层接口
EthII_Hdr * eth_ii_parse(const unsigned char *packet);
void eth_ii_print(const EthII_Hdr * eth_ii);

// VLAN解析
Vlan_Hdr * vlan_parse(const unsigned char *packet);
void vlan_print(const Vlan_Hdr * vlan_hdr);

// ARP接口
#define ARP_GRATUITOUS  1
#define ARP_REQUEST 2
Arp_Hdr * arp_parse(const unsigned char *packet);
void arp_print(const Arp_Hdr * arp_hdr);
int arp_send(pcap_t * handle,char * tpa,uint8_t type);

// IP层接口
BOOL ip_checksum(Ip_Hdr * ip_hdr);
Ip_Hdr * ip_parse(const unsigned char *data);
void ip_print(const Ip_Hdr * ip_hdr);


// ICMP协议接口
Icmp_Hdr * icmp_parse(const unsigned char *data,uint16_t length);
BOOL icmp_checksum(Icmp_Hdr * icmp_hdr,uint16_t length);
void icmp_print(const Icmp_Hdr * icmp_hdr);


// UDP协议接口
Udp_Hdr * udp_parse(const unsigned char *data,uint16_t length);
BOOL udp_checksum(Udp_Hdr * udp_hdr,uint16_t len);
void udp_print(const Udp_Hdr * udp);

#endif
