#ifndef ETHII_HDR_H
#define ETHII_HDR_H
#include <pcap.h>
#include "hdr.h"
#include <stdio.h>

// 网络层接口
EthII_Hdr * eth_ii_parse(const unsigned char *packet);
void eth_ii_print(const EthII_Hdr * eth_ii);

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

#endif
