#ifndef ETHII_HDR_H
#define ETHII_HDR_H
#include "hdr.h"

// 网络层接口
EthII_Hdr * eth_ii_parse(const unsigned char *packet);
void eth_ii_print(const EthII_Hdr * eth_ii);

// ARP接口
Arp_Hdr * arp_parse(const unsigned char *packet);
void arp_print(const Arp_Hdr * arp_hdr);

#endif
