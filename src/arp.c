#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#include "hdr.h"
#include "protc.h"
#include "global.h"

char * get_ip_str(uint32_t ip) {
    char * ip_str = malloc(16);
    uint8_t seg1 = (ip >> 24) & 0xFF;  // 最高8位 → 第一段（如192）
    uint8_t seg2 = (ip >> 16) & 0xFF;  // 次高8位 → 第二段（如168）
    uint8_t seg3 = (ip >> 8) & 0xFF;   // 次低8位 → 第三段（如1）
    uint8_t seg4 = ip & 0xFF;          // 最低8位 → 第四段（如1）

    snprintf(ip_str, 16, "%u.%u.%u.%u", seg1, seg2, seg3, seg4);
    return ip_str;
}

static  uint32_t  from_ip_str(const char * ip_str) {
    uint32_t ip = 0;
    int seg1, seg2, seg3, seg4;
    int count = sscanf(ip_str, "%d.%d.%d.%d", &seg1, &seg2, &seg3, &seg4);
    ip = ((uint32_t)seg1 << 24) |
               ((uint32_t)seg2 << 16) |
               ((uint32_t)seg3 << 8)  |
               (uint32_t)seg4;
    return ip;
}

Arp_Hdr * arp_parse(const unsigned char *packet) {
    Arp_Hdr * arp_hdr = malloc(sizeof(Arp_Hdr));
    if (!arp_hdr) return NULL;
    memcpy(arp_hdr,packet,sizeof(Arp_Hdr));
    arp_hdr->h_type = ntohs(arp_hdr->h_type);
    arp_hdr->p_type = ntohs(arp_hdr->p_type);
    arp_hdr->operate = ntohs(arp_hdr->operate);     //ntohs是16字节
    arp_hdr->spa = ntohl(arp_hdr->spa);             //ntohl是32字节
    arp_hdr->tpa = ntohl(arp_hdr->tpa);

    return arp_hdr;
}

void arp_print(const Arp_Hdr * arp_hdr) {
    if (arp_hdr->p_type == ETH_II_TYPE_IPV4) {
        printf("who has %s,tell %s \n",get_ip_str(arp_hdr->tpa),get_ip_str(arp_hdr->spa));
    }
    printf("operator op:%d\n",arp_hdr->operate);
}

static int host_mac(uint8_t * mac_val) {
    const char * mac = HOST_MAC;
    for (int i = 0;i < ETH_II_MAC_LEN;++i) {
        if (sscanf(mac+3*i,"%2hhx",&mac_val[i]) != 1) {
            return -1;
        }
    }
    return 0;
}

int arp_send(pcap_t * handle,char * tpa,uint8_t type) {
    EthII_Hdr eth_hdr = {.type = htons(ETH_II_TYPE_ARP)};
    host_mac(eth_hdr.source_mac);
    memset(eth_hdr.target_mac,0xFF,ETH_II_MAC_LEN);

    Arp_Hdr arp_hdr = {
        .h_type = htons(1),
        .p_type = htons(ETH_II_TYPE_IPV4),
        .h_len = 6,
        .p_len = 4,
        .operate = htons(1),
        .spa = htonl(from_ip_str(IP))
    };
    host_mac(arp_hdr.sha); // 源MAC
    int pl = 0; // 数据包长度
    if (type == ARP_GRATUITOUS) {
        pl = 60;
        memset(arp_hdr.tha,0xff,ETH_II_MAC_LEN);
    }
    else if (type == ARP_REQUEST) {
        pl = sizeof(EthII_Hdr) + sizeof(Arp_Hdr);
        memset(arp_hdr.tha,0,ETH_II_MAC_LEN);
        arp_hdr.tpa = htonl(from_ip_str(tpa));
    }
    uint8_t data[pl];
    memset(data,0,pl);
    memcpy(data,&eth_hdr,sizeof(EthII_Hdr));
    memcpy(data + sizeof(EthII_Hdr),&arp_hdr,sizeof(Arp_Hdr));

    // Send the packet
    if (pcap_sendpacket(handle,data,pl) != 0) {
        fprintf(stderr,"pcap_sendpacket error\n");
        return -1;
    }
    else {
        printf("pcap_sendpacket success\n");
    }
    return 0;
}