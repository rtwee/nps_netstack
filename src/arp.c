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

Arp_Hdr * arp_parse(const unsigned char *packet) {
    Arp_Hdr * arp_hdr = malloc(sizeof(Arp_Hdr));
    if (!arp_hdr) return NULL;
    // memset(arp_hdr, 0, sizeof(Arp_Hdr));
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
        printf("\t\twho has %s,tell %s \n",get_ip_str(arp_hdr->tpa),get_ip_str(arp_hdr->spa));
    }
    printf("operator op:%d\n",arp_hdr->operate);
}