#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "protc.h"
#include "hdr.h"

EthII_Hdr * eth_ii_parse(const unsigned char *packet) {
    EthII_Hdr * eth_ii = malloc(sizeof(EthII_Hdr));
    if (eth_ii == NULL) {
        return eth_ii;
    }
    memcpy(eth_ii, packet, sizeof(EthII_Hdr));
    eth_ii->type = ntohs(eth_ii->type);

    return eth_ii;
}

void eth_ii_print(const EthII_Hdr * eth_ii) {
    if (eth_ii == NULL) {
        return;
    }
    if (eth_ii->type == 0x800) {
        printf("Ethernet type: IPv4\n");
    }
    else if (eth_ii->type == 0x806) {
        printf("Ethernet type: ARP\n");
    }
    else if (eth_ii->type == 0x86DD) {
        printf("Ethernet type: IPv6\n");
    }
    else {
        printf("Ethernet type: Unknown\n");
    }

    for (int i = 0; i < ETH_II_MAC_LEN; ++i) {
        printf("%x",eth_ii->target_mac[i]);
        if (i+1 < ETH_II_MAC_LEN) printf(":");
    }
    printf(" --> ");
    for (int i = 0; i < ETH_II_MAC_LEN; ++i) {
        printf("%x",eth_ii->source_mac[i]);
        if (i+1 < ETH_II_MAC_LEN) printf(":");
    }
    printf("\n");

}