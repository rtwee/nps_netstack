#include "hdr.h"
#include "protc.h"

extern uint16_t checksum(void * data,int len);

Icmp_Hdr * icmp_parse(const unsigned char *data,uint16_t length) { // 这个len是IP层来解析的
    Icmp_Hdr * icmp_header = malloc(length);
    if (icmp_header == NULL) return NULL;
    memcpy(icmp_header,data,length);
    if (FALSE==icmp_checksum(icmp_header,length)) {
        return NULL;
    }
    return icmp_header;
}

BOOL icmp_checksum(Icmp_Hdr * icmp_hdr,uint16_t length) {
    if (checksum(icmp_hdr,length) != 0) {
        free(icmp_hdr);
        return FALSE;
    }
    return TRUE;
}

void icmp_print(const Icmp_Hdr * icmp_hdr) {
    if (icmp_hdr == NULL) return;
    printf("\t\t ICMP:\t\t  TYPE: ");
    if (icmp_hdr->type == 0 && icmp_hdr->code == 0) {
        printf("Echo Replay\n");
    }
    else if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
        printf("Echo Request\n");
    }
}