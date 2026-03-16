#include  "protc.h"

Udp_Hdr * udp_parse(const unsigned char *data,uint16_t length) {
    Udp_Hdr * udp_hdr = malloc(length);
    if (udp_hdr == NULL) return NULL;
    memcpy(udp_hdr,data,length);
    udp_hdr->sp = ntohs(udp_hdr->sp);
    udp_hdr->tp = ntohs(udp_hdr->tp);
    udp_hdr->length = htons(udp_hdr->length);

    return udp_hdr;
}

extern uint16_t checksum(void * data,int len);

BOOL udp_checksum(Udp_Hdr * udp_hdr,uint16_t len) {
    return checksum(udp_hdr,len);
}

 void udp_print(const Udp_Hdr * udp) {
    printf("\t\t UDP info:  Port: %u -> %u,\t\t length:%u\n",udp->sp,udp->tp,udp->length);
    printf("\t\t UDP context: %s\n",udp->data);
}