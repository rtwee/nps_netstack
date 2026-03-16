#include "protc.h"
#include "hdr.h"

Tcp_Hdr * tcp_parse(const unsigned char *data) {
    Tcp_Hdr * tcp_hdr = malloc(sizeof(Tcp_Hdr));
    if (!tcp_hdr) return NULL;
    memcpy(tcp_hdr,data,sizeof(Tcp_Hdr));

    tcp_hdr->sp = ntohs(tcp_hdr->sp);
    tcp_hdr->tp = ntohs(tcp_hdr->tp);
    tcp_hdr->seq = ntohl(tcp_hdr->seq);
    tcp_hdr->ack = ntohl(tcp_hdr->ack);
    tcp_hdr->ff.v = ntohs(tcp_hdr->ff.v);
    tcp_hdr->ws = ntohs(tcp_hdr->ws);
    tcp_hdr->up = ntohs(tcp_hdr->up);
    return tcp_hdr;
}
extern uint16_t checksum(void * data,int len);
BOOL tcp_checksum(Tcp_Hdr * tcp_hdr,uint16_t length) {
    return checksum(tcp_hdr,length) == TRUE;
}
void tcp_print(const Tcp_Hdr * tcp_hdr) {
    printf("\t\t\t Port: %u -> %u\n",tcp_hdr->sp,tcp_hdr->tp);
}