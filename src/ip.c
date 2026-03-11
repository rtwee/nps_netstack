#include "protc.h"
#include "hdr.h"
#include "global.h"

Ip_Hdr * ip_parse(const unsigned char *data) {
    Ip_Hdr * ip = malloc(sizeof(Ip_Hdr));
    if (ip == NULL) return NULL;
    memcpy(ip,data,sizeof(Ip_Hdr));
    ip->tot_len = ntohs(ip->tot_len);
    ip->id = ntohs(ip->id);
    ip->ff.v = ntohs(ip->ff.v);
    ip->checksum=ntohs(ip->checksum);
    ip->src_ip=ntohl(ip->src_ip);
    ip->dst_ip=ntohl(ip->dst_ip);
    return ip;
}
extern char * get_ip_str(uint32_t ip);

void ip_print(const Ip_Hdr * ip_hdr) {
    printf("\t\t Header:%u bytes , Total: %u bytes\n",ip_hdr->ihl * 4,ip_hdr->tot_len);
    printf("\t\t CHK:%#4x \n",ip_hdr->checksum);
    printf("\t\t TTL:%u \n",ip_hdr->ttl);
    if (ip_hdr->proto == IP_TOP_TCP) {
        printf("\t\t PROTO: TCP \n");
    } else if (ip_hdr->proto == IP_TOP_UDP) {
        printf("\t\t PROTO: UDP \n");
    }

    printf("\t\t %s -> %s\n",get_ip_str(ip_hdr->src_ip),get_ip_str(ip_hdr->dst_ip));
}