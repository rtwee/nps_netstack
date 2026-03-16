#include "protc.h"
#include "hdr.h"
#include "global.h"


uint16_t checksum(void * data,int len) {
    uint32_t sum = 0;
    uint16_t * ptr = data;
    // 遍历数据，按照16位单元累加
    while (len > 1) {
        sum += *ptr++;
        if (sum > 0xffff) {
            sum = (sum & 0xffff) + 1;
        }
        len -= 2;
    }

    // 如果是奇数
    if (len == 1) {
        uint8_t last_byte = *(uint8_t *)ptr;
        sum += (last_byte << 8);
        if (sum > 0xffff) {
            sum = (sum & 0xffff) + 1;
        }
    }

    // 取反，返回校验
    return ~sum;
}

Ip_Hdr * ip_parse(const unsigned char *data) {
    Ip_Hdr * ip = malloc(sizeof(Ip_Hdr));


    if (ip == NULL) return NULL;
    memcpy(ip,data,sizeof(Ip_Hdr));

    if (ip_checksum(ip) == FALSE) return NULL;

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
    printf("\t Header:%u bytes , Total: %u bytes\n",ip_hdr->ihl * 4,ip_hdr->tot_len);
    printf("\t CHK:%#4x \n",ip_hdr->checksum);
    printf("\t TTL:%u \n",ip_hdr->ttl);
    if (ip_hdr->proto == IP_TOP_TCP) {
        printf("\t PROTO: TCP \n");
    } else if (ip_hdr->proto == IP_TOP_UDP) {
        printf("\t PROTO: UDP \n");
    }

    printf("\t %s -> %s\n",get_ip_str(ip_hdr->src_ip),get_ip_str(ip_hdr->dst_ip));

}


BOOL ip_checksum(Ip_Hdr * ip_hdr) {
    // 计算校验和
    uint16_t recv_checksum = ip_hdr->checksum;
    // 不计算校验和
    if (recv_checksum == 0) return TRUE;
    // 计算校验和
    ip_hdr->checksum = 0;
    if (checksum(ip_hdr,ip_hdr->ihl * 4) == recv_checksum) {
        ip_hdr->checksum = recv_checksum;
        return TRUE;
    }
    free(ip_hdr);
    return FALSE;
}