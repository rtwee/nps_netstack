#ifndef  HDR_H
#define  HDR_H

#include <stdint.h>

#define  ETH_II_MAC_LEN 6

// Ethernet II Header 以太网头
typedef struct __attribute__((__packed__)){
    uint8_t target_mac[ETH_II_MAC_LEN];
    uint8_t source_mac[ETH_II_MAC_LEN];
    uint16_t type;  //标识类型
}EthII_Hdr;

// ARP Header
typedef struct __attribute__((__packed__)) {
    uint16_t h_type; // 硬件类型 以太网是1标识
    uint16_t p_type; // 协议类型 IP是0x0800对应上面的Ethernet II Header
    uint8_t  h_len;  // 硬件地址长度：MAC是6
    uint8_t  p_len;  // 协议地址长度：IP地址是4
    uint16_t operate;// 操作类型：1请求，2回复
    uint8_t  sha[ETH_II_MAC_LEN];    //源MAC
    uint32_t spa;                    //源IP
    uint8_t  tha[ETH_II_MAC_LEN];    //目的MAC
    uint32_t tpa;                    //目的IP
}Arp_Hdr;


// IP Header
typedef struct __attribute__((__packed__)) {
    uint8_t ihl:4;          // 首部长度
    uint8_t version:4;      // 版本
    uint8_t tos;            // 区分服务
    uint16_t tot_len;       // 总长度
    uint16_t id;            // 标识，用来区分是哪个数据包
    union {
        uint16_t v;
        struct {            // 标志分片和偏移信息的
            uint16_t fo:13;
            uint16_t flag:3;
        };
    }ff;
    uint8_t ttl;            // 生存时间
    uint8_t proto;          // 协议
    uint16_t checksum;      // 校验码
    uint32_t src_ip;
    uint32_t dst_ip;
}Ip_Hdr;

#endif