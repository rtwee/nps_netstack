#include "device.h"
#include <winsock2.h>   // 基础 Winsock 定义（包含 sockaddr_in）
#include <ws2tcpip.h>   // 扩展网络函数（如 inet_ntop，比 inet_ntoa 更安全）
#include "hdr.h"
#include "protc.h"
#include "global.h"

void device_info()
{
    pcap_if_t * alldevs;    //网卡设备列表
    pcap_if_t * device;     //当前使用的网卡

    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取设备列表
    if (pcap_findalldevs(&alldevs,errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    printf("Network devices found:\n");

    //遍历获取的设备
    for (device = alldevs; device != NULL; device = device->next) {
        printf("\nDevice Name :%s\n",device->name);

        //显示描述
        if (device->description) {
            printf("Device Description :%s\n",device->description);
        }
        else {
            printf("No Device Description available\n");
        }

        // 遍历设备地址
        pcap_addr_t * addr;
        for (addr = device->addresses; addr != NULL; addr = addr->next) {
            //仅获取IPV4地址
            if (addr->addr && addr->addr->sa_family == AF_INET) { //说明是IPV4
                struct sockaddr_in * ip_addr = (struct sockaddr_in *)addr->addr;
                struct sockaddr_in * netmask = (struct sockaddr_in *)addr->netmask;

                printf("IP Address : %s\n",inet_ntoa(ip_addr->sin_addr));
                if (netmask) {
                    printf("Subnet Mask : %s\n",inet_ntoa(netmask->sin_addr));
                }
            }
        }
    }
    // 释放设备列表
    pcap_freealldevs(alldevs);
}

pcap_if_t* device_find(pcap_if_t *alldevs,const char *ip) {

    char errbuf[PCAP_ERRBUF_SIZE];  //错误信息的缓冲区

    if (pcap_findalldevs(&alldevs,errbuf) == -1) {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

    for (pcap_if_t * device = alldevs; device != NULL; device = device->next) {
        for (pcap_addr_t * addr = device->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in * ip_addr = (struct sockaddr_in *)addr->addr;
                if (strcmp(inet_ntoa(ip_addr->sin_addr),ip) == 0) {
                    return device;
                }

            }
        }
    }

    return NULL;
}

void print_dev_info(pcap_if_t * dev) {
    if (dev->description) {
        printf("Device Description :%s\n",dev->description);
    }
    else {
        printf("No Device Description available\n");
    }

    for (pcap_addr_t * addr=dev->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr && addr->addr->sa_family == AF_INET) { //说明是IPV4
            struct sockaddr_in * ip_addr = (struct sockaddr_in *)addr->addr;
            struct sockaddr_in * netmask = (struct sockaddr_in *)addr->netmask;

            printf("IP Address : %s\n",inet_ntoa(ip_addr->sin_addr));
            if (netmask) {
                printf("Subnet Mask : %s\n",inet_ntoa(netmask->sin_addr));
            }
        }
    }

}

void device_handler(unsigned char * user,const struct pcap_pkthdr * header,const u_char * packet) {
    printf("\nPacket captured:\n");
    printf("Timestamp: %ld.%ld seconds\n",header->ts.tv_sec,header->ts.tv_usec);
    printf("Packet length: %d\n",header->len);

    const unsigned char * data = (const unsigned char *)packet;

    EthII_Hdr * eth_ii = eth_ii_parse(data);
    eth_ii_print(eth_ii);

    data+=sizeof(EthII_Hdr);

    switch (eth_ii->type) {
        case ETH_II_TYPE_ARP:
            Arp_Hdr * arp_hdr = arp_parse(data);
            arp_print(arp_hdr);
            break;
        case ETH_II_TYPE_IPV4:
            const Ip_Hdr * ip = ip_parse(data);
            ip_print(ip);
            break;
        default:
            printf("\nUnknown packet type: %d\n",eth_ii->type);
            break;
    }

}