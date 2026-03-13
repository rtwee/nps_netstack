#include "device.h"
#include "global.h"
#include <stdio.h>

#include "protc.h"

int main(void) {
    // device_info();
    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t * dev = device_find(alldevs,IP);
    if (dev == NULL) {
        fprintf(stderr,"No device found for %s\n",IP);
        exit(-1);
    }

    // 打开设备
    pcap_t * handle = pcap_open_live(dev->name,65536,1,100,errbuf);
    if (!handle) {
        fprintf(stderr,"pcap_open_live error: %s\n",errbuf);
        pcap_freealldevs(alldevs);
        exit(-1);
    }

#define USE_FILTER 1
#ifdef USE_FILTER
    // 设置过滤器
    struct bpf_program filter;
    // char filter_exp[]="arp or ip";
    char filter_exp[]="icmp";
    bpf_u_int32 net = 0;

    // 编译过滤器
    if (pcap_compile(handle,&filter,filter_exp,0,net) == -1) {
        printf("could not parse filter %s : %s\n",filter_exp,pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle,&filter) == -1) {
        fprintf(stderr,"could not set filter %s : %s\n",filter_exp,pcap_geterr(handle));
        exit(-1);
    }
#endif

    //开始抓包
    pcap_loop(handle,5,device_handler,NULL);


    // 发送ARP Request
    // for (int i = 0;i < 10;++i){
    //     arp_send(handle,"192.168.1.222",ARP_REQUEST);
    // }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
