#ifndef INCLUDE_DEVICE_H_
#define INCLUDE_DEVICE_H_
#include <pcap.h>

void device_info();
void print_dev_info(pcap_if_t * dev);
pcap_if_t* device_find(pcap_if_t *alldevs,const char *ip);
void device_handler(unsigned char * user,const struct pcap_pkthdr * header,const u_char * packet);

#endif
