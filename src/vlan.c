#include "global.h"
#include "protc.h"
#include "hdr.h"

Vlan_Hdr * vlan_parse(const unsigned char *packet) {
    Vlan_Hdr * vlan_hdr = malloc(sizeof(Vlan_Hdr));
    if (!vlan_hdr) return NULL;
    memcpy(vlan_hdr, packet, sizeof(Vlan_Hdr));
    vlan_hdr->tpid = htons(vlan_hdr->tpid);
    vlan_hdr->pcv.pcv = htons(vlan_hdr->pcv.pcv);

    return  vlan_hdr;
}
void vlan_print(const Vlan_Hdr * vlan_hdr) {
    if (vlan_hdr->tpid == ETH_II_TYPE_VLAN) {
        printf("\t VLAN Header :  ");
    }
    printf("\t PRI:%d CFI:%d VID:%d \n",vlan_hdr->pcv.pri,vlan_hdr->pcv.cfi,vlan_hdr->pcv.vid);
}