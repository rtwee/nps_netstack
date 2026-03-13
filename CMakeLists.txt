cmake_minimum_required(VERSION 4.1)
project(nps_netstack C)

set(CMAKE_C_STANDARD 11)
set(NPCAP_DIR ${PROJECT_SOURCE_DIR}/npcap)

include_directories(${NPCAP_DIR}/Include)
include_directories(${PROJECT_SOURCE_DIR}/Include)


link_directories(${NPCAP_DIR}/Lib/x64)

add_executable(nps_netstack
        main.c
        src/nps.c
        src/device.c
        src/ethii.c
        src/arp.c
        src/ip.c
        src/icmp.c
        src/vlan.c
)

target_link_libraries(nps_netstack
        Packet.lib
        wpcap.lib
        ws2_32.lib)
