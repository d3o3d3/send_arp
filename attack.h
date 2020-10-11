#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

// int getsmac(char* interface, uint8_t * smac, char * sip, uint8_t * mmac, char * mip);
void getsmac(char* interface, uint8_t * smac, char * sip, Mac mmac, Ip mip);


void attsender(char* interface, Mac smac, char * sip, Mac mmac, Ip mip, char * tip);