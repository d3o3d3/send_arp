#include "getmy.h"
#include "attack.h"

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}
	int attcnt = (argc - 2) / 2;


	uint8_t mmac[6];
	// uint32_t mip;
	char mip[16];

	uint8_t smac[6];

	if(getmac(argv[1], mmac) != 0) {
		printf("Can't Get Your MAC Address\n");
		return -1;
	}
	// // check mac address
	// for (int i = 0; i < 6; ++i)
	// 	printf(" %02x", (unsigned char)mmac[i]);
	// printf("\n");
	
	if(getip(argv[1], mip) != 0) {
		printf("Can't Get Your IP Address\n");
		return -1;
	}
	Mac myMac = Mac(mmac);
	// check ip address
	// for (int i = 0; i < 4; ++i)
	// 	printf(" %02d", *((unsigned char *)&mip+i));
	// printf("\n");
	// printf("%s\n", mip);
	Ip myIp = Ip(mip);

	for(int i = 0; i < attcnt;i++){
		getsmac(argv[1], smac, argv[2 + 2*i], myMac, myIp);
		Mac SenMac = Mac(smac);
		attsender(argv[1], SenMac, argv[2 + 2*i], myMac, myIp, argv[3 + 2*i]);
		printf("Attack %d!\n", i+1);
	}

	// getsmac(argv[1], smac, argv[2], myMac, myIp);
	// check smac address
	// for (int i = 0; i < 6; ++i)
	// 	printf(" %02x", (unsigned char)smac[i]);
	// printf("\n");
	// Mac SenMac = Mac(smac);

	// attsender(argv[1], SenMac, argv[2], myMac, myIp, argv[3]);
	
}
