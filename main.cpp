#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "protocol/all.h"
#include "packet.h"

void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == -1 || res == -2)
			break;

		const ether_header *eth = (ether_header *)packet;
		int packetIndex = sizeof(ether_header);

		printf("\n%u bytes captured\n", header->caplen);
		printf("MAC SRC");
		printMac(eth->src);
		printf("MAC DST");
		printMac(eth->dst);

		if (ntohs(eth->ether_type) == ETHERTYPE_IP)
		{

			const ip_header *ip = (ip_header *)(packet + packetIndex);
			packetIndex += sizeof(ip_header);

			printf("Type: ipv4\n");

			printf("IP SRC");
			printIp(ip->ip_src);
			printf("IP DST");
			printIp(ip->ip_dst);
			if (ip->ip_p == 6)
			{

				const tcp_header *tcp = (tcp_header *)(packet + packetIndex);

				printf("TCP SRC PORT: %d\n", ntohs(tcp->tcp_src_port));
				printf("TCP DST PORT: %d\n", ntohs(tcp->tcp_dst_port));

				uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4));
				packetIndex += sizeof(tcp_header);
				const u_char *data = packet + packetIndex;
				if (tcp_size > 0)
				{
					printData(tcp_size, data);
				}
			}
			else if (ip->ip_p == 17)
			{

				const udp_header *udp = (udp_header *)(packet + packetIndex);

				printf("UDP SRC PORT: %d\n", ntohs(udp->udp_src_port));
				printf("UPD DST PORT: %d\n", ntohs(udp->udp_dst_port));

				uint32_t udp_size = (ntohs(ip->ip_len) - sizeof(udp_header));
				packetIndex += sizeof(udp_header);
				const u_char *data = packet + packetIndex;
				if (udp_size > 0)
				{
					printData(udp_size, data);
				}
			}
		}
		else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6)
		{

			const ip_header *ip = (ip_header *)(packet + packetIndex);
			packetIndex += sizeof(ip_header);

			printf("Type: ipv6\n");

			printf("IP SRC");
			printIp(ip->ip_src);
			printf("IP DST");
			printIp(ip->ip_dst);
		}
		else if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
		{
			const arp_header *arp = (arp_header *)(packet + packetIndex);
			printf("Type: ARP\n");

			printf("ARP SENDER IP");
			printIp(arp->ip_send);
			printf("ARP TARGET IP");
			printIp(arp->ip_targ);
			printf("ARP SENDER MAC");
			printMac(arp->arp_send);
			printf("ARP TARGET MAC");
			printMac(arp->arp_targ);
		}
	}
	pcap_close(handle);
	return 0;
}
