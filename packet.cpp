#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"

void printMac(const uint8_t *_mac){
	printf(": %02X:%02X:%02X:%02X:%02X:%02X\n", _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5] );
}

void printIp(ip_addr ip){
	printf(": %d.%d.%d.%d\n", ip.a, ip.b, ip.c, ip.d);
}

void printData(uint32_t size, const u_char *data){
		    printf("=================================================\n");
		    int i = 0;
		    for(i;i<size;i++){
			printf("%02X ",data[i]);
			if((i + 1) % 8 == 0 && (i + 1) % 16 != 0)
			    printf("  ");
			if((i + 1) % 16 == 0)
			    printf("\n");
		    }
		    printf("\n=================================================\n");
}
