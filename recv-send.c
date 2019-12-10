#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/ioctl.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#define BUF_SIZE   1024
#define DEFAULT_IF   "eth0"

#define DESTMAC0 0xc8
#define DESTMAC1 0x5b
#define DESTMAC2 0x76
#define DESTMAC3 0xd2
#define DESTMAC4 0x7a
#define DESTMAC5 0x67

int main(int argc, char *argv[]) {

	struct sockaddr_in src_socket_address, dest_socket_address;
	struct ifreq ifreq_i;
	struct ifreq if_mac;
	struct ifreq ifreq_ip;
	int packet_size;
	char ifName[IFNAMSIZ];
	char sendbuf[BUF_SIZE];
	
	int tx_len = 0;
	unsigned char *buffer = (unsigned char*)malloc(65536);
	
	int sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	
	int send_soc = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	
	struct ethhdr *eth = (struct ethhdr*)sendbuf;
	struct sockaddr saddr;
	struct sockaddr_ll sadr_ll;
	int saddr_len = sizeof(saddr);
	/*Get interface name*/
	
	if(argc < 1) {
		strcpy(ifName, argv[1]);
	} else {
		strcpy(ifName, DEFAULT_IF);
	}
	
	
	if(sock < 0) {
		printf("Failed to create socket");
		exit(1);
	}
	
	if(send_soc < -1) {
		printf("Failed to create socket send");
		exit(1);
	}

	/* Get the index of the interface to send on */
	memset(&ifreq_i, 0, sizeof(struct ifreq));
	strncpy(ifreq_i.ifr_name, ifName, IFNAMSIZ-1);
	
	if((ioctl(send_soc, SIOCGIFINDEX, (void*)&ifreq_i)) < 0){
		printf("Error in index ioctl reading %s\n", strerror(errno));
		close(send_soc);
		exit(EXIT_FAILURE);	

	}
	
	/*Get the mac address of the interface*/
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	
	if((ioctl(send_soc, SIOCGIFHWADDR, &if_mac)) <0){
		
		printf("Error in SIOCGIFHWADDR ioctl reading %s\n", strerror(errno));
		close(send_soc);
		exit(EXIT_FAILURE);
	}

		
	/*Get the ip address of the interface"
	memset(&ifreq_ip, 0, sizeof(struct ifreq));
	strncpy(ifreq_ip.ifr_name, ifName, IFNAMSIZ-1);
	
	if((ioctl(send_soc, SIOCGIFADDR, &ifreq_ip)) <0)
		printf("error in SIOCGIFADDR ip address reading\n");*/
	
	while (1) {
		packet_size = recvfrom(sock, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_len);
		if(packet_size == -1) {
			printf("Failed to get packets\n");
			return 1;
		} else {
			printf("Received packets");
		}
		
		// struct iphdr *ip_packet = (struct iphdr*)buffer;
		// memset(&src_socket_address, 0, sizeof(src_socket_address));
		// src_socket_address.sin_addr.s_addr = ip_packet->saddr;
		// memset(&dest_socket_address, 0, sizeof(dest_socket_address));
		// dest_socket_address.sin_addr.s_addr = ip_packet->daddr;
		
		
		
		
		
		memset(sendbuf, 0, BUF_SIZE);
		
		/*Construct ethernet header*/
		
		eth->h_source[0] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[0]);
		eth->h_source[1] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[1]);
		eth->h_source[2] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[2]);
		eth->h_source[3] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[3]);
		eth->h_source[4] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[4]);
		eth->h_source[5] = (unsigned char)(if_mac.ifr_hwaddr.sa_data[5]);
		
		/*filling destination mac address*/
		 eth->h_dest[0] = DESTMAC0;
		 eth->h_dest[1] = DESTMAC1;
		 eth->h_dest[2] = DESTMAC2;
		 eth->h_dest[3] = DESTMAC3;
		 eth->h_dest[4] = DESTMAC4;
		 eth->h_dest[5] = DESTMAC5;
		 
		 eth->h_proto = htons(ETH_P_IP);
		 
		 /* end of ethernet header*/
		 tx_len += sizeof(struct ethhdr);
		 
		 /*Packet data for dummy data*/
		 sendbuf[tx_len++] = 0xAA;
		 sendbuf[tx_len++] = 0xBB;
		 sendbuf[tx_len++] = 0xCC;
		 sendbuf[tx_len++] = 0xDD;
		 sendbuf[tx_len++] = 0xEE;
		 
		 sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
		 sadr_ll.sll_halen = ETH_ALEN;
		 
		 sadr_ll.sll_addr[0] = DESTMAC0;
		 sadr_ll.sll_addr[1] = DESTMAC1;
		 sadr_ll.sll_addr[2] = DESTMAC2;
		 sadr_ll.sll_addr[3] = DESTMAC3;
		 sadr_ll.sll_addr[4] = DESTMAC4;
		 sadr_ll.sll_addr[5] = DESTMAC5;
		 
		 /* Send Packet */
		 
		 if (sendto(send_soc, buffer, packet_size, 0, (const struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll)) < 0) {
		 	printf("Sending packet failed\n");
		 	close(send_soc);
		 } else {
		 	printf("Sending packet successful");
		 }
		 	

		
		// printf("Yes, Incoming packet: \n");
		// printf("Packet size (bytes): %d\n", ntohs(ip_packet->tot_len));
		// printf("Source address: %s\n", (char*)inet_ntoa(src_socket_address.sin_addr));
		// printf("destination address: %s\n", (char*)inet_ntoa(dest_socket_address.sin_addr));
		// printf("Identification: %d\n", ntohs(ip_packet->id));
		printf("================================================\n");
	}
	close(send_soc);
	return 0;
}
		
