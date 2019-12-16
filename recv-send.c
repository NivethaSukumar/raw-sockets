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
#define DEFAULT_IF   "wlp1s0"
//68:07:15:35:0D:04
#define DESTMAC0 0x68
#define DESTMAC1 0x07
#define DESTMAC2 0x15
#define DESTMAC3 0x35
#define DESTMAC4 0x0d
#define DESTMAC5 0x04

int main() {

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
	
	struct sockaddr saddr;
	struct sockaddr_ll sadr_ll;
	int saddr_len = sizeof(saddr);
	
	strcpy(ifName, DEFAULT_IF);
	
	
	if(sock < 0) {
		printf("Failed to create socket");
		exit(1);
	}
	
	if(send_soc < 0) {
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

	/* Bind our socket to this interface*/
	sadr_ll.sll_family = AF_PACKET;
	sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
	sadr_ll.sll_protocol = htons(ETH_P_ALL);

	if((bind(send_soc, (struct sockaddr*)&sadr_ll, sizeof(sadr_ll))) == -1) {
		printf("Error binding raw socket to interface\n");
		close(send_soc);
		exit(-1);
	}
	
	/*Get the mac address of the interface*/
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	
	if((ioctl(send_soc, SIOCGIFHWADDR, (void*)&if_mac)) <0){
		
		printf("Error in SIOCGIFHWADDR ioctl reading %s\n", strerror(errno));
		close(send_soc);
		exit(EXIT_FAILURE);
	}

		
	/*Get the ip address of the interface"
	memset(&ifreq_ip, 0, sizeof(struct ifreq));
	strncpy(ifreq_ip.ifr_name, ifName, IFNAMSIZ-1);
	
	if((ioctl(send_soc, SIOCGIFADDR, &ifreq_ip)) <0)
		printf("error in SIOCGIFADDR ip address reading\n");*/
	
	repeat: packet_size = recvfrom(sock, buffer, 65536, 0, &saddr, (socklen_t*)&saddr_len);
		if(packet_size == -1) {
			printf("Failed to get packets\n");
			close(sock);
			return 1;
		} else {
			printf("Received packets\n");
		}
		
		struct iphdr *ip_packet = (struct iphdr*)buffer;
		memset(&src_socket_address, 0, sizeof(src_socket_address));
		src_socket_address.sin_addr.s_addr = ip_packet->saddr;
		memset(&dest_socket_address, 0, sizeof(dest_socket_address));
		dest_socket_address.sin_addr.s_addr = ip_packet->daddr;
		
		 sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;
		 sadr_ll.sll_halen = ETH_ALEN;
		 
		 sadr_ll.sll_addr[0] = DESTMAC0;
		 sadr_ll.sll_addr[1] = DESTMAC1;
		 sadr_ll.sll_addr[2] = DESTMAC2;
		 sadr_ll.sll_addr[3] = DESTMAC3;
		 sadr_ll.sll_addr[4] = DESTMAC4;
		 sadr_ll.sll_addr[5] = DESTMAC5;
		 
		 /* Send Packet */
		 
		 int send_len = sendto(send_soc, buffer, packet_size, 0, (struct sockaddr*)&sadr_ll, sizeof(struct sockaddr_ll));
		 
		 if(send_len < 0) {
		 	printf("Sending packet failed %d %s\n", send_len, strerror(errno));
		 	goto done;
		 } else {
		 	printf("Sending packet successful\n");
		 }
		
		printf("Yes, Incoming packet: \n");
		printf("Packet size (bytes): %d\n", packet_size);
		printf("Source address: %s\n", (char*)inet_ntoa(src_socket_address.sin_addr));
		printf("destination address: %s\n", (char*)inet_ntoa(dest_socket_address.sin_addr));
		printf("Identification: %d\n", ntohs(ip_packet->id));
		printf("================================================\n");
done:  goto repeat;
		close(send_soc);
		return 0;
}
