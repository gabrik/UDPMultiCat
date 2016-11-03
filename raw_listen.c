/*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*/

/*

	IP HEADER

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



	UDP Header

0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+


*/


#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define DEST_MAC0	0x00
#define DEST_MAC1	0x00
#define DEST_MAC2	0x00
#define DEST_MAC3	0x00
#define DEST_MAC4	0x00
#define DEST_MAC5	0x00

#define ETHER_TYPE	0x0800

#define DEFAULT_IF	"lo"
#define BUF_SIZ		1024


void clone_ip_header(struct iphdr *old_iph,struct iphdr *new_iph);


int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	char destination[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;

	struct sockaddr_storage dest_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	printf("Listening to: %s\n",ifName );



	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	printf("listener: Waiting to recvfrom...\n");


	while(1){

		numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
		printf("listener: got packet %lu bytes\n", numbytes);

		if(iph->protocol==17){
			printf("Received UDP!\n");
		

			printf("## DL: MAC Source Address is: %x:%x:%x:%x:%x:%x\n",eh->ether_shost[0],eh->ether_shost[1],eh->ether_shost[2],eh->ether_shost[3],eh->ether_shost[4],eh->ether_shost[5] );

			printf("## DL: MAC Destination Address is: %x:%x:%x:%x:%x:%x\n",eh->ether_dhost[0],eh->ether_dhost[1],eh->ether_dhost[2],eh->ether_dhost[3],eh->ether_dhost[4],eh->ether_dhost[5] );



			/* Get source IP */
			((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
			inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);
			((struct sockaddr_in *)&dest_addr)->sin_addr.s_addr = iph->daddr;
			inet_ntop(AF_INET,&((struct sockaddr_in*)&dest_addr)->sin_addr, destination, sizeof destination);


			printf("## NW: IP Source Address is: %s\n",sender);
			printf("## NW: IP Destination Address is %s\n",destination);


		

			printf("## TP: UDP Source Port: %u\n", ntohs(udph->source));


			printf("## TP: UDP Destination Port: %u\n", ntohs(udph->dest));

			/* UDP payload length */
			ret = ntohs(udph->len) - sizeof(struct udphdr);

			printf("## TP: UDP Data lenght:%d\n",ret);


			printf("## TP: UDP Data: %s\n",buf );

			struct iphdr *newiph = malloc(sizeof(struct iphdr *));
			
			clone_ip_header(iph,newiph);

			printf("New IP %d\n", newiph->protocol  );



			/* Print packet */
			/*printf("\tData:");
			for (i=0; i<numbytes; i++) printf("%02x:", buf[i]);
				printf("\n");

			}*/

		}


	}

	close(sockfd);
	return ret;
}



void clone_ip_header(struct iphdr *old_iph,struct iphdr *new_iph){
	printf("Cloning IP Header...\n");
	new_iph->tos=old_iph->tos;
	new_iph->tot_len=old_iph->tot_len;
	new_iph->id=old_iph->id;
	new_iph->frag_off=old_iph->frag_off;
	new_iph->ttl=old_iph->ttl;
	new_iph->protocol=old_iph->protocol;
	new_iph->saddr=old_iph->saddr;
	// need to change destination and calculate checksum
	
	
	new_iph->daddr = inet_addr("192.168.0.111");

}