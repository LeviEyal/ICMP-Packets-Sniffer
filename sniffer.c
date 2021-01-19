/****************************************************************************
* Eyal Levi ID.203249073
* Assignment number 4
* ICMP packets sniffer
****************************************************************************/

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

int count=0;
void got_packet(unsigned char* , int );

int main(int argc, char *argv[]) {

    printf("\n-----------------------------------------------------------\n");
    printf("                 Sniffing ICMP packets...\n");
    printf("-----------------------------------------------------------\n");

    /*--------------------------------------------------------------------------------
        1)   ******************** Create the raw socket ********************
    --------------------------------------------------------------------------------*/
    // -> htons(ETH_P_ALL): Capture all types of packets:
    int raw_socket;
    if ((raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("listener: socket");
        return -1;
    }

    /*--------------------------------------------------------------------------------
        2)  ***************** Turn on the promiscuous mode *****************
    --------------------------------------------------------------------------------*/
    struct packet_mreq mr;
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    /*--------------------------------------------------------------------------------
        3)  ********************* Get captured packet *********************
    --------------------------------------------------------------------------------*/
    char buffer[IP_MAXPACKET];
    while(1) {
        bzero(buffer, IP_MAXPACKET);
        int received = recvfrom(raw_socket, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
        got_packet(buffer, received);
    }
}

void got_packet(unsigned char* buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)(buffer+ETH_HLEN);
    /* If the captured packet is ICMP then: */
    if (iph->protocol == IPPROTO_ICMP) {

        unsigned short iphdrlen = iph->ihl*4;
        struct icmphdr *icmph = (struct icmphdr *)(buffer+ETH_HLEN+iphdrlen);

        char *icmp_type_names[] = {"Echo (ping) Reply","Unassigned","Unassigned","Destination Unreachable",
                                    "Source Quench","Redirect","Alternate Host Address","Unassigned",
                                    "Echo (ping)","Router Advertisement","Router Selection","Time Exceeded"};

        unsigned int type = (unsigned int)(icmph->type);
        if(type < 11)
        {
            struct sockaddr_in source, dest;
            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = iph->saddr;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = iph->daddr;

            printf("-------------------- ICMP Packet No. %d --------------------\n",++count);
            printf("\nIP Header:\n");
            printf("\tSource IP        : %s\n",inet_ntoa(source.sin_addr));
            printf("\tDestination IP   : %s\n",inet_ntoa(dest.sin_addr));
            printf("\nICMP Header:\n");
            printf("\tType             : %d - %s\n", (unsigned int)(icmph->type), icmp_type_names[type]);
            printf("\tCode             : %d\n", (unsigned int)(icmph->code));
        }
    }
}