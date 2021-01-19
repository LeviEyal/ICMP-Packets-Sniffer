/****************************************************************************
* Eyal Levi ID.203249073
* Assignment number 4
* Simple program sending ping request and recieving ping echo
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8 
#define DESTINATION_IP "172.217.22.78"
#define DATA "This is the ping.\n"
#define DATA_LEN 19

unsigned short calculate_checksum(unsigned short * paddress, int len);

int main ()
{
    /*--------------------------------------------------------------------------------
            ****************** Cooking the ICMP header: *********************
    --------------------------------------------------------------------------------*/
    
    struct icmp icmphdr; // ICMP-header
    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;
    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;
    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18;
    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;
    // Combine the packet 
    char packet[IP_MAXPACKET];
    // First, IP header.
    // memcpy (packet, &iphdr, IP4_HDRLEN);
    // Next, ICMP header
    memcpy (packet, &icmphdr, ICMP_HDRLEN);
    // After ICMP header, add the ICMP data.
    memcpy ((packet+ICMP_HDRLEN), DATA, DATA_LEN);
    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)packet, (ICMP_HDRLEN+DATA_LEN));
    memcpy (packet, &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    // dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
    dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

    // Create raw socket
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    /*--------------------------------------------------------------------------------
            ************ Send the ICMP ECHO REQUEST packet: ***************
    --------------------------------------------------------------------------------*/

    struct timeval start, end;
    gettimeofday(&start, NULL);

    // Send the packet using sendto() for sending Datagrams.
    int sent_size  = sendto(sock, packet, (ICMP_HDRLEN+DATA_LEN), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
    if (sent_size == -1) {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("Sent one packet:\n");
    printf("\tSize: %d bytes: ICMP header(%d) + data(%d)\n", sent_size, ICMP_HDRLEN, DATA_LEN);
    printf("\tData: %s \n", packet+ICMP_HDRLEN);

    /*--------------------------------------------------------------------------------
            ************ Receive the ICMP ECHO REPLY packet: ***************
    --------------------------------------------------------------------------------*/

    bzero(packet,IP_MAXPACKET);
    socklen_t len = sizeof(dest_in);
    int get_size = -1;
    while (get_size < 0) {
        get_size = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *) &dest_in, &len);
    }
    printf("Recieved one packet:\n");
    printf("\tSize: %d bytes: IP header(%d) + ICMP header(%d) + data(%d)\n", get_size, IP4_HDRLEN, ICMP_HDRLEN, DATA_LEN);
    gettimeofday(&end, NULL);

    printf("\tData: %s \n", (packet+ICMP_HDRLEN+IP4_HDRLEN));

    // second > milliseconds (10^(-3) seconds) > microseconds (10^(-6) seconds)
    float milliseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
    unsigned long microseconds = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec);
    printf("Round-trip time (RTT): %f (milliseconds), %ld (microseconds)\n", milliseconds, microseconds);

    // Close the raw socket
    close(sock);
    return 0;
}


/*--------------------------------------------------------------------------------
            ************ Compute checksum (RFC 1071): ***************
--------------------------------------------------------------------------------*/
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

