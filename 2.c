#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>

#define MAXPACKET 4096
#define DEFAULT_TIMEOUT 10
#define DEFAULT_RESEND 6

void start_scanning(const char *ipaddress, unsigned short port)
{
    unsigned int timeout = 4, maxretry = 3;
    struct sockaddr_in myudp;
    int udpsock, rawsock, retry, retval, iplen;
    fd_set r;
    struct timeval mytimeout;
    struct icmp *packet;
    struct ip *iphdr;
    struct servent *service;
    unsigned char recvbuff[4096];

    if ((udpsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("socket()");
        exit(-1);
    }

    if ((rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket()");
        exit(-1);
    }
    mytimeout.tv_sec = 1;
    mytimeout.tv_usec = 0;
    retry = 0;

    myudp.sin_addr.s_addr = inet_addr(ipaddress);
    myudp.sin_family = AF_INET;
    myudp.sin_port = htons(port);

    while (retry++ < maxretry)
    {
        FD_ZERO(&r);
        FD_SET(rawsock, &r);
        if ((sendto(udpsock, "  ", 2, 0, (struct sockaddr *)&myudp, sizeof(myudp))) < 0)
        {
            perror("sendto");
            exit(-1);
        }
        retval = select((rawsock + 1), &r, NULL, NULL, &mytimeout);
        if (retval == 1)
        { //some data reach
            if ((recvfrom(rawsock, recvbuff, sizeof(recvbuff), 0x0, NULL, NULL)) < 0)
            {
                perror("Recv");
                exit(-1);
            }
            iphdr = (struct ip *)recvbuff;
            iplen = iphdr->ip_hl * 4;
            packet = (struct icmp *)(recvbuff + iplen);
            //printf("the icmp type is=%d, code=%d \n", packet->icmp_type, packet->icmp_code);
            if ((packet->icmp_type == ICMP_UNREACH) && (packet->icmp_code == ICMP_UNREACH_PORT))
                break;
        } //end if(retval ==1)
        else if (retval == 0)
        {
            //printf("time out! the port may be availed !\n");
            continue;
        }
        else
        {
            printf("occur some errors! scan udp failed !\n");
            return;
        }
    } //end while(1)

    if (retry >= maxretry)
    {
        if ((service = getservbyport(htons(port), "udp")) == NULL)
            fprintf(stdout, "Unknown port %u, open.\n", port);
        else
            fprintf(stdout, "UDP service %s open.\n", service->s_name);
        fflush(stdout);
    }
    else
    {
        printf("the port:%d is unavailable!\n", port);
    }
    close(udpsock);
    close(rawsock);
}

int main(int argc, char **argv)
{
    int i;
    for( i = 1; i < 65535; i++)
    {
        start_scanning("192.168.109.141", 40);
    }
    printf("scan over\n");
    return 0;
}