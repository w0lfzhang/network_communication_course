/*
* the program mainly does two things:
* 1. discovering the hosts which are alive and then print the ip address 
* and it's name
* 2. discovering the opened ports in the above hosts
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <sys/select.h>
#include <fcntl.h>


#define DEBUG
/*
* can pass the network interface's name by argv
* test on ubuntu 16.04
*/
#define ETH_NAME	"ens33"

int chksum(unsigned short *buf, int size);
void pack_icmp(void *buf);
struct in_addr get_local_ip();
int test_alive(struct in_addr ip);  
int scan_ports(struct in_addr ip);
struct in_addr alive_ips[255];


int main(int argc, char const *argv[])
{
    char *test_ip = "192.168.109.137";
    char *test_ip1 = "192.168.109.138";
    char *test_ip2 = "192.168.109.13";
    struct in_addr ip;
    inet_aton(test_ip, &ip);
    test_alive(ip);
    inet_aton(test_ip1, &ip);
    test_alive(ip);
    inet_aton(test_ip2, &ip);
    test_alive(ip);
	return 0;
}

int chksum(unsigned short *buf, int size)  
{   
    unsigned long sum = 0;    
     
    while(size > 1)  
    {  
        sum += *buf++;  
        size -= sizeof(unsigned short);  
    }  
    if ( size == 1 )  
    {   
        sum += *(unsigned char *)buf;  
    }  
    
    sum = (sum >> 16) + (sum & 0xffff) ;
 	sum += (sum >> 16);
    return (unsigned short)(~sum);
} 

void pack_icmp(void *buf)  
{  
	int sequence = 1; 
	int datalen = 56;
	/*
	**note: using struct icmp, not icmphdr
	*/
    struct icmp *icmp_hdr = (struct icmp *)buf;  
  
    icmp_hdr->icmp_type = ICMP_ECHO; 
    icmp_hdr->icmp_code = 0; 
    icmp_hdr->icmp_cksum = 0;  
    icmp_hdr->icmp_seq = sequence;  
    icmp_hdr->icmp_id = getpid();  

    //filling the data padding 
    memset(icmp_hdr->icmp_data, 0xff, datalen);
    gettimeofday((struct timeval *)icmp_hdr->icmp_data, NULL);

    icmp_hdr->icmp_cksum = chksum((unsigned short *)icmp_hdr, 8 + datalen);    
} 

/*
* get local machine's local network's ip address
*/
struct in_addr get_local_ip()
{
	struct in_addr ip;
	int sock;
    struct sockaddr_in addr;          
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        perror("[-] tcp socket failed\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ETH_NAME, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
    	perror("[-] ioctl failed\n");
    	exit(0);
    }

    memcpy(&addr, &ifr.ifr_addr, sizeof(addr));
    memcpy(&ip, &(addr.sin_addr), sizeof(struct in_addr));

    printf("[+] local network address: %s\n", inet_ntoa(ip));
    close(sock);
    return ip;
}

/*
* test if the host is alive
* if not alive, return 0
* if alive, return 1
*/
int test_alive(struct in_addr ip)
{
    int i, count;
    int errono;
    int size = 50 * 1024 ;
    int sockfd;

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    memcpy(&(dest_addr.sin_addr), &ip, sizeof(ip));

    char *send_buf = (char *)malloc(0x100);

	struct protoent *proto = NULL;
	proto = getprotobyname("icmp");
	sockfd = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if( sockfd < 0 )
	{
		perror("[-] raw sockset failed");
		exit(0);
    }
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    printf("[+] ping target: %s\n", inet_ntoa(dest_addr.sin_addr));
    pack_icmp(send_buf);
    errno = sendto(sockfd, send_buf, 64, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if( errno < 0 )
    {
        perror("[-] sendto failed");
        exit(0);
    }

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    struct timeval time = {1, 0};
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sockfd, &set);

    int ret = select(sockfd + 1, &set, NULL, NULL, &time);

    if( ret == - 1)
    {
        perror("[-] select error");
        close(sockfd);
        free(send_buf);
        send_buf = NULL;
        return 0;
    }
    else if( ret == 0 )
    {
        printf("[-] timeout!\n");
        close(sockfd);
        free(send_buf);
        send_buf = NULL;
        return 0;
    }
    else
    {
        if( FD_ISSET(sockfd, &set) )
        {
            printf("[+] %s is alive.\n", inet_ntoa(ip));
            close(sockfd);
            free(send_buf);
            send_buf = NULL;
            return 1;
        }
    }
}

/*
* scan the host's ports
*/
int scan_ports(struct in_addr ip)
{

}
