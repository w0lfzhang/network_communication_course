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
#include <netinet/udp.h>
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
void pack_icmp(void *buf, int sequence);
struct in_addr get_local_ip(); 
int scan_tcp_ports(struct in_addr ip);
int scan_udp_ports(struct in_addr ip);
int discover_hosts();
struct in_addr alive_ips[255];

int main(int argc, char const *argv[])
{
    struct in_addr ip;
    char *test_ip1 = "192.168.109.245";
    inet_aton(test_ip1, &ip);

    scan_udp_ports(ip);
    //discover_hosts();
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

void pack_icmp(void *buf, int sequence)  
{   
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

    #ifdef DEBUG
      printf("[+] local network address: %s\n", inet_ntoa(ip));
    #endif

    close(sock);
    return ip;
}

/*
* return the count of hosts alive
*/
int discover_hosts()
{
    memset(alive_ips, 0, 255 * sizeof(struct in_addr));
    struct in_addr local_net_ip, ip_addr; //big endian
    unsigned int local_host_ip;  //little endian
    int count = 0;  //the count of hosts alive
    int sockfd;

    local_net_ip = get_local_ip();
    local_host_ip = ntohl(local_net_ip.s_addr);
    /*
    * we just use three bytes 
    * shift right 8bit
    * then shift legt 8bit
    */
    local_host_ip = local_host_ip >> 8;
    local_host_ip = local_host_ip << 8;

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    
    //recveiving and send buffer
    char *send_buf = (char *)malloc(0x100);
    char *recv_buf = (char *)malloc(0x200);
    
    struct protoent *proto = NULL;
	proto = getprotobyname("icmp");
	sockfd = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if( sockfd < 0 )
	{
		perror("[-] raw sockset failed");
		exit(0);
    }

    int size = 50 * 1024, on = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    int i, j, errno;
    for(i = 1; i < 255; i++)
    {
        ip_addr.s_addr = htonl(local_host_ip + i);
        dest_addr.sin_addr.s_addr = ip_addr.s_addr;

        /*
        * just send one packet is not working
        * packets may be lossed
        */
        for(j = 0; j < 4; j ++)
        {
            struct timeval time;
            printf("[+] Scan host %s (%d)\r", inet_ntoa(dest_addr.sin_addr), j + 1);
            fflush(stdout);

            pack_icmp(send_buf, i);

            errno = sendto(sockfd, send_buf, 64, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (errno < 0)
            {
                perror("[-] sendto error");
                exit(0);
            }

            time.tv_sec = 0;
            time.tv_usec = 200 * 1000;

            while ( 1 )
            {
                fd_set set;
                struct ip *ip;
                int iphdr_len;

                FD_ZERO(&set);
                FD_SET(sockfd, &set);
                errno = select(sockfd + 1, &set, NULL, NULL, &time);
                if( errno <= 0 )
                {
                    break;
                }

                if( recvfrom(sockfd, recv_buf, 0x200, 0, NULL, NULL) < 0 )
                {
                    perror("[-] recvfrom error");
                    exit(0);
                }

                ip = (struct ip *)recv_buf;
                iphdr_len = ip->ip_hl << 2;
                if ( ip->ip_src.s_addr == dest_addr.sin_addr.s_addr )
                {
                    struct icmp *icmp;
                    icmp = (struct icmp *)(recv_buf + iphdr_len);
                    if( icmp->icmp_type == ICMP_ECHOREPLY &&
                        icmp->icmp_id == getpid() )
                    {
                        printf("[+] host %s is alive:\t", inet_ntoa(ip_addr));
                        memcpy(&alive_ips[count], &ip_addr, sizeof(ip_addr));
                        count += 1;

                        //getting its host information
                        struct hostent *host = gethostbyaddr(&ip_addr, sizeof(ip_addr), AF_INET);
                        printf("host name: %s\n", host->h_name);
                        break;
                    }
                }
            }
        break;
        }
    }

    free(send_buf);
    free(recv_buf);
    send_buf = NULL;
    recv_buf = NULL;
    close(sockfd);
    return count;
}

/*
* scan the host's tcp ports
*/
int scan_tcp_ports(struct in_addr ip)
{
    int sockfd;
    int ret, count = 0;
    
    struct sockaddr_in scan_addr;
    struct servent *server;
    int start_port = 1, end_port = 65535, temp_port;
    scan_addr.sin_family = AF_INET;
    memcpy(&(scan_addr.sin_addr), &ip, sizeof(ip));

    /*
    * scanning tcp ports
    */
    for( temp_port = start_port; temp_port <= end_port; temp_port++)
    {
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        scan_addr.sin_port = htons(temp_port);

        ret = connect(sockfd, (struct sockaddr *)&scan_addr, sizeof(scan_addr));
        if( ret == 0 )
        {
            server = getservbyport( htons(temp_port), "tcp");
            printf("[+] opened tcp port: %d/%s\n", temp_port, (server == NULL) ? "unknow" : server->s_name);
            count += 1;
        }
    }

    close(sockfd);
    return count;
}


/*
* scan the host's udp ports
*/
int scan_udp_ports(struct in_addr ip)
{
    int send_fd, recv_fd;
    int count = 0;

    send_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(  send_fd < 0 )
    {
        perror("[-] socket udp failed");
        exit(0);
    }

    recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if( recv_fd < 0 )
    {
        perror("[-] socket raw failed");
        exit(0);
    }

    struct sockaddr_in send_addr;
    char *recv_buf = (char *)malloc(0x100);
    char *send_buf = (char *)malloc(0x10);
    memset(send_buf, 0x41, 0x10);

    memset(&send_addr, 0, sizeof(send_addr));
    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = ip.s_addr;

    int port;
    for( port = 1; port < 65535; port++ )
    {
        send_addr.sin_port = htons(port);
        int errno;
        errno = sendto(send_fd, NULL, 0, 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
        if( errno < 0 )
        {
            perror("[-] sendto failed");
            exit(0);
        }

        struct timeval time = {1, 0};
        while( 1 )
        {
            fd_set set;
            FD_ZERO(&set);
            FD_SET(recv_fd, &set);

            errno = select(recv_fd + 1, &set, NULL, NULL, &time);
            if( errno > 0 )
            {
                /*
                * 服务器reply一个类型为端口不可达的ICMP，
                * ICMP数据部分就是UDP请求's ip层及其以上的数据。
                */
                struct icmp *icmp;
                struct ip *ip;  //receiving ip data
                struct ip *data_ip;  //icmp's data
                int iphdr_len;
                int data_iphdr_len;
                struct udphdr *udp;

                /*
                *first the packet must greater than 56
                */
                if( recvfrom(recv_fd, recv_buf, 0x200, 0, NULL, NULL) < 56 )
                {
                    continue;
                }

                ip = (struct ip *)recv_buf;
                iphdr_len = ip->ip_hl << 2;
                icmp = (struct icmp *)(recv_buf + iphdr_len);
                data_ip = (struct ip *)icmp->icmp_data;
                data_iphdr_len = data_ip->ip_hl << 2;
                udp = (struct udphdr *)((char *)data_ip + data_iphdr_len);

                if( ip->ip_src.s_addr == send_addr.sin_addr.s_addr &&
                    icmp->icmp_type == ICMP_UNREACH &&
                    icmp->icmp_code == ICMP_UNREACH_PORT &&
                    data_ip->ip_p == IPPROTO_UDP &&
                    udp->dest == send_addr.sin_port )
                {
                    break;
                }
            }
            //select() <=0
            else
            {
                count +=1;
                struct servent *server;
                server = getservbyport(htons(port), "udp");
                printf("[+] opened udp ports: %d/%s\n", port, (server == NULL) ? "unknow" : server->s_name);
                break;
            }
            

        }//end while
    }//end for

    close(send_fd);
    close(recv_fd);
    free(recv_buf);
    recv_buf = 0;
    return count;
}