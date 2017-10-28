/*
** before running, be root to execute the command: sudo setcap cap_net_raw=eip ping
** gcc -o ping ping.c -pthread
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
#include <signal.h>

//#define DEBUG
#define DEFAULT_LENGTH 56
#define DEFAULT_COUNT 4
#define BUF_LEN 1024
#define ICMP_HDRSIZE sizeof(struct icmphdr)
/*
** save the length and count of the ping packets
*/
struct send_args
{
	size_t length;  //data length
	size_t count;   //ping count
}send_args;

/*
**parse args to save in send_args and dest_addr
*/
int parse_args(char *cmd[]);

/*
** send ping sockets to destination address
*/
void *send_packet(void *args);

/*
** receive responsed packets from destination address
*/
void *recv_packet();

/*
** print statistics information during the operation
*/

int chksum(unsigned short *buf, int size);
void pack_icmp(void *buf, int sequence, int datalen);
int unpack_icmp(void *buf, int len);
void statistics();

struct in_addr ipv4_addr;
char *addr;  //the ping target
struct send_args send_arg;
int sockfd;
struct sockaddr_in dest_addr;
struct sockaddr_in recv_addr;
struct timeval recv_time;
int nsend_pkt = 0, nrecv_pkt = 0;
struct timeval start_time, end_time;

int main(int argc, char *argv[])
{
	//printf("%ld %ld\n", ICMP_HSIZE, sizeof(struct icmp));
	if( argc < 2 )
	{
		printf("[-] usage: ./ping dest_addr -l length -n count\n");
		exit(0);
	}
	parse_args(argv);

	struct protoent *proto = NULL;
	proto = getprotobyname("icmp");
	sockfd = socket(AF_INET, SOCK_RAW, proto->p_proto);
	if( sockfd < 0 )
	{
		perror("[-] sockset failed");
		exit(0);
	}

	/*
	**Set the maximum socket receive buffer in bytes
	**Set the time-to-live value of outgoing multicast packets for this socket
	**Set the current time-to-live field that is used in every packet sent from this socket
	*/
	int size = 32 * 1024;   
    int ttl = 64; 
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));  
    setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));  
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

	memset(&dest_addr, 0, sizeof(struct sockaddr_in));
	memset(&recv_addr, 0, sizeof(struct sockaddr_in));

	dest_addr.sin_family = AF_INET;
	//recv_addr.sin_family = AF_INET;
	memcpy(&(dest_addr.sin_addr), &ipv4_addr, sizeof(struct in_addr)); 

	/*
	** create two threads to send and receive data
	*/
	printf("ping %s (%s) with %ld bytes of data\n", addr, inet_ntoa(ipv4_addr), send_arg.length);
	signal(SIGINT, statistics);
	pthread_t pid[2] = {0, 0};
	pthread_create(&pid[0], NULL, send_packet, (void *)&send_arg);
	pthread_create(&pid[1], NULL, recv_packet, NULL);

	pthread_join(pid[0], NULL);
	pthread_join(pid[1], NULL);

	statistics();

	return 0;
}

int parse_args(char *cmd[])
{
	int errno = 0; //return status
	int i, j;
	/*
	* allocate memory for the out-of-args
	*/
	for(i = 0; i < 7; i++)
	{
		if( cmd[i] == NULL )
		{
			//printf("%d\n", i);
			for(; i < 7; i++)
			{
				cmd[i] = (char *)malloc(10);
			}
		}
	}
	//the default value of length and count
	send_arg.length = DEFAULT_LENGTH;
	send_arg.count = DEFAULT_COUNT;

	for(i = 1; i < 6; i++) //skip the first argument: ./ping
	{
		if ( !strcmp(cmd[i], "-l") )
		{
			long int length = strtol(cmd[i+1], NULL, 10);
			if( length <= 0 || length > 255)
			{
				puts("[-] length can't be negative or greater than 255!");
				return -1;
			}
			/*
			long int => size_t, correct?
			*/
			#ifdef DEBUG
			  printf("[DEBUG] packet length: %ld\n", length);
			#endif
			send_arg.length = length;
		}

		if ( !strcmp(cmd[i], "-n") )
		{
			long int count = strtol(cmd[i+1], NULL, 10);
			if( count < 0 )
			{
				puts("[-] count must be opposite!");
				return -1;
			}
			//the same problem with above
			#ifdef DEBUG
			  printf("[DEBUG] packet count: %ld\n", count);
			#endif
			send_arg.count = count;
		}

		//address if there is '.' in the string 
		if( strstr(cmd[i], ".") != NULL )
		{
			#ifdef DEBUG
			  printf("[DEBUG] ping address: %s\n", cmd[i]);
			#endif
			addr = cmd[i];
		}
	}
	
	//parse dest_addr: domain name or ip address ==> in_addr
	struct hostent *host = NULL;
	errno = inet_aton(addr, &ipv4_addr);
	if( errno == 0 )
	{
		host = gethostbyname(addr);
		if( host == NULL )
		{
			puts("[-] invalid destination address");
			return -1;
		}
		memcpy(&(ipv4_addr.s_addr), host->h_addr, sizeof(struct in_addr));
	}

	#ifdef DEBUG
	  printf("[DEBUG] ipv4 address: %s\n", inet_ntoa(ipv4_addr));
	#endif

	// free the out-of-args
	for(i = 0; i < 7; i++)
	{
		if( cmd[i] == NULL )
		{
			for(; i < 7; i++)
			{
				free(cmd[i+1]);
			}
		}
	}

	return 0;
}

/*
1、将检验和字段置为0
2、把需校验的数据看成以16位为单位的数字组成，依次进行求和，并存到32位的整型中
3、把求和结果中的高16位(进位)加到低16位上，如果还有进位，重复第3步[实际上，这一步最多会执行2次]
4、将这个32位的整型按位取反，并强制转换为16位整型(截断)后返回
*/
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

/*
* @buf: icmp packet buffer
* @sequence: the icmp packet sequence
* @datalen: the length of icmp packet's data, not including the icmp header
*/
void pack_icmp(void *buf, int sequence, int datalen)  
{  
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

    icmp_hdr->icmp_cksum = chksum((unsigned short *)icmp_hdr, ICMP_HDRSIZE + datalen);    
} 

void *send_packet(void *args)
{
	int i;
	int length, errno;
	void *buf = malloc(BUF_LEN);
	memset(buf, 0, BUF_LEN);

	struct send_args *temp_arg = (struct send_args *)args;
	length = ICMP_HDRSIZE + temp_arg->length;

	gettimeofday(&start_time, NULL);

	for(i = 0; i < temp_arg->count; i++)
	{
		pack_icmp(buf, i + 1, temp_arg->length);
		#ifdef DEBUG
		  printf("[DEBUG] sending packet %d\n", i + 1);
		#endif
		sendto(sockfd, buf, length, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		if( errno == -1 )
		{
			printf("[-] send failed!\n");
			sleep(1);
			continue;
		}
		nsend_pkt += 1;
		sleep(1);
	}

	free(buf);
	buf = NULL;

	return NULL;
}

/*
* @buf: ip packet buffer
* @len: ip packet length
* note: target host will reply the same icmp packet to the source host
* when receiving a icmp packet. 
*/
int unpack_icmp(void *buf, int len)
{
	/*
	**note: using struct ip, not iphdr
	*/
	struct ip *ip_hdr = (struct ip *)buf;
	int iphdr_len; 
	double rtt; //round trip time
	struct timeval *send_time;

	iphdr_len = ip_hdr->ip_hl * 4;
	struct icmp *icmp_hdr = (struct icmp *)(buf + iphdr_len);

	len -= iphdr_len;
	if (len < ICMP_HDRSIZE)
	{
		printf("[-] invalid icmp packet! Size is less than 8 byte\n");
		return -1;
	}

	//icmp packet we send?
	if( icmp_hdr->icmp_type == ICMP_ECHOREPLY && 
		icmp_hdr->icmp_id == getpid() )
	{

		send_time = (struct timeval *)icmp_hdr->icmp_data;
		rtt = ((&recv_time)->tv_sec - send_time->tv_sec) * 1000 + 
		((&recv_time)->tv_usec - send_time->tv_usec)/(double)1000.0;
		printf("%d byte from %s: icmp_seq = %u ttl = %d rtt = %.3f ms\n", 
			len, inet_ntoa(ip_hdr->ip_src), icmp_hdr->icmp_seq, 
			ip_hdr->ip_ttl, rtt);
	}
	else
	{
		printf("[-] invalid icmp packet! Not matched.\n");
		return -1;
	}

	return 0;
}

void *recv_packet()
{
	int size, errno;
	socklen_t addrlen = sizeof(recv_addr);
	char *buf = (char *)malloc(BUF_LEN);
	memset(buf, 0, BUF_LEN);
	//sleep(1);

	while( 1 )
	{
		#ifdef DEBUG
		  printf("[DEBUG] receiving packet %d\n", nrecv_pkt + 1);
		#endif
		size = recvfrom(sockfd, buf, BUF_LEN, 0, (struct sockaddr *)&recv_addr, &addrlen);
		//puts("recving...");
		if( size < 0 )
		{
			printf("[-] Lost the packet\n");
			continue;
		}
		gettimeofday(&recv_time, NULL);
		errno = unpack_icmp(buf, size);
		if( errno == -1 )
		{
			printf("[-] unpack icmp failed.\n");
			continue;
		}

		nrecv_pkt += 1;
		if (nrecv_pkt == send_arg.count)
		{
			break;
		}
	}

	free(buf);
	buf = NULL;

	return NULL;
}

void statistics()  
{  
	gettimeofday(&end_time, NULL);

	long time;
	struct timeval off_time;
	off_time.tv_sec = end_time.tv_sec - start_time.tv_sec;
	off_time.tv_usec = end_time.tv_usec - start_time.tv_usec;
	

	time = off_time.tv_sec * 1000 + off_time.tv_usec / 1000;

    printf("\n--- %s ping statistics ---\n", inet_ntoa(dest_addr.sin_addr));  
    printf("%d packets transmitted, %d received, %.3f%c packet loss, time %ldms\n",  
           nsend_pkt, nrecv_pkt, (float)100*(nsend_pkt - nrecv_pkt)/nsend_pkt, '%', time);

    close(sockfd);  
  
    exit(0);  
}  
