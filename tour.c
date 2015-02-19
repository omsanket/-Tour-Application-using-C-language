#include  	"unp.h"
#include 	<netinet/ip.h>
#include 	"hw_addrs.h"
#include	<sys/socket.h>
#include 	<linux/if_ether.h>
#include 	<linux/if_arp.h>
#include	<netinet/in_systm.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include 	<arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
 #include <sys/ioctl.h>
#include <pthread.h>
#include <setjmp.h>

//#include <net/if.h>

#define MY_PROTOCOL 216
#define M_ADDR "224.124.108.27"
#define M_PORT 4093
#define MY_ID 9799
#define	BUFSIZE		1500
#define ID 52680
#define MAXLINE 5000
#define IF_HADDR 6

static sigjmp_buf 			jmpbuf;	
			/* globals */
char	 sendbuf[BUFSIZE];

int		 datalen;			/* # bytes of data following ICMP header */
char	*host;
int		 nsent;				/* add 1 for each sendto() */
pid_t	 pid;				/* our PID */
int		 sockfd;
int		 verbose;
int STOP_FLAG=0;
int max_count=0;
int visited=0;
int ping_flag=0;
int myself=0;
int End;
struct in_addr target_strt,myip_strt;
char my_ip[20],target_ip[20];
unsigned char source_mac[6];

struct proto
{
	void	 (*fproc)(char *, ssize_t, struct msghdr *, struct timeval *);
	void	 (*fsend)(void);
	void	 (*finit)(void);
	struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */
	struct sockaddr  *sarecv;	/* sockaddr{} for receiving */
	socklen_t	    salen;		/* length of sockaddr{}s */
	int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */
}*pr;

struct vm_info
{
	char name[20];
	char ip[20];
	struct vm_list *next;
}*vm_head;

struct ip_list
{
	char ipname[20];
}ip[30];


struct payload
{
	char data[450];
	char mcast_addr[20];
	int mcast_port;
	int ip_index;
	int final;
	//struct ip_list ip[30];
};

struct ethernet_packet
{
	struct iphdr ping_header;
	struct icmp details;
};

struct packet
{
	struct iphdr *head;
	char packet_pl[492];
};

struct hwaddr
{
	int             sll_ifindex;				 /* Interface number */
	unsigned short  sll_hatype;				 /* Hardware type */
	unsigned char   sll_halen;				/* Length of address */
	unsigned char   sll_addr[8];				 /* Physical layer address */
};

void sig_alrm(int signo)
{
	if(End!=1)
	{
		(*pr->fsend)();

		//alarm(1);
		return;
	}
	else exit(0);
}



void error(char *msg)
{
	fprintf(stderr,"%s:  %s\n",msg,strerror(errno));
	exit(1);
}

void error_wo_exit(char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
}

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr)
{
   	int socku, n, i;
	struct sockaddr_un apiaddr;
	char ip[20], sendline[MAXLINE],  recvline[MAXLINE],temp[14];
	fd_set rset;
	struct timeval timeout;

	if((socku = socket(AF_LOCAL, SOCK_STREAM, 0))<0)
	{
	error("Error in socket creation");
	}
	bzero(&apiaddr, sizeof(apiaddr));

	apiaddr.sun_family = AF_LOCAL;
	strcpy(apiaddr.sun_path,"/tmp/arp6820");
	if(connect(socku, (SA*) &apiaddr,sizeof(struct sockaddr_un))<0)
            error("Error in connect");
        struct sockaddr_in *addrin=(struct sockaddr_in*)IPaddr;
	strncpy(temp,IPaddr->sa_data,14);

	strcpy(ip,inet_ntoa(addrin->sin_addr));
	
	sprintf(sendline,"%s|%d|%hu|%u\n", temp, HWaddr->sll_ifindex, HWaddr->sll_hatype, HWaddr->sll_halen);
	if (write(socku, sendline, sizeof(sendline))<0)
	error("Error in write");
	printf("\nMessage sent to ARP unix domain socket..\n%s\n",sendline);
	FD_ZERO(&rset);
	FD_SET(socku, &rset);
	timeout.tv_sec = 5L;
	int ready;
	if(ready=select(socku+1,&rset,NULL,NULL,&timeout)<0)
	error("Error in select");
	if (FD_ISSET(socku, &rset))
	{
	if((n=read(socku,recvline,MAXLINE))<0)
	{
	    if(close(socku)<0)
		error("Error in close");
	    error("Error in read");
	}

	printf("\nMessage received from ARP...	Mac address: ");
	recvline[n]=0;
	HWaddr->sll_addr[0]=recvline[0];
	HWaddr->sll_addr[1]=recvline[1];
	HWaddr->sll_addr[2]=recvline[2];
	HWaddr->sll_addr[3]=recvline[3];
	HWaddr->sll_addr[4]=recvline[4];
	HWaddr->sll_addr[5]=recvline[5];
	HWaddr->sll_addr[6]=0x00;
	HWaddr->sll_addr[7]=0x00;
	   
	return 1;


	   

	}
	if(ready==0) //timeout
	{
	printf("ARP Request timeout\n");
	if(close(socku)<0)
	    error("Error in close");
	return 0;
	}
	remove("/tmp/arp6820");

}

void add(struct hostent *host,char *name,int i)
{
	
	struct in_addr **addr_list;
	struct vm_info *current,*current1;
	current=vm_head;
	while(current->next!=NULL)
	{
		current=current->next;
	}
	current1=(struct vm_info*)malloc(sizeof(struct vm_info));
	
	addr_list = (struct in_addr **)host->h_addr_list;		
	strcpy(current1->name,name); 	
	strcpy(current1->ip,inet_ntoa(*addr_list[0]));
	memcpy(&ip[i-1].ipname,&current1->ip,strlen(current1->ip));
	
	current1->next=NULL;
	current->next=current1;
	max_count++;
	
}

void add_info(int argc,char **argv)
{
	int i;
	struct hostent *host;

	for(i=1;i<argc;i++)
	{
		if(i!=1)
			if((strcmp(argv[i],argv[i-1]))==0)
			{
				printf("Invalid input: Consecutive nodes\n");fflush(stdout);
				exit(0);
			}
		if((host=gethostbyname(argv[i]))!=NULL)		
		{
			add(host,argv[i],i);				
		}
	}
}	

void join(int sockfd,char *ip)
{	
	struct sockaddr_in join;
	join.sin_family=AF_INET;
	join.sin_addr.s_addr=inet_addr(ip);
	if((mcast_join(sockfd,&join,sizeof(join),NULL,0))<0)
		error("Error in adding multicast address");
}

void getpayload(char *name)
{	
	struct vm_info *current;
	current=vm_head;
	char ip[20];
	strcpy(name,current->ip);
	while(current->next!=NULL)
	{	
		current=current->next;
		strcat(name,"|");
		strcat(name,current->ip);
		
	}	
}

void send_multicast(char *msg,int mcast_send)
{
	struct sockaddr_in maddr;
	bzero(&maddr,sizeof(maddr));
	maddr.sin_family=AF_INET;
	maddr.sin_addr.s_addr=inet_addr(M_ADDR);
	maddr.sin_port=htons(M_PORT);
	sleep(5);
	
	sendto(mcast_send,msg,100,0,(struct sockaddr_in*)&maddr,sizeof(maddr));
}

uint16_t in_cksum(uint16_t *addr, int len)
{
	int			nleft = len;
	uint32_t		sum = 0;
	uint16_t		*w = addr;
	uint16_t		answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) 
	{
		sum += *w++;
		nleft -= 2;
	}

		/* 4mop up an odd byte, if necessary */
	if (nleft == 1) 
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w ;
		sum += answer;
	}

		/* 4add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)
{	
	int				hlen1, icmplen;
	double			rtt;
	struct iphdr		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	ip = (struct iphdr *) ptr;		/* start of IP header */
	hlen1 = ip->ihl << 2;		/* length of IP header */
	if (ip->protocol != IPPROTO_ICMP)
		return;				/* not ICMP */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		return;				/* malformed packet */

	if (icmp->icmp_type == ICMP_ECHOREPLY) 
	{	

		if (ntohs(icmp->icmp_id) != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			return;			/* not enough data to use */
	
		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_seq, ip->ttl, rtt);

	} 
}

void send_v4(void)
{
	int		len,pf_socket;
	struct icmp	*icmp;
	struct ethernet_packet *ping;
	struct hwaddr *mac;
	unsigned char destination_mac[6];
	if((pf_socket=socket(PF_PACKET,SOCK_RAW,ETH_P_IP))<0)
	error("Error in creating pf_socket");
	void* buffer=(void*)malloc(ETH_FRAME_LEN);
	memset(buffer,0,ETH_FRAME_LEN);	
	struct ethhdr *ethHeader = (struct ethhdr *)buffer;
	struct sockaddr send_addr;
	struct iphdr* header_ip;
	struct iphdr *header;
	struct icmp *data;
	
	
	struct sockaddr_ll dest_addr;
	bzero(&dest_addr,sizeof(struct sockaddr_ll));
	
    	char   *ptr,temp[14];
    	int    i, prflag;
	mac=(struct hwaddr*)malloc(sizeof(struct hwaddr));
	memset(mac,0,sizeof(struct hwaddr));
	memset(destination_mac,0,6);
	icmp=(struct icmp*)malloc(64);
	memset(icmp,0,64);
	strcpy(temp,"");
	strcpy(send_addr.sa_data,"");
	memcpy(&temp,inet_ntoa(target_strt),14);
	memset(&send_addr,0,sizeof(struct sockaddr));
	send_addr.sa_family=AF_UNIX;
	memcpy(send_addr.sa_data,temp,14);
	ping=(struct ethernet_packet*)malloc(sizeof(struct ethernet_packet));
	memset(ping,0,sizeof(struct ethernet_packet));
	header = &(ping->ping_header);
	header=(struct iphdr*)malloc(sizeof(struct iphdr));
	memset(header,0,sizeof(struct iphdr));
	data=malloc(sizeof(struct icmp));
	memset(data,0,sizeof(struct icmp));
	
	if((areq(&send_addr,sizeof(struct sockaddr),mac))<0)
	{
		printf("AREQ error");
		exit(1);
	}
	memset(destination_mac,0,6);
	destination_mac[0]=mac->sll_addr[0];
	destination_mac[1]=mac->sll_addr[1];
	destination_mac[2]=mac->sll_addr[2];
	destination_mac[3]=mac->sll_addr[3];
	destination_mac[4]=mac->sll_addr[4];
	destination_mac[5]=mac->sll_addr[5];
	printf("00:");fflush(stdout);	
	for(i=5;i>0;i--)
	printf("%.2x%s",destination_mac[i]&0xff,i==1?" ":":");
	printf("\n");

	icmp = &(ping->details);
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = htons(pid);
	icmp->icmp_seq = htons(0);
	memset(icmp->icmp_data, 0xa5, datalen);	/* fill with pattern */
	Gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);
	
	
	memcpy(data,icmp,sizeof(struct icmp));
	header->version =IPVERSION;
	header->ihl = 5;			////gethostbyname 
	header->tos = 0;
	header->tot_len = sizeof(struct iphdr)+sizeof(struct icmp);
	header->id = htons(0);
	header->ttl = 225;
	header->protocol = IPPROTO_ICMP;
	header->saddr = inet_addr(my_ip);
	header->daddr = inet_addr(target_ip);
	memcpy(data,icmp,sizeof(struct icmp));

	memcpy((void*)buffer,(void*)source_mac,ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN),(void*)destination_mac,ETH_ALEN);
	ethHeader->h_proto = htons(ETH_P_IP);
	

	memcpy((void*)(buffer+14),(void*)header,sizeof(struct iphdr));
	memcpy((void*)(buffer+14+(sizeof(struct iphdr))),(void*)data,sizeof(struct icmp));
	
	dest_addr.sll_family = PF_PACKET;
	dest_addr.sll_ifindex = 2;
	dest_addr.sll_protocol=htons(ETH_P_IP);
	dest_addr.sll_hatype = ARPHRD_ETHER;
	dest_addr.sll_pkttype = PACKET_OTHERHOST;
	dest_addr.sll_halen = ETH_ALEN;
	dest_addr.sll_addr[0] = destination_mac[0];
	dest_addr.sll_addr[1] = destination_mac[1];
	dest_addr.sll_addr[2] = destination_mac[2];
	dest_addr.sll_addr[3] = destination_mac[3];
	dest_addr.sll_addr[4] = destination_mac[4];
	dest_addr.sll_addr[5] = destination_mac[5];
	dest_addr.sll_addr[6] = destination_mac[6];
	dest_addr.sll_addr[7] = destination_mac[7];
	

	if((sendto(pf_socket, buffer,ETH_FRAME_LEN, 0,(struct sockaddr*) &dest_addr, sizeof(dest_addr)))<0)
		error("error in sendto of ping1");
	
}

int checkifcorrect(char *input)
{	
	if(strlen(input)<3 || strlen(input)>4)
	return 0;	
	if(input[0]=='v' && input[1]=='m' && isdigit(input[2]) && input[2]!='0')
	{
		if(strlen(input)==4)
		{
			if(input[3]=='0') return 1;
			else return 0;
		}
		else return 1;
	}return 0;
}

void process_pg(int pg_socket)
{
	printf("inside ping ");fflush(stdout);
	int				size;
	char			recvbuf[0];
	char			controlbuf[BUFSIZE];
	struct msghdr	msg;
	struct iovec	iov;
	ssize_t			n;
	struct timeval	tval;
	
	
	setuid(getuid());		/* don't need special permissions any more */
	
	
	size = 60 * 1024;		/* OK if setsockopt fails */
	setsockopt(pg_socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	
	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = pr->sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;
	msg.msg_namelen = pr->salen;
	msg.msg_controllen = sizeof(controlbuf);
	n = recvfrom(pg_socket, &msg, sizeof(msg), 0,NULL,NULL);
	if (n < 0) 
	{
		error("Error in recieve");
	}
	Gettimeofday(&tval, NULL);
	(*pr->fproc)(recvbuf, n, &msg, &tval);

}

struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, NULL, 0, IPPROTO_ICMP };

void ping()
{
	int c;
	struct addrinfo	*ai;
	int datalen = 56;
	char *h;
	pid = getpid() & 0xffff;	/* ICMP ID field is 16 bits */
	if(ping_flag==0)
	{
		signal(SIGALRM, sig_alrm);
		ai = Host_serv(target_ip, NULL, 0, 0);
		h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
		printf("PING %s (%s): %d data bytes\n",ai->ai_canonname ? ai->ai_canonname : h,h, datalen);
		pr = &proto_v4;
		pr->sasend = ai->ai_addr;
		pr->sarecv = Calloc(1, ai->ai_addrlen);
		pr->salen = ai->ai_addrlen;
		sig_alrm(SIGALRM);		/* send first packet */
		ping_flag=1;
		//while(STOP_FLAG!=1)
		//{
			//sleep(1);
			(*pr->fsend)();
		//}
		
	}
}

void send_packet(int rt_socket,char *ipp,struct payload *pload,char *hostname)
{
	struct sockaddr_in destination;
	struct in_addr *destaddr;
	struct hostent *ht;
	struct packet *ip_pack;
	struct iphdr *header;
	char temp[20],temp_list[400];
	void* buffer = (void*)malloc(512);
	void* data = buffer + 20;
	
	ip_pack=(struct packet*)malloc(512);
	strcpy(temp_list,pload->data);
	
	char * temp1;
	char ipaddress[20];
  	int count=0;
	  temp1 = strtok (temp_list,"|");
	  while (temp1 != NULL)
	  {
	    count++;
		if(count==(pload->ip_index+1))
		{
			strcpy(ipaddress,temp1);
			break;
		}	
	    temp1 = strtok (NULL, "|");
	  }
	memset(ip_pack,0,sizeof(struct packet));
	header = &(ip_pack->head);
	header=(struct iphdr*)malloc(sizeof(struct iphdr));
	memset(header,0,sizeof(struct iphdr));
	header->version =IPVERSION;
	header->ihl = 5;			
	header->tos = 0;
	header->tot_len = sizeof(struct packet) ;
	header->id = htons(MY_ID);
	header->ttl = 225;
	header->protocol = MY_PROTOCOL;
	header->saddr = inet_addr(ipp);
	header->daddr = inet_addr(ipaddress);
	strcpy(ip_pack->packet_pl,pload->data);
	
		
	memcpy((void*)buffer,(void*)header,sizeof(struct iphdr));
	memcpy((void*)data,(void*)pload,sizeof(struct payload));

	bzero(&destination,sizeof(destination));
	destination.sin_family = AF_INET;
	destination.sin_addr.s_addr=header->daddr;

	if((sendto(rt_socket,buffer,header->tot_len,0,(struct sockaddr*)&destination,sizeof(destination)))<0)
		error("Error in send");
	ht=gethostbyaddr(&(destination.sin_addr),sizeof(destination),AF_INET);
	printf("Sending rt packet from %s to %s\n",hostname,ht->h_name);fflush(stdout);
}

void process_recv(int recv_mcast,int send_mcast,char *name)
{
	int n;
	char buffer[100],msg[100];
	if((n=recvfrom(recv_mcast,buffer,100,0,NULL,NULL))<0)
		error("Error in read\n");
	printf("Node: %s  received:%s\n",name,buffer);
	signal(SIGALRM, sig_alrm);
	if(strstr(buffer,"ended")!=NULL)
	{	
		STOP_FLAG=1;
		sprintf(msg,"<<<<< Node %s .  I am a member of the group. >>>>>",name);
		printf("Node: %s Sending %s\n",name,msg);
		send_multicast(msg, send_mcast);
	}
	else if(strstr(buffer,"I am a member of the group") != NULL)
	{
		End = 1;
		alarm(2);	
	}
}	

void process_rt(int rt_socket,int recv_mcast,int send_mcast)
{	
	struct sockaddr_in current;
	struct in_addr src,dst;
	struct hostent *ht1,*ht2;
	struct packet *ip_pack;
	struct payload *pload;
	struct iphdr *header;
	struct hwa_info *hwa, *hwahead;
	struct sockaddr *sa;
	int i, prflag;
	socklen_t len=sizeof(current);
	void* buffer = (void*)malloc(512);
	void* data=buffer+20;
	char source[20],destination[20],present_time[MAXLINE],msg[100],*dst_ip,*src_ip, *ptr;
	time_t ticks;
	ip_pack=(struct packet*)malloc(512);
	header=(struct iphdr*)malloc(sizeof(struct iphdr));
	pload=(struct payload*)malloc(sizeof(struct payload));
	memset(buffer,0,sizeof((void*)buffer));
	memset(header,0,sizeof(struct iphdr));
	memset(pload,0,sizeof(struct payload));
	memset(ip_pack,0,sizeof(struct packet));
	if((recvfrom(rt_socket,buffer,sizeof(struct packet),0,(struct sockaddr_in*)&current,&len))<0)
		error("Error in recvfrom for rt_socket");

	header=(struct iphdr*)buffer;
	pload=(struct payload*)(buffer+sizeof(struct iphdr));

	if( (ntohs(header->id)==MY_ID) && (header->protocol==MY_PROTOCOL))
	{	
		src.s_addr=header->saddr;
		dst.s_addr=header->daddr;
		
		strcpy(target_ip,inet_ntoa(src));
		strcpy(my_ip,inet_ntoa(dst));
		memcpy(&target_strt,&src,sizeof(struct in_addr));
		memcpy(&myip_strt,&dst,sizeof(struct in_addr));
		ht1=gethostbyaddr(&src,sizeof(src),AF_INET);
		strcpy(source,ht1->h_name);
		ht2=gethostbyaddr(&dst,sizeof(dst),AF_INET);

		for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) 
		{	
			if ( (sa = hwa->ip_addr) != NULL);
			prflag = 0;
			i = 0;
			do {
			    if (hwa->if_haddr[i] != '\0') 
			    {
				prflag = 1;
				break;
			    }
			} while (++i < IF_HADDR);
			if (prflag) 
			{
			    ptr = hwa->if_haddr;
			    i = IF_HADDR;
			    if(strcmp(my_ip,sock_ntop(sa, sizeof(*sa))))
			    {
			    do {
				source_mac[i]=*ptr & 0xff; 
				
			    } while (--i > 0);
			    }
			}
		}

		free_hwa_info(hwahead);
		strcpy(destination,ht2->h_name);
		ticks = time(NULL);
		snprintf(present_time, sizeof(present_time), "%.24s", ctime(&ticks));
		printf("%s: received source routing packet from %s\n",present_time,source);
		if(visited==0)
		{
			visited=1;
			memcpy(pload,(struct payload*)data,sizeof(pload));
			join(recv_mcast,M_ADDR);
			printf("Node:%s Joined multicast group\n",destination);fflush(stdout);
		}
		else printf("Already in the group\n");
		if(pload->ip_index==pload->final)
		{	
			sprintf(msg,"<<<<< This is node %s .  Tour has ended .  Group members please identify yourselves. >>>>>",destination);
			printf("Node %s : Sending %s\n",destination,msg);
			send_multicast(msg, send_mcast);			//last node reached
		}
		else	{
				pload->ip_index++;
				send_packet(rt_socket,inet_ntoa(dst),pload,destination);
			}
		printf("Node %s is going to ping node %s at ip address %s\n",destination,source,inet_ntoa(dst));
		ping();
				
	}
}

int main(int argc,char **argv)
{
	
	struct hostent *ht;
	struct sockaddr_in server,serv;
	struct payload *pload=(struct payload*)malloc(sizeof(struct payload));
	struct in_addr **addr_list;
	struct ifreq ifr;
	struct hwa_info *hwa,*hwahead;
	struct sockaddr *sa;

	int rt_socket,pg_socket,pf_socket,recv_mcast,send_mcast,max,ready,sd,i;				//sockets
	int hdr_option=1;										//socket options	
	char hostname[MAXLINE], list[492],cport[10],temp[20],interface[20],temp2[20],src_ip[20];
	memset(pload,0,sizeof(pload));
	
	vm_head=NULL;
	strcpy (interface, "eth0");

	if((rt_socket=socket(AF_INET,SOCK_RAW,MY_PROTOCOL))<0)
	error("Error in creating rt_socket");
		if (setsockopt (rt_socket, IPPROTO_IP, IP_HDRINCL, &hdr_option, sizeof(hdr_option)) < 0)
	error("Error in setsockopt of rt_socket");
	  
	if((pg_socket=socket(AF_INET,SOCK_RAW,htons(IPPROTO_ICMP)))<0)
	error("Error in creating pg_socket");
	
	if((recv_mcast=socket(AF_INET,SOCK_DGRAM,0))<0)
	error("Error in creating recv_mcast socket");	
	bzero(&server,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_addr.s_addr=inet_addr(M_ADDR);
	server.sin_port=htons(M_PORT);
	if((bind(recv_mcast,(struct sockaddr*)&server,sizeof(server)))<0)
	error("Error in bind for recv_mcast socket");
	
	
	if((send_mcast=socket(AF_INET,SOCK_DGRAM,0))<0)
	error("Error in creating send_mcast socket");
	
	if((gethostname(hostname,sizeof(hostname)))<0)	
	error("Error in gethostname");
	
	printf("The host machine is %s\n",hostname);fflush(stdout);
	
	
	
	if(argc>=2)							//define multicast addr and port no. and add them to the list
	{	
		myself=1;
		if((strcmp(hostname,argv[1]))==0)
		{
			printf("Invalid input: 1st node is same as host node\n");
			exit(1);
		}
		
		for(i=1;i<argc;i++)
		{
			if((checkifcorrect(argv[i]))==0)
				{
					printf("Invalid input\n");
					exit(0);
				}			
		}
		if(((ht=gethostbyname(hostname)))!=NULL)		
		{
			struct vm_info *current;
			current=vm_head;
			current=(struct vm_info*)malloc(sizeof(struct vm_info));
			addr_list = (struct in_addr **)ht->h_addr_list;		
			strcpy(current->name,hostname);
			strcpy(current->ip,inet_ntoa(*addr_list[0]));
			vm_head=current;
			vm_head->next=NULL;
			strcpy(src_ip,inet_ntoa(*addr_list[0]));		
		}
		add_info(argc,argv);
		join(recv_mcast,M_ADDR);
		printf("Node:%s joined multicast address %s with port number %i\n",hostname,M_ADDR,M_PORT);	
		getpayload(list);
		strcat(list,"|");
		strcat(list,M_ADDR);
		strcat(list,"|");
		sprintf(cport,"%d",M_PORT);
		strcat(list,cport);
		strcpy(temp,M_ADDR);
		printf("The list of ip address %s\n",list);fflush(stdout);
		strcpy(pload->data,list);
		strcpy(pload->mcast_addr,temp);
		pload->final=max_count;
		pload->mcast_port=(M_PORT);	
		pload->ip_index=1;
		send_packet(rt_socket,src_ip,pload,hostname);
	}	
		


	//setup the ip packet

	//send the packet on rt_socket

	while (1)
	{			
		
		fd_set bset;
		FD_ZERO(&bset);
		FD_SET(rt_socket,&bset);
		FD_SET(pg_socket,&bset);
		FD_SET(recv_mcast,&bset);
		max=rt_socket;
		if(rt_socket<pg_socket)
			max=pg_socket;
		if(max<recv_mcast)
			max=recv_mcast;
		ready=select(max+1,&bset,NULL,NULL,NULL);
		if(ready < 0 && (errno==EINTR))
		{
			continue;
		}		
		else if(ready <0) error("Error in select");
		if(FD_ISSET(rt_socket,&bset))
		{
			process_rt(rt_socket,recv_mcast,send_mcast);			//rt_socket process
				
			
		}
		if(FD_ISSET(pg_socket,&bset))
		{	
			process_pg(pg_socket);					//pg_socket process
		}
		if(FD_ISSET(recv_mcast,&bset))
		{	
			process_recv(recv_mcast,send_mcast,hostname);						//recv_socket process
		}
	}

}
