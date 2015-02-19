#include <sys/socket.h>
#include "hw_addrs.h"
#include "unp.h"
#include <linux/if_ether.h>
#include <linux/if_arp.h>
//#define USID_PROTO 0x4481
//#define UNIXDG_PATH "testpath"
//#define ETH_FRAME_LEN 1514
//#define IDENTIFIER 72217

static int IGNORE_FLAG=0;

extern struct hwa_info  *Get_hw_addrs();
extern void free_hwa_info(struct hwa_info *);

struct arpframe
{
	uint16_t id_value;
	uint16_t hard_type;
	uint16_t proto_type;
	uint8_t hard_size;
	uint8_t proto_size;
	uint16_t op;
	unsigned char sender_ethernet_address[6];
	char sender_ip_address[INET_ADDRSTRLEN];
	unsigned char target_ethernet_address[6];
	char target_ip_address[INET_ADDRSTRLEN];
};


struct hw_addr
{
    char name[50];                          
    char ip_addr[20];                    
    unsigned char hw_addr[6];                      
    int index;                          
}ifi_info[10];


struct cache_entry
{
	char ip_addr[INET_ADDRSTRLEN];
	unsigned char hw_addr[6];
	int sll_ifindex;
	unsigned short sll_hatype;
	int unix_domain_confd;
	struct cache_entry *next;
}*c_head;

void error(char *msg)
{
    fprintf(stderr,"%s:  %s\n",msg,strerror(errno));
    exit(1);
}


void error_wo_exit(char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
}

void insert_cache(char *ip_addr, unsigned char *mac_addr, int index, unsigned short hatype, int socku)
{
	int i;
	struct cache_entry *current;
	current=c_head;
	if(current==NULL)
	{
		current = (struct cache_entry*)malloc(sizeof(struct cache_entry));
		memset(current,0,sizeof(struct cache_entry));
		c_head=current;
		current->next=NULL;
	}
	else
	{	
		while(current->next!=NULL)
			current=current->next;
		//current=current->next;
		current->next=(struct cache_entry*)malloc(sizeof(struct cache_entry));
		memset(current->next,0,sizeof(struct cache_entry));
		current=current->next;
		current->next=NULL;
	}

	strcpy(current->ip_addr,ip_addr);
	if(mac_addr==NULL)
		memset(current->hw_addr,0,6);
	else
	{
	current->hw_addr[0]=mac_addr[0];
	current->hw_addr[1]=mac_addr[1];
	current->hw_addr[2]=mac_addr[2];
	current->hw_addr[3]=mac_addr[3];
	current->hw_addr[4]=mac_addr[4];
	current->hw_addr[5]=mac_addr[5];
	}
	
	current->sll_ifindex=index;////
	current->sll_hatype=ARPHRD_ETHER;
	current->unix_domain_confd=socku;
	return;

}

struct cache_entry* get_cache_entry_from_IP(char *ip_address)
{
	struct cache_entry *current; 
	current=c_head;
	
	while( current!=NULL )
	{	
		if((strcmp(current->ip_addr, ip_address)==0))
		{
			return current;
		}
		current = current->next;
		
	}
	return NULL;	
}
void display_ether_addr(unsigned char *ether)
{
	int i;
	printf("00:");fflush(stdout);
	for(i=5;i>0;i--)
			printf("%.2x%s",ether[i] & 0xff, (i == 1) ? " " : ":");
	return;
}

void display_frame(char *input)
{
	struct arpframe *aframe1 = (struct arpframe*)malloc(sizeof(struct arpframe));
	memset(aframe1,0,sizeof(struct arpframe));
	void *buffer = (void*)malloc(ETH_FRAME_LEN);
	memset(buffer,0,ETH_FRAME_LEN);
	void *data=buffer+14;
	memcpy(buffer,(void*)input,ETH_FRAME_LEN);
	aframe1=(struct arpframe*)data;
	printf("Sender Ethernet Addr: ");
	display_ether_addr(&aframe1->sender_ethernet_address);
	printf("\nSender IP Addr: %s\n",aframe1->sender_ip_address);
	printf("Destination Ethernet Addr: ");
	display_ether_addr(&aframe1->target_ethernet_address);
	printf("\nDestination IP Addr: %s\n",aframe1->target_ip_address);
	printf("ID_value = %d\n",ntohs(aframe1->id_value));
	printf("Hard_type = %d\n",ntohs(aframe1->hard_type));
	printf("Proto_type = %d\n",ntohs(aframe1->proto_type));
	printf("op = %d\n",ntohs(aframe1->op));
	return;
	
}

void broadcast(int socku, int a, char *target_ip)
{
	int i;
	struct arpframe *aframe=(struct arpframe*)malloc(sizeof(struct arpframe));
	memset(aframe,0,sizeof(struct arpframe));
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	memset(buffer,0,ETH_FRAME_LEN);
	unsigned char* etherhead = buffer;
	void* data = buffer + 14;
	unsigned char destination_mac[6];
	unsigned char source_mac[6];

	struct ethhdr *eh = (struct ethhdr *)etherhead;
	struct sockaddr_ll broadcast;           
	bzero(&broadcast,sizeof(broadcast));
	broadcast.sll_family = PF_PACKET;
	broadcast.sll_ifindex = ifi_info[a].index;
	broadcast.sll_protocol=htons(3243);
	broadcast.sll_hatype = ARPHRD_ETHER;
	broadcast.sll_pkttype = PACKET_OTHERHOST;
	broadcast.sll_halen = ETH_ALEN;
	broadcast.sll_addr[0] = 0xff;
	broadcast.sll_addr[1] = 0xff;
	broadcast.sll_addr[2] = 0xff;
	broadcast.sll_addr[3] = 0xff;
	broadcast.sll_addr[4] = 0xff;
	broadcast.sll_addr[5] = 0xff;
	broadcast.sll_addr[6] = 0x00;
	broadcast.sll_addr[7] = 0x00;

	destination_mac[0]=0xff;
	destination_mac[1]=0xff;
	destination_mac[2]=0xff;
	destination_mac[3]=0xff;
	destination_mac[4]=0xff;
	destination_mac[5]=0xff;

	source_mac[0]=ifi_info[a].hw_addr[0];
	source_mac[1]=ifi_info[a].hw_addr[1];
	source_mac[2]=ifi_info[a].hw_addr[2];
	source_mac[3]=ifi_info[a].hw_addr[3];
	source_mac[4]=ifi_info[a].hw_addr[4];
	source_mac[5]=ifi_info[a].hw_addr[5];
	
	memcpy((void*)buffer, (void*)destination_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)source_mac, ETH_ALEN);
	eh->h_proto = htons(3243);
	aframe->id_value=htons(33423);
	aframe->hard_type=htons(1);
	aframe->proto_type=htons(3243);
	aframe->hard_size=htons(6);
	aframe->proto_size=htons(4);
	aframe->op=htons(1);
	
	aframe->sender_ethernet_address[0]=ifi_info[a].hw_addr[0];
	aframe->sender_ethernet_address[1]=ifi_info[a].hw_addr[1];
	aframe->sender_ethernet_address[2]=ifi_info[a].hw_addr[2];
	aframe->sender_ethernet_address[3]=ifi_info[a].hw_addr[3];
	aframe->sender_ethernet_address[4]=ifi_info[a].hw_addr[4];
	aframe->sender_ethernet_address[5]=ifi_info[a].hw_addr[5];
		
	strcpy(aframe->sender_ip_address,ifi_info[a].ip_addr);
	strcpy(aframe->target_ip_address,target_ip);

	memcpy(data,aframe,sizeof(struct arpframe));
	printf("\nSending ARP Request...\nFrame details:\n");
	display_frame((char*)buffer);
	if(sendto(socku,buffer,ETH_FRAME_LEN,0,(struct sockaddr*)&broadcast,sizeof(broadcast))<0)
		error_wo_exit("Error in sendto of broadcast");
	free(buffer);  
}

struct arpframe* extract_arp_frame(char *input)
{
	struct arpframe *aframe1 = (struct arpframe*)malloc(sizeof(struct arpframe));
	struct arpframe *aframe2 = (struct arpframe*)malloc(sizeof(struct arpframe));
	void *buffer = (void*)malloc(ETH_FRAME_LEN);
	memset(aframe1,0,sizeof(struct arpframe));
	memset(aframe2,0,sizeof(struct arpframe));
	memset(buffer,0,sizeof(ETH_FRAME_LEN));	
	void *data=buffer+14;
	memcpy(buffer,(void*)input,ETH_FRAME_LEN);
	aframe1=(struct arpframe*)data;
	aframe2->id_value=ntohs(aframe1->id_value);
	aframe2->hard_type=ntohs(aframe1->hard_type);
	aframe2->proto_type=ntohs(aframe1->proto_type);
	aframe2->op=ntohs(aframe1->op);
	aframe2->sender_ethernet_address[0]=aframe1->sender_ethernet_address[0];
	aframe2->sender_ethernet_address[1]=aframe1->sender_ethernet_address[1];
	aframe2->sender_ethernet_address[2]=aframe1->sender_ethernet_address[2];
	aframe2->sender_ethernet_address[3]=aframe1->sender_ethernet_address[3];
	aframe2->sender_ethernet_address[4]=aframe1->sender_ethernet_address[4];
	aframe2->sender_ethernet_address[5]=aframe1->sender_ethernet_address[5];
	strcpy(aframe2->sender_ip_address,aframe1->sender_ip_address);
	aframe2->target_ethernet_address[0]=aframe1->target_ethernet_address[0];
	aframe2->target_ethernet_address[1]=aframe1->target_ethernet_address[1];
	aframe2->target_ethernet_address[2]=aframe1->target_ethernet_address[2];
	aframe2->target_ethernet_address[3]=aframe1->target_ethernet_address[3];
	aframe2->target_ethernet_address[4]=aframe1->target_ethernet_address[4];
	aframe2->target_ethernet_address[5]=aframe1->target_ethernet_address[5];
	strcpy(aframe2->target_ip_address,aframe1->target_ip_address);	
	return aframe2;

}

void send_ARP_response_frame(int sockraw,struct arpframe *aframe,struct cache_entry *rep_entry)
{
	int i;
	struct arpframe *send_aframe=(struct arpframe*)malloc(sizeof(struct arpframe));
	memset(send_aframe,0,sizeof(struct arpframe));
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	memset(buffer,0,ETH_FRAME_LEN);
	unsigned char* etherhead = buffer;
	void* data = buffer + 14;
	unsigned char destination_mac[6];
	unsigned char source_mac[6];

	struct ethhdr *eh = (struct ethhdr *)etherhead;
	struct sockaddr_ll sendresp;           
	bzero(&sendresp,sizeof(sendresp));
	sendresp.sll_family = PF_PACKET;
	sendresp.sll_ifindex = rep_entry->sll_ifindex;
	sendresp.sll_protocol=htons(3243);///////////////////
	sendresp.sll_hatype = ARPHRD_ETHER;
	sendresp.sll_pkttype = PACKET_OTHERHOST;
	sendresp.sll_halen = ETH_ALEN;

	sendresp.sll_addr[0]=0xff;
	sendresp.sll_addr[1]=0xff;
	sendresp.sll_addr[2]=0xff;
	sendresp.sll_addr[3]=0xff;
	sendresp.sll_addr[4]=0xff;
	sendresp.sll_addr[5]=0xff;
	sendresp.sll_addr[6]=0x00;
	sendresp.sll_addr[7]=0x00;
	
	destination_mac[0]=0xff;
	destination_mac[1]=0xff;
	destination_mac[2]=0xff;
	destination_mac[3]=0xff;
	destination_mac[4]=0xff;
	destination_mac[5]=0xff;
	
	//memcpy((void*)buffer, (void*)aframe->sender_ethernet_address, ETH_ALEN);
	memcpy((void*)buffer, (void*)destination_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)rep_entry->hw_addr, ETH_ALEN);
	eh->h_proto = htons(3243);
	send_aframe->id_value=htons(33423);
	send_aframe->hard_type=htons(1);
	send_aframe->proto_type=htons(3243);
	send_aframe->hard_size=htons(6);
	send_aframe->proto_size=htons(4);
	send_aframe->op=htons(2);
	send_aframe->sender_ethernet_address[0]=rep_entry->hw_addr[0];
	send_aframe->sender_ethernet_address[1]=rep_entry->hw_addr[1];
	send_aframe->sender_ethernet_address[2]=rep_entry->hw_addr[2];
	send_aframe->sender_ethernet_address[3]=rep_entry->hw_addr[3];
	send_aframe->sender_ethernet_address[4]=rep_entry->hw_addr[4];
	send_aframe->sender_ethernet_address[5]=rep_entry->hw_addr[5];
	strcpy(send_aframe->sender_ip_address,aframe->target_ip_address);
	send_aframe->target_ethernet_address[0]=aframe->sender_ethernet_address[0];
	send_aframe->target_ethernet_address[1]=aframe->sender_ethernet_address[1];
	send_aframe->target_ethernet_address[2]=aframe->sender_ethernet_address[2];
	send_aframe->target_ethernet_address[3]=aframe->sender_ethernet_address[3];
	send_aframe->target_ethernet_address[4]=aframe->sender_ethernet_address[4];
	send_aframe->target_ethernet_address[5]=aframe->sender_ethernet_address[5];
	strcpy(send_aframe->target_ip_address,aframe->sender_ip_address);

	memcpy(data,send_aframe,sizeof(struct arpframe));
	printf("Sending ARP response...\nFrame details:\n");
	display_frame((char*)buffer);
	if(sendto(sockraw,buffer,ETH_FRAME_LEN,0,(struct sockaddr*)&sendresp,sizeof(sendresp))<0)
		error_wo_exit("Error in sendto of ARP response");
	
	free(buffer);  
	
}

void display_cache()
{
	int i;
	struct cache_entry *current;
	current=c_head;
	printf("-----------------------------------------------------------------------------------------------------\n");
	printf("    IP ADDR\t  HW_ADDR\t   IFINDEX   HA_TYPE\tUNIX_DOMAIN_CONFD\n");
	printf("-----------------------------------------------------------------------------------------------------\n");
	while(current!=NULL)
	{
		printf("%s\t",current->ip_addr);
		for(i=6;i>0;i--)
			printf("%.2x%s",current->hw_addr[i] & 0xff, (i == 1) ? " " : ":");
		printf("\t%d\t%hu\t%d\n",current->sll_ifindex,current->sll_hatype,current->unix_domain_confd);
		current=current->next;
	}
	printf("-----------------------------------------------------------------------------------------------------\n");
}

int checkif_own_ip(char *target_ip_address, int a)
{
	int i;
	for(i=0;i<a;i++)
	{
		if(strcmp(target_ip_address,ifi_info[a].ip_addr)==0)
			return 1;
	}
return 0;
}

void cache_delete_entry(int connfd)
{
	struct cache_entry *current, *current1;
	current=c_head;
	if(current->unix_domain_confd==connfd)
	{
		c_head=current->next;
		free(current);
	}
	else
	{
		while(current!=NULL)
		{
			current1=current->next;
			if(current1->unix_domain_confd==connfd)
			{
				current=current1->next;
				free(current1);
			}
			current=current->next;
		}
	}

}

void update_and_delete_confd_cache(char *target_ip_address,unsigned char *hw_address, int index)//adds HW_ADDR and deletes connfd from the cache
{
	struct cache_entry *current;
	current=c_head;
	while(current!=NULL)
	{
		if(strcmp(current->ip_addr,target_ip_address)==0)
		{
			current->hw_addr[0]=hw_address[0];
			current->hw_addr[1]=hw_address[1];
			current->hw_addr[2]=hw_address[2];
			current->hw_addr[3]=hw_address[3];
			current->hw_addr[4]=hw_address[4];
			current->hw_addr[5]=hw_address[5];
			current->sll_ifindex=index;
			current->unix_domain_confd=NULL;
		}
		current=current->next;
	}
}

int main()
{
	struct hwa_info *hwa, *hwahead;
	int x=0, i, sockraw, unix_domain_socket, ready, n, prflag, connfd;
	struct sockaddr_un unixaddr, arpaddr;
	struct sockaddr_ll addr1;
	fd_set rset;
	size_t len, len1;
	char *tokens[10], recvline[MAXLINE], buffer[ETH_FRAME_LEN], *ptr;
	struct cache_entry *entry;
	struct sockaddr	*sa;	

	c_head=NULL;
	memset(ifi_info,0,sizeof(ifi_info));
	printf("\n\n----------------set of  <IP address , HW address>  matching pairs for all eth0 interface IP addresses----------------\n");fflush(stdout);
	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) 
	{
		if(strcmp(hwa->if_name,"eth0")==0)
		{
			printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");
			if ( (sa = hwa->ip_addr) != NULL)
				printf("< IP addr = %s , ", sock_ntop(sa, sizeof(*sa)));
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
			    printf("HW addr = ");
			    ptr = hwa->if_haddr;
			    i = IF_HADDR;
			    do {
				ifi_info[x].hw_addr[i]=*ptr & 0xff; 
				printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
			    } while (--i > 0);
			    printf(" >");
			}

			printf("\tinterface index = %d\n\n", hwa->if_index);


			strcpy(ifi_info[x].name,hwa->if_name);
			strcpy(ifi_info[x].ip_addr,sock_ntop(sa, sizeof(*sa)));
			ifi_info[x].index=hwa->if_index;
			x++;
		}
	}
	free_hwa_info(hwahead);
	printf("------------------------------------------------------------------------------------------------------------------\n");fflush(stdout);
	for(i=0;i<x;i++)
		insert_cache(ifi_info[i].ip_addr,ifi_info[i].hw_addr,ifi_info[i].index,NULL,NULL);
	
	display_cache();
	if((sockraw = socket(PF_PACKET, SOCK_RAW, htons(3243)))<0)
 		error("Error in PF_PACKET socket");
 
 	if((unix_domain_socket = socket(AF_LOCAL, SOCK_STREAM, 0))<0)
 		error("Error in UNIX socket");

	bzero(&unixaddr, sizeof(unixaddr));
	unixaddr.sun_family = AF_LOCAL;
	unlink("/tmp/arp6820");
	strcpy(unixaddr.sun_path,"/tmp/arp6820");
    	if(bind(unix_domain_socket, (SA *) &unixaddr, sizeof(unixaddr))<0)
		error("Error in binding");
	
	if(listen(unix_domain_socket, LISTENQ)<0)
		error("Error in listening");
	char *devname = "eth0";
	if(setsockopt(sockraw, SOL_SOCKET, SO_BINDTODEVICE, devname, strlen(devname))<0)
		error("Error in setsock");
	int maxfd;
	printf("Waiting for request...\n");fflush(stdout);
	while(1)
	{label:
		FD_ZERO(&rset);
		FD_SET(sockraw,&rset);
		FD_SET(unix_domain_socket,&rset);
		maxfd = sockraw>unix_domain_socket?sockraw:unix_domain_socket;
		
		if((ready=select(maxfd+1,&rset,NULL,NULL,NULL))<0)
		{
			if(errno==EINTR)	
				continue;
			else error("Error in select");

		}
		
		if(FD_ISSET(sockraw,&rset))
		{	
			len1=sizeof(addr1);
	        	if((n=recvfrom(sockraw,buffer,ETH_FRAME_LEN,0,(SA*)&addr1,&len1))<0)
	        	{
				if(errno==EINTR)	
					continue;
				else error("Error in recvfrom");
			}
			
			struct arpframe *aframe = extract_arp_frame(buffer);
			if(strcmp(aframe->target_ip_address,ifi_info[0].ip_addr)!=0)
				continue;
			
			if(aframe->id_value==33423)
			{
				
				if(aframe->op==1)
				{
					//request
					printf("ARP Request Received\nFrame details:\n");
					display_frame((char*)buffer);fflush(stdout);
					struct cache_entry *req_entry = (struct cache_entry*)malloc(sizeof(struct cache_entry));
					req_entry=get_cache_entry_from_IP(aframe->target_ip_address);
					
					if(req_entry!=NULL && req_entry->hw_addr!=NULL)
					{
						printf("<IP addr, HW addr> matching pair found in the cache\n");
						send_ARP_response_frame(sockraw,aframe,req_entry);
					}
					else if(req_entry==NULL)
						{
							if(checkif_own_ip(aframe->target_ip_address,x)==1)
								insert_cache(aframe->sender_ip_address,aframe->sender_ethernet_address,addr1.sll_ifindex,aframe->hard_type,NULL);
							else printf("Update\n");fflush(stdout);
						}
				
				}
				if(aframe->op==2)
				{
					//reply
					
					if(IGNORE_FLAG==1)
					{
						printf("Ignoring ARP response since areq client closed connection\n");fflush(stdout);
					}
					else
					{	printf("ARP Reply Received\nFrame details:\n");
						display_frame((char*)buffer);
						struct cache_entry *rep_entry = (struct cache_entry*)malloc(sizeof(struct cache_entry));
						rep_entry = get_cache_entry_from_IP(aframe->sender_ip_address);
						if(rep_entry!=NULL && rep_entry->unix_domain_confd!=NULL)
						{
							if(write(rep_entry->unix_domain_confd,aframe->sender_ethernet_address,6)<0)
								error("Error in write ARP response");
							printf("HW addr sent!\n");fflush(stdout);
							FD_CLR(rep_entry->unix_domain_confd,&rset);
							if(close(rep_entry->unix_domain_confd)<0)
								error("Error in close");
							update_and_delete_confd_cache(aframe->sender_ip_address,aframe->sender_ethernet_address,addr1.sll_ifindex);
							printf("Updated cache details:\n");							
							display_cache();
						}
					}
				}
			}
			else printf("Different protocol...Not intended for me\n"); fflush(stdout);


		}
		if(FD_ISSET(unix_domain_socket,&rset))
		{	
			len=sizeof(arpaddr);
			bzero(&arpaddr,sizeof(arpaddr));
			if((connfd = accept(unix_domain_socket, (struct sockaddr_un*)&arpaddr, &len))<0)
			{
				error_wo_exit("Error in accept");
				continue;
			}
			
			memset(recvline,0,MAXLINE);
			if ((n = read(connfd, recvline, MAXLINE))<0)
			{
				error_wo_exit("Error in readline");
				continue;

			}
			i=0;
			
			tokens[i] = strtok(recvline, "|");
			while( tokens[i] != NULL ) 
			{
			printf( " %s", tokens[i]);
			i++;
			tokens[i] = strtok(NULL, "|");
			}
			
			entry=get_cache_entry_from_IP(tokens[0]);
			
			if(entry!=NULL)
			{	
				printf("Entry found in cache\n");fflush(stdout);
				
				if((write(connfd,entry->hw_addr,6))<0)
					error_wo_exit("Error in write");
				printf("HW addr sent!\n");
				close(connfd);
			
			}
			else
			{
				printf("Broadcasting ARP request\n"); fflush(stdout);
				for(i=0;i<x;i++)
					broadcast(sockraw,i,tokens[0]);
				printf("Adding incomplete entry to the cache...\n");
				insert_cache(tokens[0],NULL, atoi(tokens[1]),(unsigned short)atoi(tokens[2]),connfd );
				display_cache();
				FD_SET(connfd, &rset);
				int maxfdp=maxfd>connfd?maxfd:connfd;
				goto label;

			}

		}
		if(FD_ISSET(connfd, &rset))
		{	
			if((n = readline(connfd, recvline, MAXLINE))<0)
				error("Error in readline");
			
			if ( n == 0)
			{ 	printf("areq client disconnected!\nDeleting incomplete cache entry...\n");
				cache_delete_entry(connfd);
				display_cache();
				if(close(connfd)<0)
					error("Error in close");
				IGNORE_FLAG=1;
        		}
        	}

	}
	





}
