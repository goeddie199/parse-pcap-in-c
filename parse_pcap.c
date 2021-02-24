#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<time.h>
#include<arpa/inet.h>
#define BUFSIZE 10240
#define STRSIZE 1024
typedef long bpf_int32;
typedef unsigned long bpf_u_int32;
typedef unsigned short  u_short;
typedef unsigned long u_int32;
typedef unsigned short u_int16;
typedef unsigned char u_int8;
//pacp global header structure
struct pcap_file_header
{
	unsigned int magic;           //0xa1b2c3d4
	unsigned short version_major; //magjor Version 2
	unsigned short version_minor; //magjor Version 4 
	int thiszone;                 //gmt to local correction
	unsigned int sigfigs;         //accuracy of timestamps 
	unsigned int snaplen;         //max length saved portion of each pkt 
	unsigned int linktype;        //data link type (LINKTYPE_*) 
};
//time structure
struct time_val
{
	unsigned int tv_sec;          //seconds
	unsigned int tv_usec;         //and microseconds 
};
//pcap packet header
struct pcap_pkthdr
{
	struct time_val ts;           //time stamp 
	unsigned int caplen;          //length of portion present 
	unsigned int len;             //length this packet 
};
//frame header
typedef struct FrameHeader_t
{
	unsigned char DstMAC[6];      //destination MAC
	unsigned char SrcMAC[6];      //source MAC
	unsigned short FrameType;     //ethernet type
} FrameHeader_t;
//IP packet header
typedef struct IPHeader_t
{
	unsigned char Ver_HLen;       //IP Version Number + IHL
	unsigned char TOS;            //Type of Service
	unsigned short TotalLen;      //Total Length
	unsigned short ID;            //Identification
	unsigned short Flag_Segment;  //Flags + Fragment Offset
	unsigned char TTL;            //Time to Live
	unsigned char Protocol;       //Protocol Type
	unsigned short Checksum;      //Header Checksum
	unsigned int SrcIP;           //Source Address
	unsigned int DstIP;           //Destination Address
} IPHeader_t;
//TCP header
typedef struct TCPHeader_t
{
	unsigned short SrcPort;       //Source Port
	unsigned short DstPort;       //Destination Port
	unsigned int SeqNO;           //Sequence Number
	unsigned int AckNO;           //Acknowledgment Number
	unsigned char HeaderLen;      //Size of the TCP header(4 bit) + Reserved(4 bit)
	unsigned char Flags;          //Different TCP Control Message
	unsigned short Window;        //Window Size
	unsigned short Checksum;      //Checksum
	unsigned short UrgentPointer; //Urgent Pointer 
}TCPHeader_t;
//UDP header
typedef struct UDPHeader_t
{
	unsigned short SrcPort;       //Source Port
	unsigned short DstPort;       //Destination Port
	unsigned short Len;           //Number of bytes in packet
	unsigned short Checksum;      //Checksum
}UDPHeader_t;

typedef struct VLANHeader_t
{
	unsigned char PCP_CFI_VID1;    //Priority Code Point + Canonical Format Identifier + VLAN ID 1
	unsigned char VID2;            //VLAN ID 2
	unsigned short FrameType;      //ethernet type
}VLANHeader_t;

//
void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len); //Find http message
//

static int Frame_handler(FrameHeader_t *frame_header, int i){
	char buf[BUFSIZE];
	snprintf(buf, 18, "%02x %02x %02x %02x %02x %02x",
			frame_header->SrcMAC[0], frame_header->SrcMAC[1],
			frame_header->SrcMAC[2], frame_header->SrcMAC[3],
			frame_header->SrcMAC[4], frame_header->SrcMAC[5]);
	printf("%d:  src mac= %s\n", i, buf);
	
	snprintf(buf, 18, "%02x %02x %02x %02x %02x %02x",
			frame_header->DstMAC[0], frame_header->DstMAC[1],
			frame_header->DstMAC[2], frame_header->DstMAC[3],
			frame_header->DstMAC[4], frame_header->DstMAC[5]);
	printf("%d:  dst mac= %s\n", i, buf);
	printf("%d:  frame type =%04X\n",i, ntohs(frame_header->FrameType));
	return ntohs(frame_header->FrameType);
}

static int IPv4_handler(IPHeader_t *ip_header, int i){
	char src_ip[STRSIZE], dst_ip[STRSIZE];
	//int ip_len; 
	int ip_proto;
	inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
	inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);
	ip_proto = ip_header->Protocol;
	//ip_len = ip_header->TotalLen; //IP packet total length
	printf("%d:  src ip =%s\n", i, src_ip);
	printf("%d:  dst ip =%s\n", i, dst_ip);
	printf("%d:  src protocol =%02X\n", i, ip_proto);
	return ip_proto;
}

static int VLAN_handler(VLANHeader_t *vlan_header, int i){
	unsigned int priority, CFI, VID;
	priority = (vlan_header->PCP_CFI_VID1)>>5;
	CFI = ((vlan_header->PCP_CFI_VID1)<<3)>>7;
	VID = (int)(vlan_header->PCP_CFI_VID1);
	VID &= (0X0001); //VID1
	VID = (VID<<8) | vlan_header->VID2;
	printf("%d:  vlan priority=%d\n", i, priority);
	printf("%d:  vlan CFI=%d\n", i, CFI);
	printf("%d:  vlan ID=%d\n", i, VID);
	printf("%d:  vlan frmae type=%04X\n", i, ntohs(vlan_header->FrameType));
	return ntohs(vlan_header->FrameType);
}

int main(){
	//struct pcap_file_header *file_header;
	struct pcap_pkthdr *ptk_header;
	FrameHeader_t *frame_header;
	IPHeader_t *ip_header;
	TCPHeader_t *tcp_header;
	UDPHeader_t *udp_header;
	VLANHeader_t *vlan_header;
	FILE *fp, *output;
	int   pkt_offset, i=0;
	int frame_type;
	int ip_proto, http_len, ip_len;
	int src_port, dst_port, tcp_flags;
	int vlan_frame_type;
	char buf[BUFSIZE], my_time[STRSIZE];
	//unsigned char src_mac[STRSIZE], dst_mac[STRSIZE];
	char src_ip[STRSIZE], dst_ip[STRSIZE];
	char  host[STRSIZE], uri[BUFSIZE];
	//initialization
	//file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
	ptk_header  = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
	frame_header = (FrameHeader_t *)malloc(sizeof(FrameHeader_t));
	ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
	tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
	udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));
	vlan_header = (VLANHeader_t *)malloc(sizeof(VLANHeader_t));
	memset(buf, 0, sizeof(buf));

	//open pcap file and record file
	if((fp = fopen("vlan.pcap","r")) == NULL){
		printf("error: can not open pcap file\n");
		exit(0);
	}
	if((output = fopen("output.txt","w+")) == NULL){
		printf("error: can not open output file\n");
		exit(0);
	}


	//start read pcap file
	pkt_offset = 24; //pcap global header is 24 bytes
	while(fseek(fp, pkt_offset, SEEK_SET) == 0){ //while loop for search full pcap file
		i++;
		//PCAP Packet Header is 16 Bytes
		if(fread(ptk_header, 16, 1, fp) != 1){ //read pcap packet header
			printf("\nread end of pcap file\n");
			break;
		}
		pkt_offset += 16 + ptk_header->caplen;   //Where does the next packet start
		printf("%d:  now pkt length: %d\n", i, ptk_header->caplen);
		
		//frame header is 14 bytes
		//fseek(fp, 14, SEEK_CUR); //ignore frame header

		if(fread(frame_header, sizeof(FrameHeader_t), 1, fp) != 1){
			printf("%d: can not read frame_header\n", i);
			break;
		}
		
		//IP packet header is 20 bytes
		//fseek(fp, 20, SEEK_CUR); //ignore ip header
		frame_type = Frame_handler(frame_header, i);
		if(frame_type == 0X0800){ //IPv4 ethertype is 0X0800
		//if(ntohs(frame_header->FrameType)==0X0800){ //IPv4 ethertype is 0X0800
			if(fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1){
				printf("%d: can not read ip_header\n", i);
				break;
			}
			ip_proto = IPv4_handler(ip_header, i);
			if(ip_proto == 0X06){ // TCP
				//TCP header is 20 bytes
				//fseek(fp, 20, SEEK_CUR); //ignore TCP header
			
				if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1){
					printf("%d: can not read tcp_header\n", i);
					break;
				}
				src_port = ntohs(tcp_header->SrcPort);
				dst_port = ntohs(tcp_header->DstPort);
				tcp_flags = tcp_header->Flags;
				printf("%d:  TCP src port = %d\n", i, src_port);
				printf("%d:  TCP dst port = %d\n", i, dst_port);
				printf("%d:  TCP src flag =%x\n", i, tcp_flags);
			
				if(tcp_flags == 0X18) // (PSH, ACK) three-way handshake success
				{
					if(dst_port == 80) // HTTP GET request
					{
						ip_len = ip_header->TotalLen; //IP packet total length
						http_len = ip_len - 40; //http length
						match_http(fp, "Host: ", "\r\n", host, http_len); //find "HOST" 
						match_http(fp, "GET ", "HTTP", uri, http_len); //find uri 
						sprintf(buf, "%d:  %s  src=%s:%d  dst=%s:%d  %s%s\r\n", i, my_time, src_ip, src_port, dst_ip, dst_port, host, uri);
						//printf(“%s”, buf);
						if(fwrite(buf, strlen(buf), 1, output) != 1)
						{
							printf("output file can not write");
							break;
						}
					}
				}
			}
			else if(ip_proto == 0x11){ //UDP
				//UDP header is 8 Bytes
				//fseek(fp, 8, SEEK_CUR); //ignore UDP header
				if(fread(udp_header, sizeof(UDPHeader_t), 1, fp) != 1){
						printf("%d: can not read udp_header\n", i);
						break;
				}
				src_port = ntohs(udp_header->SrcPort);
				dst_port = ntohs(udp_header->DstPort);
				printf("%d:  UDP src port = %d\n", i, src_port);
				printf("%d:  UDP dst port = %d\n", i, dst_port);
			}
		}
		else if(frame_type == 0X8100){ //VLAN 0X8100
		//else if(ntohs(frame_header->FrameType)==0X8100){ //VLAN 0X8100
			if(fread(vlan_header, sizeof(VLANHeader_t), 1, fp) != 1){
				printf("%d: can not read vlan_header\n", i);
				break;
			}
			vlan_frame_type = VLAN_handler(vlan_header, i);
			if(vlan_frame_type == 0X0800){ //IPv4 ethertype is 0X0800
				if(fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1){
				printf("%d: can not read ip_header in vlan\n", i);
				break;
				}
				ip_proto = IPv4_handler(ip_header, i);
				if(ip_proto == 0X06){ // TCP 	
					//TCP header is 20 bytes
					//fseek(fp, 20, SEEK_CUR); //ignore TCP header
				
					if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1){
						printf("%d: can not read tcp_header\n", i);
						break;
					}
					src_port = ntohs(tcp_header->SrcPort);
					dst_port = ntohs(tcp_header->DstPort);
					tcp_flags = tcp_header->Flags;
					printf("%d:  TCP src port = %d\n", i, src_port);
					printf("%d:  TCP dst port = %d\n", i, dst_port);
					printf("%d:  TCP src flag =%x\n", i, tcp_flags);
				}
				else if(ip_proto == 0x11){ //UDP
					//UDP header is 8 Bytes
					//fseek(fp, 8, SEEK_CUR); //ignore UDP header
					if(fread(udp_header, sizeof(UDPHeader_t), 1, fp) != 1){
							printf("%d: can not read udp_header\n", i);
							break;
					}
					src_port = ntohs(udp_header->SrcPort);
					dst_port = ntohs(udp_header->DstPort);
					printf("%d:  UDP src port = %d\n", i, src_port);
					printf("%d:  UDP dst port = %d\n", i, dst_port);
				}
			}
		}
	} // end while
	fclose(fp);
	fclose(output);
	return 0;
}


//Find HTTP message

void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len){
	int i;
	int http_offset;
	int head_len, tail_len, val_len;
	char head_tmp[STRSIZE], tail_tmp[STRSIZE];
	//initialization
	memset(head_tmp, 0, sizeof(head_tmp));
	memset(tail_tmp, 0, sizeof(tail_tmp));
	head_len = strlen(head_str);
	tail_len = strlen(tail_str);
	//Find head_str
	http_offset = ftell(fp); //record HTTP offset
	while((head_tmp[0] = fgetc(fp)) != EOF) //search by byte
	{
		if((ftell(fp) - http_offset) > total_len) //search is finish
		{
			sprintf(buf, "can not find %s \r\n", head_str);
			exit(0);
		}
		if(head_tmp[0] == *head_str) //match first head_str first byte
		{
			for(i=1; i<head_len; i++) //match head_str other byte
			{
				head_tmp[i]=fgetc(fp);
				if(head_tmp[i] != *(head_str+i))
				break;
			}
			if(i == head_len) //match head_str success, stop search
				break;
		}
	}
	// printf(“head_tmp=%s \n”, head_tmp);
	//find tail_str
	val_len = 0;
	while((tail_tmp[0] = fgetc(fp)) != EOF) //search by byte
	{
		if((ftell(fp) - http_offset) > total_len) //search is finish
		{
			sprintf(buf, "can not find %s \r\n", tail_str);
			exit(0);
		}
		buf[val_len++] = tail_tmp[0]; //use buf store value until find tail_str
		if(tail_tmp[0] == *tail_str) //match tail_str first byte
		{
			for(i=1; i<tail_len; i++) //match tail_str other byte
			{
				tail_tmp[i]=fgetc(fp);
				if(tail_tmp[i] != *(tail_str+i))
				break;
			}
			if(i == tail_len) //match tail_str success, stop search
			{
				buf[val_len-1] = 0; //clear extra char
				break;
			}
		}
	}
	// printf(“val=%s\n”, buf);
	fseek(fp, http_offset, SEEK_SET); //move file descriptor to the start of the file
}
