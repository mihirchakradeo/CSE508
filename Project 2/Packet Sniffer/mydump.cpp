#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <netinet/ether.h>
#include <time.h>
#include <cstring>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>




using namespace std;
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
cout<<endl;
return;
}
/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	int tcpFlag = 0;
	int udpFlag = 0;
	int icmpFlag = 0;


	//****************GETTING TIMESTAMP
	struct timeval timeStamp = header->ts;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	//This will hold the entire header and the payload (if any)
	char *finalPacket = new char[10000];

	nowtime = timeStamp.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "\n%s.%06ld", tmbuf, timeStamp.tv_usec);
	//****************TIMESTAMP COLLECTED


	char *expressionFilter = NULL;

	static int count = 1;                   /* packet counter */


	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
	const struct ether_arp *arp;
	const struct arphdr *ea_hdr;
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct udphdr *udp;
	const struct icmphdr* icmp;
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_icmp;
	int size_payload;


	count++;

	/* define ethernet header */
	ethernet = (sniff_ethernet*)(packet);

	sprintf(finalPacket, "%s ",buf);
	sprintf(finalPacket, "%s %s -> %s type %x len %d",finalPacket, ether_ntoa((struct ether_addr *)ethernet->ether_shost),
		ether_ntoa((struct ether_addr *)ethernet->ether_dhost),
		ethernet->ether_type, header->len);



	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {

		if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP)
		{
			 // for(int i=0; i<6;i++)
    //     		printf("%02X:", arp->arp_sha[i]);
	 		printf("%s\n%s -> %s OTHER\n",finalPacket, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
  		}

		return;
	}


	// sprintf(finalPacket, "%s\n%s:%d -> %s:%d ",finalPacket, inet_ntoa(ip->ip_src), udp->uh_sport, inet_ntoa(ip->ip_dst), udp->uh_dport);

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			// sprintf(finalPacket, "%s TCP\n",finalPacket);
			tcpFlag = 1;
			break;
		case IPPROTO_UDP:
			// sprintf(finalPacket, "%s UDP\n",finalPacket);
			udpFlag = 1;
			break;
		case IPPROTO_ICMP:
			// sprintf(finalPacket, "%s ICMP\n",finalPacket);
			icmpFlag = 1;
			break;
		case IPPROTO_IP:
			sprintf(finalPacket, "%s IP\n",finalPacket);
			return;
		default:
			printf(finalPacket, "%s OTHER\n",finalPacket);
			return;
	}

	if(tcpFlag == 1)
	{
		/*
		 *  OK, this packet is TCP.
		 */

		/* define/compute tcp header offset */
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		sprintf(finalPacket, "%s\n%s:%d -> %s:%d TCP",finalPacket, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport), inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
		size_tcp = TH_OFF(tcp)*4;

		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}

		/* define/compute tcp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	}

	else if(udpFlag == 1)
	{
		/*
		 *  OK, this packet is UDP.
		 */


		udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip + 8);
		sprintf(finalPacket, "%s\n%s:%d -> %s:%d UDP",finalPacket, inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
		size_udp = 8;
		if (size_udp < 8) {
		printf("   * Invalid UDP header length: %u bytes\n", size_udp);
		return;
		}

		/* define/compute udp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);

	}

	else if(icmpFlag == 1)
	{
		/*
		 *  OK, this packet is ICMP.
		 */
		icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
		sprintf(finalPacket, "%s\n%s -> %s ICMP",finalPacket, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));

		size_icmp = sizeof(icmphdr);
		if (size_icmp < 8) {
		printf("   * Invalid ICMP header length: %u bytes\n", size_icmp);
		return;
		}

		/* define/compute icmp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
	}

	if(args != NULL)
	{
		expressionFilter = strstr((char *)payload, (char *)args);
		cout<<expressionFilter<<endl;
		if(expressionFilter != NULL)
		{
			//print as payload is there
			if(tcpFlag == 1)
			{
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			}
			else if(udpFlag == 1)
			{
				size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
			}
			else if(icmpFlag == 1)
			{
				size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
			}

			/* compute tcp payload (segment) size */

			/*
			 * Print payload data; it might be binary, so don't just
			 * treat it as a string.
			 */
			if (size_payload > 0) {
				cout<<finalPacket<<endl;
				print_payload((u_char *)expressionFilter, size_payload);
				cout<<endl;
			}
		}
	}
	else
	{
		if(tcpFlag == 1)
		{
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		}
		else if(udpFlag == 1)
		{
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
		}
		else if(icmpFlag == 1)
		{
			size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
		}
		cout<<finalPacket<<endl;
		print_payload((u_char*)payload, size_payload);

	}


return;
}

int main(int argc, char **argv)
{
	int c;
	u_char *stringEntered = NULL;
	int iflag = 0;
	int rflag = 0;
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	const char* fname = NULL;
	char filter_exp[3];		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */




	while((c = getopt(argc, argv, "i:r:s:")) != -1)
	{

		switch(c)
		{
			case 'i':
				cout<<"Entered device: "<<optarg<<endl;

				iflag = 1;
				break;

			case 'r':
				if (iflag == 1)
				{
					cout<<"Invalid combination"<<endl;
					exit(0);
				}

				fname = optarg;
				rflag = 1;
				break;

			case 's':
				stringEntered = new u_char[sizeof(optarg)];
				memcpy(stringEntered, optarg, sizeof(optarg));
				// strcpy(stringEntered, optarg);
				break;

			case '?':
				if(optopt == 'i' || optopt == 'r' || optopt == 's')
				{
					fprintf(stderr, "Option -%c needs an argument\n", optopt);
				}
				else
				{
					fprintf(stderr, "Unknown option %c\n", optopt);
				}
				break;

			default:
				fprintf(stderr, "getopt");
		}
	}


	/* find a capture device if not specified on command-line */

	//expression
	dev = optarg;

	if(argv[optind] != NULL)
		strcpy(filter_exp, argv[optind]);


	dev = pcap_lookupdev(errbuf);

	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}


	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}



	/* print capture info */
	printf("Device: %s\n", dev);

	/* open capture device */

	if(rflag == 1)
	{
		handle = pcap_open_offline(fname, errbuf);
	}

	else
	{

		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}
	}


	/* compile the filter expression */
	if(filter_exp != NULL)
	{
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
		}

		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
			    filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

	}

	/* now we can set our callback function */
	pcap_loop(handle, 0, got_packet, stringEntered);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
