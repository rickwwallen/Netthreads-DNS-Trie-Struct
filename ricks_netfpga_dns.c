/*
 * * FILE NAME:		ricksDNS.c
 * * DNS SERVER THE UTILIZES TRIE STRUCTURE AS THE LOOKUP DATABASE
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	SEPTEMBER.29.2014
 * * DATE LAST MOD:	SEPTEMBER.29.2014
 * *     ___________
 * *    |           |
 * *  [[|___________|]]
 * *    \___________/
 * *   __|[ ]||||[ ]|__
 * *   \_| # |||| # |_/
 * *  ___ ===Jeep=== ___
 * * |\/\| ''    '' |\/\|
 * * |/\/|          |/\/|
 * * |_\_|          |_\_|
 * */
/**********************************************************************/
/*
 * * MODIFIED LOG:
 * *       <date>-<description>
 * *	September.29.2014-Adapted from ricksDNS.c
 * *	December.27.2014-Altered ones_complement_sum to corrected version
 * *		-Added ARP to allow others to negotiate with other devices
 * *		-Added ICMP to allow a ping
 * *		-Current ping is broken but can be seen with packet capture
 * *		-Altered passing of packet so that it can access correct info
 * *		-Removed send packet and to have the functions send internally
 * */
/**********************************************************************/
//#include "structs_netfpga.h"
#include "dns_netfpga.h"
//#include "my_inet.c"
#include "triez_netfpga.c"
#include "shared_functions_netfpga.c"

#include "common.h"
#include "pktbuff.h"
#include "dev.h"
#include "support.h"

//#include <netinet/udp.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <support.h>

#define ARP_PKT_SIZE (sizeof(struct ioq_header)  + sizeof(struct ether_header) + sizeof(struct ether_arp))
#define ICMP_PKT_SIZE (sizeof(struct ioq_header)  + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 512)
//#define DNS_PKT_SIZE

/*
  This is the skeleton of a typical NetThreads application.
  There is a wealth of undocumented routines in the ../common folder.
  All received packets are preceeded by an ioq_header (8 bytes), followed
  usually by an ethernet header, ip header, etc.

  A restricted version of the standard C library is precompiled. It
  should fulfil most needs. There is no support for printf or file I/O
  on the netfpga.  You can however use the log() function as a
  printf(). This function will be omitted when compiling with:
  make. Compiling with "make CONTEXT=sw" will produce an executable
  for an executable for the machine you are using will be produced. It
  will be single threaded and has the option of reading packets either
  from a packet trace or from the network (by default using tap
  devices, see the sw_* files in the
  netthreads/compiler/src/bench/common/ folder). Using this mechanism,
  you can run the exact same code on the host machine (no changes
  necessary) to verify that the functionnality is correct.

  Software is very flexible: a number of deep packet inspection
  programs have been written with this framework.
*/

// all threads start here, NetThreads 1.0 has 8 threads (4 per CPU)
// instructions from the 4 thread on a CPU are interleaved in a
// round-robin fashion. use compiler/bin/mips-mips-elf-objdump -h to
// see the memory layout of your compiled application and support.h to
// see where some controls are memory-mapped.

u_int16_t ones_complement_sum(char *data, int len)
{
	u_int32_t sum = 0;
	while (len > 1)
	{
		/*  This is the inner loop */
		sum += * (unsigned short*) data;
		data += 2;
		//data++;
		len -= 2;
	}

	/*  Add left-over byte, if any */
	if( len > 0 )
		sum += * (unsigned char *) data;
  
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
  
	//return (u_int16_t) sum;
	return (u_int16_t) ~sum;
}

// Send Answer/Response to the DNS Query
//int send_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, DnsHeader *dns, t_addr *pkt)
int send_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, DnsHeader *dns, struct pkt_buff *pkt)
{
	t_addr *reply;
	//struct ioq_header *rioq;
	unsigned short reply_bytes;
	struct ether_header *reth;
	struct iphdr *rip;
	struct udphdr *rudp;
	DnsHeader *rdns;
	u_int32_t acc;
	int byte_size;

	byte_size = ntohs(ioq->byte_length);

	// Create and send a reply.
	//if (pkt_alloc(&reply,
	//	sizeof(struct ioq_header) +
	//	sizeof(struct ether_header) +
	//	sizeof(struct iphdr) +
	//	sizeof(struct udphdr) +
	//	sizeof(DnsHeader) +
	//	pkt->len) == 0)
	//{
	//  return -15;
	//}

	// allocate reply size
	// ***TODO***
	reply = nf_pktout_alloc(byte_size);

	//rioq		= pkt_pull(&reply, sizeof(struct ioq_header));
	//reply_bytes	= (unsigned short) reply.len;
	//reth		= pkt_pull(&reply, sizeof(struct ether_header));
	//rip		= pkt_pull(&reply, sizeof(struct iphdr));
	//rudp		= pkt_pull(&reply, sizeof(struct udphdr));
	//rdns		= pkt_pull(&reply, sizeof(DnsHeader));
	//fill_ioq(rioq, ioq->src_port, reply_bytes);
	// setup the ioq_header
	// ***TODO***
	fill_ioq((struct ioq_header*) reply, 2, byte_size);
	
	// setup the ethernet header
	reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

	// setup the ip header
	rip = (struct iphdr*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));

	// setup the udp header
	rudp = (struct icmp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr));

	// setup the dns header
	rdns = (struct icmp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(DnsHeader));

	// fill ethernet header
	memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
	memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
	reth->ether_type = htons(ETHERTYPE_IP);

	// fill ip header
#ifndef DEBUG
	rip->version_ihl = 0x45;
	//rip->ihl = 5;
#else
	rip->version = 4;
	rip->ihl = 5;
#endif
	rip->tos = ip->tos; // not sure about this one
	// ***TODO***
	//rip->tot_len = htons(20 + pkt->len);
	rip->tot_len = htons(sizeof(struct iphdr) + (byte_size - (sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr))));
	rip->id = ip->id; // Lets use the id given
	rip->frag_off = 0;
	rip->ttl = IPDEFTTL;
	//rip->ttl = 64;
	rip->protocol = IPPROTO_UDP;
#ifndef DEBUG
	rip->saddr_h = ip->daddr_h;
	rip->saddr_l = ip->daddr_l;
	rip->daddr_h = ip->saddr_h;
	rip->daddr_l = ip->saddr_l;
#else
	//rip->saddr = ip->daddr;
	rip->saddr = iface->ip;
	rip->daddr = ip->saddr;
#endif
	//rip->check = ones_complement_sum((char *)rip, 20);
	rip->check = ntohs(0);
	acc = ones_complement_sum(rip, ntohs(rip->tot_len));
	rip->check = htons(acc);
	acc = 0;

	// fill udp, base it on udp request
	//memcpy(rudp, udp, pkt->len);
	rudp->source = udp->dest;
	rudp->dest   = udp->source;
	// ***TODO***
	//rudp->len    = htons(1000 + sizeof(struct udphdr));
	//rudp->len    = htons(ntohs(rip->tot_len) + sizeof(struct udphdr));
	rudp->len    = htons(ntohs(rip->tot_len) - sizeof(struct iphdr));

	// init checksum to zero to calcualate
	rudp->check = ntohs(0);

	// calculate checksum
	// ***TODO update total lenght***
	acc = ones_complement_sum(rudp, (ntohs(rip->tot_len) - sizeof(struct iphdr)));

	// assign checksum
	rudp->check = htons(acc);

	// fill dns
	// ***TODO ***
	//memcpy(rdns, dns, (byte_size - (sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr))));
	//memcpy(rdns, dns, (ntohs(rip->tot_len) + sizeof(struct udphdr)));
	memcpy(rdns, dns, ntohs(rudp->len));

	// send it
	// ***TODO***
	nf_pktout_send(reply, reply + (htons(ioq->byte_length)) + sizeof(struct ioq_header)); 

	return 1;
}

// Process DNS Query
//int process_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, DnsHeader *dns, t_addr *pkt)
int process_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, t_addr *pkt)
{
	DnsHeader *dns;			// DNS header pointer
	DnsHeader head;			// Hold header information
	DnsHdrFlags fl;			// Hold flag information
	DnsQuery qry[QRY_NO];		// Holds all the queries' qtype and qclass
	//Trie *root;			// Holds the start of the trie structure
	//Trie *result;			// Holds the node that search returns
	char msg[PKT_SZ];		// Messages sent to and from server
	char nme[DNM_SZ];		// Name
	char dmn[DNM_SZ][QRY_NO];	// Holds all the queries' domain names
	int offset;			// Offset of message parsing
	int offset2;			// Offset of message parsing holds query offset
	int qdc = QRY_NO;		// Number of queries allowed in message
	int i;
	int rc;				// Return Code
	t_addr *reply;
	struct ether_header *reth;
	struct iphdr *rip;
	struct udphdr *rudp;
	DnsHeader *rdns;
	u_int32_t acc;

	offset = 0;
	i = 0;
	rc = 0;
	//time_t tme;
	//struct tm *tinfo;
	//char t[25];
	//double stlu, etlu, telu;
	//double stps, etps, teps;
	//stps = getTime();

	log("Starting DNS server\n");
	log("    ___________\n");
	log("   |           | \n");
	log(" [[|___________|]] \n");
	log("   \\___________/ \n");
	log("  __|[ ]||||[ ]|__\n");
	log("  \\_| # |||| # |_/\n");
	log(" ___ ===Jeep=== ___ \n");
	log("|\\/\\| ''    '' |\\/\\|\n");
	log("|/\\/|          |/\\/|\n");
	log("|_\\_|          |_\\_|\n");
	log("\n\n\n");

	log("DATE TS,ID,QUERY QR,OPCODE,QDCOUNT,QUERY,QTYPE,QCLASS,RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIME TO LOOKUP(SECONDS),TIME TO SEND BACK(SECONDS)\n");

	// New DNS header pointer
	dns = pkt_pull(pkt, sizeof(DnsHeader));
	//DnsHeader *dnshdr = pkt_pull(pkt, sizeof(DnsHeader));
	memcpy(msg, pkt, (ntohs(ioq->byte_length) - sizeof(struct ioq_header) - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct udphdr)));
	//dnshdr = pkt_pull(pkt, sizeof(DnsHeader));

	//memcpy(msg, pkt->head, pkt-len);
	
	strToHdr(msg, &head);
	u16IToFlags(&fl, head.flags);
	//strToHdr(msg, &head);
	//u16IToFlags(&fl, head.flags);

	//DATETS,ID,QR,OPCODE,QDCOUNT
	log("%s,%d,%d,%d,%d,", t, (int) head.id, (int) fl.qr, (int) fl.opcode, (int) head.qdcount);

	if((fl.opcode != 0) || (head.qdcount > QRY_NO) || (fl.qr != 0))
	{
		//Only support standard queries
		fl.rcode = 4;
		if(fl.opcode != 0)
			log("%s,%d,%d,", "ERROR REFUSED FROM OPCODE", (int) fl.opcode, 0);
		else if(head.qdcount != QRY_NO)
			log("%s,%d,%d,", "ERROR REFUSED FROM QDCOUNT", (int) head.qdcount, 0);
		else
			log("%s,%d,%d,", "ERROR REFUSED FROM QR", (int) fl.qr, 0);
	}
	else
	{
		// set flags for response
		fl.qr = 1;
		// set recursion to not available
		fl.rd = 0;
		fl.ra = 0;
		// set authority
		fl.aa = 1;

		for(i = 0; i < qdc; i++)
		{
			strToQry(msg+offset, &qry[i], dmn[i], &offset);
			//QUERY,QTYPE,QCLASS
			log("%s,%d,%d,", dmn[i], (int) qry[i].qtype, (int) qry[i].qclass);
		}
		// holds query offset
		offset2 = offset;

		head.ancount = 0;
		head.nscount = 0;
		head.arcount = 0;

		for(i = 0; i < qdc; i++)
		{
			//stlu = getTime();
			fl.rcode = chSup((DnsType) qry[i].qtype, (DnsClass) qry[i].qclass);
			if(fl.rcode == 0)
			{
				if(qry[i].qtype != (uint16_t) ptr)
					fl.rcode = checkDN(dmn[i]);
				if(fl.rcode == 0)
				{
					strcpy(nme , dmn[i]);
					revDN(dmn[i]);
					//result = searchTrie(root, dmn[i], qry[i].qtype, qry[i].qclass);
					uDN(nme);
					//if(result != NULL)
						//putResRecStr(&fl, &head, root, result, &qry[i], msg+offset, &offset, nme);
					//else if(result == NULL)
						//fl.rcode = 3;
				}
			}
			//etlu = getTime();
			//telu = etlu - stlu;
		}//end 2nd for loop

		if(fl.rcode == 0)
			if((head.ancount == 0) || (head.nscount > 0) || (head.arcount > 0))
				fl.rcode = 3;
		//put header back in
		//RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIMELOOKUP,TIMETOTAL
		log("%d,%d,%d,%d,", (int) fl.rcode, (int) head.ancount, (int) head.nscount, (int) head.arcount);
		flagsToU16I(fl, &head.flags);
		//hdrToStr(msg, &head);
		//hdrToStr(pkt->head, &head);
		hdrToStr(dns, &head);

		// Push to f(x) to build the DNS Response
		//rc=send_dns(iface, ioq, eth, ip, udp, dnshdr, pkt, &msg);
		//memcpy(dns, msg, sizeof(DnsHeader) + offset); // Push the internal buffer msg to pkt
		//pkt_push(pkt, sizeof(DnsHeader));
		//pkt->len = offset;
		ioq->byte_length = htons(ntohs(ioq->byte_length) + (offset - offset2));
		//rc=send_dns(iface, ioq, eth, ip, udp, dns, pkt);
	// allocate reply size
	reply = nf_pktout_alloc(ntohs(ioq->byte_length));

	// setup the ioq_header
	fill_ioq((struct ioq_header*) reply, 2, ntohs(ioq->byte_length));
	
	// setup the ethernet header
	reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

	// setup the IP header
	rip = (struct iphdr*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));

	// setup the UDP header	
	rudp = (struct icmp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr));

	//setup the DNS header
	rdns = (DnsHeader *) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));

	// start putting things into the packet
	// ethernet
	memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
	memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
	reth->ether_type = ETHERTYPE_IP;

	// ip
	rip->version_ihl = 0x45;
	rip->tos = ip->tos; // not sure about this one
	rip->tot_len = htons(ntohs(ioq->byte_length) - sizeof(struct ioq_header) - sizeof(struct ether_header));
	rip->id = ip->id + 12; // not sure about this one
	//rip->id = 1988; // not sure about this one
	rip->frag_off = ip->frag_off;
	rip->ttl = ip->ttl--;
	rip->protocol = IPPROTO_ICMP;
	rip->saddr_h = ip->daddr_h;
	rip->saddr_l = ip->daddr_l;
	rip->daddr_h = ip->saddr_h;
	rip->daddr_l = ip->saddr_l;
	//rip->check = ones_complement_sum(rip, ntohs(ip->tot_len));
	rip->check = ntohs(0);
	acc = ones_complement_sum(rip, htons(rip->tot_len));
	rip->check = htons(acc);
	acc = 0;

	// udp
	memcpy(rudp->source, udp->dest, sizeof(u_int16_t));
	memcpy(rudp->dest, udp->source, sizeof(u_int16_t));
	rudp->len    = htons(ntohs(rip->tot_len) - sizeof(struct iphdr));
	// init checksum to zero to calcualate
	rudp->check = htons(0);
	// calculate checksum
	acc = ones_complement_sum(rudp, (ntohs(rip->tot_len) - sizeof(struct iphdr)));
	// put checksum in
	rudp->check = htons(acc);

	// dns
	memcpy(rdns, msg, sizeof(DnsHeader) + offset); // Push the internal buffer msg to pkt

	// send it
	nf_pktout_send(reply, reply + (htons(ioq->byte_length)) + sizeof(struct ioq_header)); 

		return rc;
	}//end else from opcode check

	//put header back in
	//RCODE,ANCOUNT,NSCOUNT,ARCOUNT,TIMELOOKUP,TIMETOTAL
	//log("%d,%d,%d,%d,", (int) fl.rcode, (int) head.ancount, (int) head.nscount, (int) head.arcount);
	//flagsToU16I(fl, &head.flags);
	//hdrToStr(msg, &head);
	//hdrToStr(pkt->head, &head);
	//send_dns(iface, ioq, eth, ip, udp, dnshdr, pkt, &msg)
	//sendto(udpSock, msg, PKT_SZ, 0, (struct sockaddr *) &cliSockAddr, cliLen);

	//etps = getTime();
	//teps = etps - stps;
	////TIMELOOKUP,TIMETOTAL
	//log("%lf,%lf\n", telu, teps);
	return -10;
}

//int process_udp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, DnsHeader *dns, t_addr *pkt)
int process_udp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, t_addr *pkt)
{
	struct udphdr *udp;
	int result;
	u_int16_t check;

	// New UDP header pointer
	udp = pkt_pull(pkt, sizeof(struct udphdr));

	// Most checks rely on pkt_buff structure and must be commented
//	log("Process UDP of size %u\n", pkt->len);
//	// check min size
//	if (pkt->len < 8)
//	{
//		return -4;
//	}
//
//	//struct udphdr *udp = pkt_pull(pkt, sizeof(struct udphdr));
//	udp = pkt_pull(pkt, sizeof(struct udphdr));
//
//	// verify checksum
//	//u_int16_t check = ones_complement_sum((char *)udp, pkt->len);
//	check = ones_complement_sum((char *)udp, pkt->len);
//	if (check != 0xFFFF)
//	{
//		log("Checksum failed %x\n", check);
//		return -5;
//	}

	if (htons(udp->dest) == UDP_PT)
	{
		log("Is DNS Query\n");
		//result = process_dns(iface, ioq, eth, ip, udp, dns, pkt);
		result = process_dns(iface, ioq, eth, ip, udp, pkt);
	}
	else
		result = 1;
	return result;
}

//int process_icmp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct icmphdr *icmp, t_addr *pkt)
int process_icmp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct pkt_buff *pkt)
{
	struct icmphdr *icmp;
	t_addr *reply;
	struct ether_header *reth;
	struct iphdr *rip;
	struct icmphdr *ricmp;
	u_int32_t acc;

	// New ICMP header pointer
	icmp = pkt_pull(pkt, sizeof(struct icmphdr));

	// allocate reply size
	reply = nf_pktout_alloc(ICMP_PKT_SIZE);

	// setup the ioq_header
	fill_ioq((struct ioq_header*) reply, 2, ICMP_PKT_SIZE);
	
	// setup the ethernet header
	reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

	// setup the ip header
	rip = (struct iphdr*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));

	// setup the icmp header	
	ricmp = (struct icmp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr));

	// start putting things into the packet
	// ethernet
	memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
	memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
	reth->ether_type = ETHERTYPE_IP;

	// ip
	rip->version_ihl = 0x45;
	rip->tos = ip->tos; // not sure about this one
	rip->tot_len = ip->tot_len;
	rip->id = ip->id + 12; // not sure about this one
	//rip->id = 1988; // not sure about this one
	rip->frag_off = ip->frag_off;
	rip->ttl = ip->ttl--;
	rip->protocol = IPPROTO_ICMP;
	rip->saddr_h = ip->daddr_h;
	rip->saddr_l = ip->daddr_l;
	rip->daddr_h = ip->saddr_h;
	rip->daddr_l = ip->saddr_l;
	rip->check = ntohs(0);
	acc = ones_complement_sum(rip, htons(ip->tot_len));
	rip->check = htons(acc);
	acc = 0;
	//rip->check = ~ones_complement_sum((char *)rip, 20);

	// fill icmp
	memcpy(ricmp, icmp, (ntohs(ip->tot_len) - sizeof(struct iphdr)));
	//memcpy(ricmp, icmp, (ntohs(ip->tot_len) - 20));
	ricmp->type = ICMP_ECHOREPLY;

	// init checksum to zero to calcualate
	ricmp->checksum = ntohs(0);

	// calculate checksum
	acc = ones_complement_sum(ricmp, (ntohs(ip->tot_len) - sizeof(struct iphdr)));
	//acc = ones_complement_sum(ricmp, (ntohs(ip->tot_len) - 20));

	// assign checksum
	ricmp->checksum = htons(acc);

	// send it
	nf_pktout_send(reply, reply + (htons(ioq->byte_length)) + sizeof(struct ioq_header)); 

	return 0;
}

//int process_ip(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct icmphdr *icmp, struct udphdr *udp, DnsHeader *dns, t_addr *pkt)
int process_ip(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct pkt_buff *pkt)
{
	int result;
	int ihl;
	int options_size;
	u_int16_t check;
	struct iphdr *ip;
	void *options;

	// New IP header pointer
	ip = pkt_pull(pkt, sizeof(struct iphdr));

	//Comment IP check, most use the pk_buff checks that couldn't get passed.
//	log("Process ip\n");
//	ip = pkt_pull(pkt, sizeof(struct iphdr));
//	if (!ip)
//	{
//		return -7;
//	}
//
//#ifndef DEBUG
//	ihl = ip->version_ihl&0xf;
//	if ((ip->version_ihl&0xf0) != 0x40 || ihl < 5)
//	{
//		return -8;
//	}
//#else
//	ihl = ip->ihl;
//	if (ip->version != 4 || ihl < 5)
//	{
//		return -8;
//	}
//#endif
//
//	//int options_size = ihl * 4 - sizeof(struct iphdr);
//	//void *options = pkt_pull(pkt, options_size);
//	options_size = ihl * 4 - sizeof(struct iphdr);
//	options = pkt_pull(pkt, options_size);
//	if (!options)
//	{
//		log("Options truncated. size=%d\n", options_size);
//		return -9;
//	}
//
//	// verify checksum
//	//u_int16_t check = ones_complement_sum((char *)ip, ihl * 4);
//	check = ones_complement_sum((char *)ip, ihl * 4);
//	if (check != 0xFFFF)
//	{
//		log("Checksum failed %x\n", check);
//		return -10;
//	}
//
//	if (ntohs(ip->tot_len) != ihl * 4 + pkt->len)
//	{
//		log("Packet data truncated %d instead of %d\n", ntohs(ip->tot_len), ihl * 4 + pkt->len);
//		return -11;
//	}
	
	switch (ip->protocol)
	{
		case IPPROTO_ICMP:
			//result = process_icmp(iface, ioq, eth, ip, icmp, pkt);
			result = process_icmp(iface, ioq, eth, ip, pkt);
			break;
		case IPPROTO_UDP:
			//result = process_udp(iface, ioq, eth, ip, udp, dns, pkt);
			result = process_udp(iface, ioq, eth, ip, pkt);
			break;
		default:
			result = 1;
			break;
	}
	return result;
}

//int process_arp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct ether_arp *etharp, t_addr *pkt)
int process_arp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct pkt_buff *pkt)
{
	unsigned short int my_hrd;
	unsigned short int my_pro;
	struct ether_arp *etharp;
	t_addr *reply;
	struct ether_header *reth;
	struct ether_arp *rarp;

	my_hrd = 6;		// set to mac(6)
	my_pro = 4;		// set to ipv4(4)

	// New ARP pointer
	etharp = pkt_pull(pkt, sizeof(struct ether_arp));

	// If we aren't getting a request or reply we don't care
	if(ntohs(etharp->ea_hdr.ar_hrd) != ARPHRD_ETHER || 
		ntohs(etharp->ea_hdr.ar_pro) !=  ETHERTYPE_IP ||
		etharp->ea_hdr.ar_hln != my_hrd ||
		etharp->ea_hdr.ar_pln != my_pro ||
		(
			ntohs(etharp->ea_hdr.ar_op) != ARPOP_REPLY &&
			ntohs(etharp->ea_hdr.ar_op) != ARPOP_REQUEST
		)
	)
	{
		return 1;
	}
	if(memcmp(htonl(etharp->arp_tpa), iface->ip, 4) == 0)
	{
		if(ntohs(etharp->ea_hdr.ar_op) == ARPOP_REQUEST)
		{
			// allocate reply size
			reply = nf_pktout_alloc(ARP_PKT_SIZE);

			// setup the ioq_header
			fill_ioq((struct ioq_header*) reply, 2, ARP_PKT_SIZE);

			// setup the ethernet header
			reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

			// setup the ethernet arp
			rarp = (struct ether_arp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));
		
			// start putting things into the packet
			// ethernet
			memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
			memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
			reth->ether_type = ETHERTYPE_ARP;

			// arp header
			rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
			rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
			rarp->ea_hdr.ar_hln = 6;
			rarp->ea_hdr.ar_pln = 4;
			rarp->ea_hdr.ar_op = htons(ARPOP_REPLY);

			// arp ethernet
				// source
			memcpy(rarp->arp_sha, iface->mac, ETH_ALEN);
			memcpy(rarp->arp_spa, iface->ip, 4);
				// target
			memcpy(rarp->arp_tha, etharp->arp_sha, ETH_ALEN);
			memcpy(rarp->arp_tpa, etharp->arp_spa, 4);

			// send it
			nf_pktout_send(reply, reply + ARP_PKT_SIZE); 
		}
	}
	return 0;
} 

int process_eth(struct net_iface *iface, t_addr *pkt)
{
	struct pkt_buff my_pkt; 
	int result;
	struct ioq_header *ioq;
	unsigned int size;
	struct ether_header *eth;
	//struct ether_arp *etharp;
	//struct iphdr *ip;
	//struct icmphdr *icmp;
	//struct udphdr *udp;
	//DnsHeader *dns;

	result = 0;

	ioq = pkt;
	size = ntohs(ioq->byte_length);

	pkt_fill(&my_pkt, pkt,  ntohs(ioq->byte_length) + sizeof(struct ioq_header));
	pkt_pull(&my_pkt, sizeof(struct ioq_header));
	eth = pkt_pull(&my_pkt, sizeof(struct ether_header));
	//eth = (struct ether_header*) (pkt + sizeof(struct ioq_header));
	switch (ntohs(eth->ether_type))
	{
		case ETHERTYPE_ARP:
			//etharp = (struct ether_arp*) (pkt + 
			//		sizeof(struct ioq_header) + 
			//		sizeof(struct ether_header));
			//result = process_arp(iface, ioq, eth, etharp, pkt);
			result = process_arp(iface, ioq, eth, &my_pkt);
			break;
		case ETHERTYPE_IP:
			//ip = (struct iphdr*) (pkt + 
			//		sizeof(struct ioq_header) + 
			//		sizeof(struct ether_header));
			//icmp = (struct icmphdr*) (pkt +
			//		sizeof(struct ioq_header) +
			//		sizeof(struct ether_header)+
			//		sizeof(struct iphdr));
			//udp = (struct udphdr*) (pkt +
			//		sizeof(struct ioq_header) +
			//		sizeof(struct ether_header)+
			//		sizeof(struct iphdr));
			//dns = (DnsHeader*) (pkt +
			//		sizeof(struct ioq_header) +
			//		sizeof(struct ether_header)+
			//		sizeof(struct iphdr) +
			//		sizeof(struct udphdr));
			//result = process_ip(iface, ioq, eth, ip, icmp, udp, dns, pkt);
			result = process_ip(iface, ioq, eth, &my_pkt);
		default:
			result = 1;
			break;
	}
	return result;
}

int main(void)
{
	t_addr *pkt;
	struct net_iface iface;
	struct ether_header *reth;
	struct ether_arp *rarp;
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];

	// iface is not shared, it's on the stack
	//00:4e:46:32:43:00
	//00:4e:46:32:43:01
	//00:4e:46:32:43:02
	//00:4e:46:32:43:03
	
	// iface is not shared, it's on the stack
	arp_init(&iface.arp);

	iface.mac[0] = 0x00;
	iface.mac[1] = 0x43;
	iface.mac[2] = 0x32;
	iface.mac[3] = 0x46;
	iface.mac[4] = 0x4e;
	iface.mac[5] = 0x00;

	iface.ip[0] = 192;
	iface.ip[1] = 168;
	iface.ip[2] = 0;
	iface.ip[3] = 100;

	dest_mac[0] = 0xff;
	dest_mac[1] = 0xff;
	dest_mac[2] = 0xff;
	dest_mac[3] = 0xff;
	dest_mac[4] = 0xff;
	dest_mac[5] = 0xff;

	dest_ip[0] = 192;
	dest_ip[1] = 168;
	dest_ip[2] = 0;
	dest_ip[3] = 1;

	//only run this program on thread 0
	if (nf_tid() != 0) 
	{
	   while (1) {}
	}
	
	// initialize
	nf_pktout_init();
	nf_pktin_init();

	// This is to just send an ARP request to router
	// allocate an output buffer
	pkt = nf_pktout_alloc(ARP_PKT_SIZE);

	// setup the ioq_header
	fill_ioq((struct ioq_header*) pkt, 2, ARP_PKT_SIZE);

	// setup the ethernet header
	reth = (struct ether_header*) (pkt + sizeof(struct ioq_header));
 
	// setup the ethernet arp
	rarp = (struct ether_arp*) (pkt + sizeof(struct ioq_header) + sizeof(struct ether_header));

	// start putting things into the packet
	// ethernet
	memcpy(reth->ether_shost, &iface.mac, ETH_ALEN);
	memcpy(reth->ether_dhost, &dest_mac, ETH_ALEN);
	reth->ether_type = ETHERTYPE_ARP;

	// arp header
	rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	rarp->ea_hdr.ar_hln = 6;
	rarp->ea_hdr.ar_pln = 4;
	rarp->ea_hdr.ar_op = htons(ARPOP_REQUEST);

	// arp ethernet
		// source
	memcpy(rarp->arp_sha, &iface.mac, ETH_ALEN);
	memcpy(rarp->arp_spa, &iface.ip, 4);
		// target
	memcpy(rarp->arp_tha, dest_mac, ETH_ALEN);
	memcpy(rarp->arp_tpa, dest_ip, 4);

	// send it
	nf_pktout_send(pkt, pkt + ARP_PKT_SIZE); 

//	dest_ip[0] = 192;
//	dest_ip[1] = 168;
//	dest_ip[2] = 0;
//	dest_ip[3] = 2;
//
//	// This is to just send an ARP request to switch
//	// allocate an output buffer
//	pkt = nf_pktout_alloc(ARP_PKT_SIZE);
//
//	// setup the ioq_header
//	fill_ioq((struct ioq_header*) pkt, 2, ARP_PKT_SIZE);
//
//	// setup the ethernet header
//	reth = (struct ether_header*) (pkt + sizeof(struct ioq_header));
// 
//	// setup the ethernet arp
//	rarp = (struct ether_arp*) (pkt + sizeof(struct ioq_header) + sizeof(struct ether_header));
//
//	// start putting things into the packet
//	// ethernet
//	memcpy(reth->ether_shost, &iface.mac, ETH_ALEN);
//	memcpy(reth->ether_dhost, &dest_mac, ETH_ALEN);
//	reth->ether_type = ETHERTYPE_ARP;
//
//	// arp header
//	rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
//	rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
//	rarp->ea_hdr.ar_hln = 6;
//	rarp->ea_hdr.ar_pln = 4;
//	rarp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
//
//	// arp ethernet
//		// source
//	memcpy(rarp->arp_sha, &iface.mac, ETH_ALEN);
//	memcpy(rarp->arp_spa, &iface.ip, 4);
//		// target
//	memcpy(rarp->arp_tha, dest_mac, ETH_ALEN);
//	memcpy(rarp->arp_tpa, dest_ip, 4);
//
//	// send it
//	nf_pktout_send(pkt, pkt + ARP_PKT_SIZE); 

	// start in on replying
	while(1)
	{
		pkt = nf_pktin_pop();  // test for next_packet
		if(!nf_pktin_is_valid(pkt))
			continue;

		process_eth(&iface, pkt);

		nf_pktin_free(pkt);
	} 

	// never reached
	return 0;
}
