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
 * */
/**********************************************************************/
//#include "structs_netfpga.h"
#include "dns_netfpga.h"
#include "my_inet.c"
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

int send_pkt(char* data, unsigned len)
{
	nf_pktout_send(data, &(data[len]));
	return len;
}

u_int16_t ones_complement_sum(char *data, int len)
{
	u_int32_t sum = 0;
	while (len > 1)
	{
		/*  This is the inner loop */
		sum += * (unsigned short*) data;
		data += 2;
		len -= 2;
	}

	/*  Add left-over byte, if any */
	if( len > 0 )
		sum += * (unsigned char *) data;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (u_int16_t) sum;
}

// Send Answer/Response to the DNS Query
//int send_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, DnsHeader dnshdr, struct pkt_buff *pkt, char *msg)
int send_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, DnsHeader *dnshdr, struct pkt_buff *pkt)
{
	struct pkt_buff reply;
	struct ioq_header *rioq;
	unsigned short reply_bytes;
	struct ether_header *reth;
	struct iphdr *rip;
	struct udphdr *rudp;
	DnsHeader *rdns;
	u_int32_t acc;

	// Create and send a reply.
	if (pkt_alloc(&reply,
		sizeof(struct ioq_header) +
		sizeof(struct ether_header) +
		sizeof(struct iphdr) +
		sizeof(struct udphdr) +
		sizeof(DnsHeader) +
		pkt->len) == 0)
	{
	  return -15;
	}

	//struct ioq_header *rioq = pkt_pull(&reply, sizeof(struct ioq_header));
	//unsigned short reply_bytes = (unsigned short) reply.len;
	//struct ether_header *reth = pkt_pull(&reply, sizeof(struct ether_header));
	//struct iphdr *rip = pkt_pull(&reply, sizeof(struct iphdr));
	//struct udphdr *rudp = pkt_pull(&reply, sizeof(struct udphdr));
	//DnsHeader *rdns = pkt_pull(&reply, sizeof(DnsHeader));

	rioq		= pkt_pull(&reply, sizeof(struct ioq_header));
	reply_bytes	= (unsigned short) reply.len;
	reth		= pkt_pull(&reply, sizeof(struct ether_header));
	rip		= pkt_pull(&reply, sizeof(struct iphdr));
	rudp		= pkt_pull(&reply, sizeof(struct udphdr));
	rdns		= pkt_pull(&reply, sizeof(DnsHeader));

	fill_ioq(rioq, ioq->src_port, reply_bytes);

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
	rip->tot_len = htons(20 + pkt->len);
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
	rip->check = ~ones_complement_sum((char *)rip, 20);

	// fill udp, base it on udp request
	//memcpy(rudp, udp, pkt->len);
	rudp->source = udp->dest;
	rudp->dest   = udp->source;
	rudp->len    = htons(pkt->len + sizeof(struct udphdr));

	// update checksum instead of recompute
	//u_int32_t acc = (u_int32_t) ~ntohs(rudp->checksum) + (u_int32_t) ~0x0400;
	acc = (u_int32_t) ~ntohs(rudp->check) + (u_int32_t) ~0x0400;
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	rudp->check = htons(~acc);

	// fill dns
	memcpy(rdns, pkt->head, pkt->len);

	// Push and Send
	pkt_push_all(&reply);
	send_pkt(reply.data, reply.len);

	return 1;
}

// Process DNS Query
int process_dns(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct udphdr *udp, struct pkt_buff *pkt)
{
	DnsHeader *dnshdr;		// DNS header pointer
	DnsHeader head;			// Hold header information
	DnsHdrFlags fl;			// Hold flag information
	DnsQuery qry[QRY_NO];		// Holds all the queries' qtype and qclass
	//Trie *root;			// Holds the start of the trie structure
	//Trie *result;			// Holds the node that search returns
	char msg[PKT_SZ];		// Messages sent to and from server
	char nme[DNM_SZ];		// Name
	char dmn[DNM_SZ][QRY_NO];	// Holds all the queries' domain names
	int offset = 0;			// Offset of message parsing
	int qdc = QRY_NO;		// Number of queries allowed in message
	int i = 0;
	int rc = 0;			// Return Code

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

	//DnsHeader *dnshdr = pkt_pull(pkt, sizeof(DnsHeader));
	memcpy(msg, pkt->head, pkt->len);
	dnshdr = pkt_pull(pkt, sizeof(DnsHeader));

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
		hdrToStr(pkt->head, &head);

		// Push to f(x) to build the DNS Response
		//rc=send_dns(iface, ioq, eth, ip, udp, dnshdr, pkt, &msg);
		memcpy(dnshdr, msg, offset); // Push the internal buffer msg to pkt
		pkt_push(pkt, sizeof(DnsHeader));
		pkt->len = offset;
		rc=send_dns(iface, ioq, eth, ip, udp, dnshdr, pkt);

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

int process_udp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct pkt_buff *pkt)
{
	int rc = 0;
	u_int16_t check;
	struct udphdr *udp;

	log("Process UDP of size %u\n", pkt->len);
	// check min size
	if (pkt->len < 8)
	{
		return -4;
	}

	//struct udphdr *udp = pkt_pull(pkt, sizeof(struct udphdr));
	udp = pkt_pull(pkt, sizeof(struct udphdr));

	// verify checksum
	//u_int16_t check = ones_complement_sum((char *)udp, pkt->len);
	check = ones_complement_sum((char *)udp, pkt->len);
	if (check != 0xFFFF)
	{
		log("Checksum failed %x\n", check);
		return -5;
	}

	if (udp->dest == UDP_PT)
	{
		log("Is DNS Query\n");
		rc = process_dns(iface, ioq, eth, ip, udp, pkt);
		return rc;
	}
	return -6;
}

int process_ip(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct pkt_buff *pkt)
{
	int result = -12;
	int ihl = 0;
	int options_size;
	u_int16_t check;
	struct iphdr *ip;
	void *options;

	log("Process ip\n");

	//struct iphdr *ip = pkt_pull(pkt, sizeof(struct iphdr));
	ip = pkt_pull(pkt, sizeof(struct iphdr));
	if (!ip)
	{
		return -7;
	}

#ifndef DEBUG
	ihl = ip->version_ihl&0xf;
	if ((ip->version_ihl&0xf0) != 0x40 || ihl < 5)
	{
		return -8;
	}
#else
	ihl = ip->ihl;
	if (ip->version != 4 || ihl < 5)
	{
		return -8;
	}
#endif

	//int options_size = ihl * 4 - sizeof(struct iphdr);
	//void *options = pkt_pull(pkt, options_size);
	options_size = ihl * 4 - sizeof(struct iphdr);
	options = pkt_pull(pkt, options_size);
	if (!options)
	{
		log("Options truncated. size=%d\n", options_size);
		return -9;
	}

	// verify checksum
	//u_int16_t check = ones_complement_sum((char *)ip, ihl * 4);
	check = ones_complement_sum((char *)ip, ihl * 4);
	if (check != 0xFFFF)
	{
		log("Checksum failed %x\n", check);
		return -10;
	}

	if (ntohs(ip->tot_len) != ihl * 4 + pkt->len)
	{
		log("Packet data truncated %d instead of %d\n", ntohs(ip->tot_len), ihl * 4 + pkt->len);
		return -11;
	}

	switch (ip->protocol)
	{
		case IPPROTO_UDP:
			result = process_udp(iface, ioq, eth, ip, pkt);
			break;
	}
	return result;
}

void process_pkt(struct net_iface *iface, void* data)
{
	//volatile char* testp = data;
	struct pkt_buff pkt;
	struct ioq_header *ioq = data;
	unsigned int size = ntohs(ioq->byte_length);
	int result = 0;
	//size = size + ioq->word_length;

	log("ioq_hdr: dst=%hx words=%hu src=%hu bytes=%hu\n", ntohs(ioq->dst_port), ntohs(ioq->word_length), ntohs(ioq->src_port), size);
	pkt_fill(&pkt, data, size + sizeof(struct ioq_header));

	pkt_pull(&pkt, sizeof(struct ioq_header));
	struct ether_header *eth = pkt_pull(&pkt, ETHER_HDR_LEN);
	if (eth)
	{
#ifdef CONTEXT_SIM
	log("dest: "); print_mac(eth->ether_dhost); log("\n");
	log("source: "); print_mac(eth->ether_shost); log("\n");
	log("eth_proto: %hx\n", ntohs(eth->ether_type));
#endif

		switch (ntohs(eth->ether_type))
		{
			case ETHERTYPE_IP:
				result = process_ip(iface, ioq, eth, &pkt);
				break;
			default:
				result = -13;
				break;
		}
	}

	// We failed to send a reply for some reason. Echo the packet
	if (result <= 0)
	{
		char* ptr;
		struct pkt_buff reply;
		struct ioq_header *dioq;

		pkt_push_all(&pkt);
		if (pkt_alloc(&reply, pkt.len) == 0) return;

		dioq = (struct ioq_header *)pkt_pull(&reply, sizeof(struct ioq_header));
		fill_ioq(dioq, ioq->src_port, ioq->byte_length);

		memcpy(reply.head,
		       (char*)pkt.data + sizeof(struct ioq_header),
		       reply.len);

		ptr = (char*)reply.head;
		ptr[0] = -result;
		log("Set result %d\n", -result);

		send_pkt(reply.data, reply.total_size);
 	}
}

int main(void)
{
	struct net_iface iface;
	int mytid = nf_tid();

	if(mytid != 0)
	{
		nf_stall_a_bit();
		nf_lock(LOCK_INIT); // should not get it
	}
	else
	{
#ifndef DEBUG
	nf_lock(LOCK_INIT); // should get it on the first attempt
	nf_pktout_init();
	nf_pktin_init();
#endif
		//sp_init_mem_single();	// initialize the multithreaded memory allocator

		// perform memory allocation for initialization purposes
		// only use sp_free() and sp_malloc()
		// two implementations of these functions exists. If you prefer the STANDARD_MALLOC
		// from ../common/memory.c, you should not perform sp_init_mem_single() nor sp_init_mem_pool().

		// finalize the initialization of the multithreaded memory allocator
		// since each thread allocates from its private head and adds to its heap
		// upon memory free, the heaps can get unbalanced if care is not taken
		//sp_init_mem_pool();
	}
	nf_unlock(LOCK_INIT);


	// iface is not shared, it's on the stack
	//00:4e:46:32:43:00
	//00:4e:46:32:43:01
	//00:4e:46:32:43:02
	//00:4e:46:32:43:03
	
	arp_init(&iface.arp);
	
	iface.mac[0] = 0x00;
	iface.mac[1] = 0x4e;
	iface.mac[2] = 0x46;
	iface.mac[3] = 0x32;
	iface.mac[4] = 0x43;
	iface.mac[5] = 0x00;
	
	iface.ip[0] = 192;
	iface.ip[1] = 168;
	iface.ip[2] = 0;
	iface.ip[3] = 110;

	while(1)
	{
		// get the time if you need it
		//uint t = nf_time();	// 32-bit unsigned wrap-around time

		nf_lock(LOCK_DS0);	 // valid lock identifiers are integers from 0 to 15 inclusively
		// do some synchronized action here
		nf_unlock(LOCK_DS0);

		t_addr* next_packet = nf_pktin_pop();	// get the next available packet, this is non-blocking call

		// test if we have a packet
		if (nf_pktin_is_valid(next_packet))
		{
			// process the packet
			process_pkt(&iface, next_packet);
			nf_pktin_free(next_packet);	// free this packet from the input memory
		}
	}

	// rever reached
	return 0;
}
