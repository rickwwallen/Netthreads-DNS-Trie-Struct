/*
 * * FILE NAME:		structs_netfpga.h
 * * STRUCTURES FOR THE DNS SERVER
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	SEPTEMBER.29.2014
 * * DATE LAST MOD:	JANUARY.28.2015
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
 * *	September.29.2014-Adapted from structs.h
 * *	January.28.2015-Altered structs containing IPv4 and IPv6 (in_addr and in6_addr)
 * */
/**********************************************************************/
#ifndef _STRUCTS_NETFPGA_
#define _STRUCTS_NETFPGA_ 1

//#include <arpa/inet.h>
#include "dns_netfpga.h"

/* Structures */
	/*Server Structs*/
/*
 * For use if ever switch to one client per thread
typedef struct cliInfo
{
	socklen_t		len;
	struct sockaddr_in	sockAddrInfo;
	char			msg[PKT_SZ];
	struct trieptr		*rt;
	double			start;
	FILE			*fptr;
}CliInfo;
*/
	/*Trie Structs*/
typedef struct trieptr
{
	char key;
	struct rr *val;
	struct trieptr *par;
	struct trieptr *snt;
	struct trieptr *spv;
	struct trieptr *cdn;
}Trie;

	/*Header Structs*/
typedef struct
{
	unsigned qr	: 1;
	unsigned opcode	: 4;
	unsigned aa	: 1;
	unsigned tc	: 1;
	unsigned rd	: 1;
	unsigned ra	: 1;
	unsigned z	: 3;
	unsigned rcode	: 4;
} DnsHdrFlags;

typedef struct
{
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
}DnsHeader;

	/*Record Structs*/
typedef struct
{
	uint16_t qtype;
	uint16_t qclass;
}DnsQuery;

typedef struct rr
{
	struct arec 	*ars;
	struct nsrec	*nsrs;
	struct cnamerec	*cnamers;
	struct ptrrec	*ptrrs;
	struct mxrec	*mxrs;
	struct aaaarec	*aaaars;
	struct soarec	*soars;
}RR;

typedef struct arec
{
	//struct in_addr	address;
	unsigned char address[4];

	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	rdlen;
	struct arec	*anxt;
} A;

typedef struct nsrec
{
	char		*nsdname;

	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	rdlen;
	struct nsrec	*nsnxt;
} NS;

typedef struct cnamerec
{
	char		*cname;

	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	rdlen;
} CNAME;

typedef struct soarec
{
	char 		*mname;
	char		*rname;
	uint32_t	serial;
	int32_t		refresh;
	int32_t		retry;
	int32_t		expire;
	uint32_t	minimum;

	uint16_t	rclass;
	uint16_t	rdlen;
} SOA;

typedef struct ptrrec
{
	char		*ptrdname;

	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	rdlen;
} PTR;

typedef struct mxrec
{
	uint16_t	preference;
	char		*exchange;

	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	rdlen;
	struct mxrec	*mxnxt;
} MX;

typedef struct aaaarec
{
	//struct in6_addr	address;
	unsigned char address[16];

	uint16_t	rclass;
	int32_t		ttl;
	uint16_t	rdlen;
	struct aaaarec	*aaaanxt;
} AAAA;

typedef enum
{
	a = 1,
	ns,
	md,
	mf,
	cname,
	soa,
	mb,
	mg,
	mr,
	null,
	wks,
	ptr,
	hinfo,
	minfo,
	mx,
	txt,
	aaaa = 28,
	axfr = 252,
	mailb,
	maila,
	allTypes
}DnsType;

typedef enum
{
	in = 1,
	cs,
	ch,
	hs,
	allClasses = 255
}DnsClass;

#endif //end if structs_netfpga.h
