/*
 * * FILE NAME: shared_functions_netfpga.c
 * * ONLY CONTAIN NETFPGA SERVER FUNCTIONS DUE TO LIMITED C FUNCTIONS USED
 * * CREATED BY:   RICK W. WALLEN
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
 * *	September.29.2014-Adapted from sharedFunctions.c
 * *	November.10.2014-Removed print functions
 * *		-
 * */
/**********************************************************************/
#include "shared_functions_netfpga.h"
#include "dns_netfpga.h"

/* F(X) FOR TIMESTAMPS */
double getTime()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec*1e-6;
}

/* F(X) PUT QUERY IN STRING TO SEND UDP */
int qryToStr(char *dest, DnsQuery *org1, char *org2, int *offset)
{
	int offs = 0;

	offs = conDnsNameToSend(org2, dest);
	//strcpy(dest,org2);
	//offs = strlen(org2);

	org1->qtype = htons(org1->qtype);
	org1->qclass = htons(org1->qclass);

	memcpy((void *) (dest+offs), (void *) &org1->qtype, sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);
	memcpy((void *) (dest+offs), (void *) &org1->qclass, sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);
	(*offset) = *offset + offs;
	return 0;
}

/* F(X) PULL QUERY FROM STRING IN UDP */
int strToQry(char *org, DnsQuery *dest1, char *dest2, int *offset)
{
	int offs = 0;
	char buff[DNM_SZ];

	strcpy(buff, org);
	conDnsNameToPars(buff, dest2);
	offs = strlen(dest2) + 1;

	memcpy((void *) &dest1->qtype, (void *) (org+offs), sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);
	memcpy((void *) &dest1->qclass, (void *) (org+offs), sizeof(uint16_t));
	offs = offs + sizeof(uint16_t);

        dest1->qtype = ntohs(dest1->qtype);
        dest1->qclass = ntohs(dest1->qclass);

	(*offset) = *offset + offs;

	return 0;
}

/* F(X) PUT HEADER IN STRING TO SEND UDP */
int hdrToStr(char *dest, DnsHeader *org)
{
	org->id      = htons(org->id);
	org->flags   = htons(org->flags);
	org->qdcount = htons(org->qdcount);
	org->ancount = htons(org->ancount);
	org->nscount = htons(org->nscount);
	org->arcount = htons(org->arcount);

	memcpy((void *) dest, (void *) &org->id, sizeof(uint16_t));
	memcpy((void *) (dest+sizeof(uint16_t)), (void *) &org->flags, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*2)), (void *) &org->qdcount, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*3)), (void *) &org->ancount, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*4)), (void *) &org->nscount, sizeof(uint16_t));
	memcpy((void *) (dest+(sizeof(uint16_t)*5)), (void *) &org->arcount, sizeof(uint16_t));

	return 0;
}

/* F(X) PUT STRING TO HEADER FROM UDP */
int strToHdr(char *org, DnsHeader *dest)
{
	memcpy((void *) &dest->id, (void *) org, sizeof(uint16_t));
	memcpy((void *) &dest->flags, (void *) (org+sizeof(uint16_t)), sizeof(uint16_t));
	memcpy((void *) &dest->qdcount, (void *) (org+(sizeof(uint16_t)*2)), sizeof(uint16_t));
	memcpy((void *) &dest->ancount, (void *) (org+(sizeof(uint16_t)*3)), sizeof(uint16_t));
	memcpy((void *) &dest->nscount, (void *) (org+(sizeof(uint16_t)*4)), sizeof(uint16_t));
	memcpy((void *) &dest->arcount, (void *) (org+(sizeof(uint16_t)*5)), sizeof(uint16_t));

	dest->id      = ntohs(dest->id);
	dest->flags   = ntohs(dest->flags);
	dest->qdcount = ntohs(dest->qdcount);
	dest->ancount = ntohs(dest->ancount);
	dest->nscount = ntohs(dest->nscount);
	dest->arcount = ntohs(dest->arcount);

	return 0;
}

/* F(X) CONVERT DNS NAME FROM STD NOTATION TO QUERY NOTATION PER UNIVERSAL USE*/
int conDnsNameToSend(char *org, char *dest)
{
	int cnt;
	int i;
	int plc;

	cnt = 0;
	plc = 0;

	if((strlen(org) == 1) && (org[0] == '.'))
	{
		dest[0] = (uint8_t) 0;
		return 2;
	}
	for(i = 0; i <= strlen(org); i++)
	{
		if((org[i] == '.') || (org[i] == '\0'))
		{
			dest[plc] = (uint8_t) cnt;
			plc = i+1;
			if(cnt != 0)
			{
				dest[plc] = (uint8_t) 0;
			}
			cnt = 0;
		}
		else
		{
			dest[i+1] = org[i];
			cnt++;
		}
	}
	if(org[strlen(org)-1] != '.')
	{
		i++;
		dest[i] = (uint8_t) 0;
	}

	return i;
}

/*F(X) CONVERT DNS NAME FROM QUERY TO STD NOTATION */
void conDnsNameToPars( char *org, char *dest )
{
	uint8_t cnt;
	cnt = (uint8_t) *org++;

	if(cnt == 0)
	{
		*dest++ = '.';
		*dest++ = '\0';
		return;
	}
	while(cnt != 0)
	{
		cnt--;
		if(cnt == 0)
		{
			*dest++ = *org++;
			*dest++ = '.';
			cnt = (uint8_t) *org++;
		}
		else
			*dest++ = *org++;
	}
	*dest++ = '\0';

	return;
}

/*F(X) CONVERT DNS FLAGS TO 16BIT INT */
int flagsToU16I(DnsHdrFlags fg, uint16_t *hdr)
{
	*hdr = 0;
	*hdr   |= (((uint16_t) fg.qr) << 15)
		| (((uint16_t) fg.opcode) << 11)
		| (((uint16_t) fg.aa) << 10)
		| (((uint16_t) fg.tc) << 9)
		| (((uint16_t) fg.rd) << 8)
		| (((uint16_t) fg.ra) << 7)
		| (((uint16_t) fg.z) << 4)
		| (((uint16_t) fg.rcode) << 0);

	return 0;
}

/*F(X) CONVERT 16 BIT INT FLAG INTO DNS FLAGS */
int u16IToFlags(DnsHdrFlags *fg, uint16_t hdr)
{
	fg->qr		= 0;
	fg->opcode	= 0;
	fg->aa		= 0;
	fg->tc		= 0;
	fg->rd		= 0;
	fg->ra		= 0;
	fg->z		= 0;
	fg->rcode	= 0;

	fg->qr     |= (0x0001 & (hdr >> 15));
	fg->opcode |= (0x000F & (hdr >> 11));
	fg->aa     |= (0x0001 & (hdr >> 10));
	fg->tc     |= (0x0001 & (hdr >> 9));
	fg->rd     |= (0x0001 & (hdr >> 8));
	fg->ra     |= (0x0001 & (hdr >> 7));
	fg->z      |= (0x0007 & (hdr >> 4));
	fg->rcode  |= (0x000F & (hdr >> 0));

	return 0;
}

/* F(X) TO CHECK NUMERIC */
int myisdigit(char chk)
{
	if( (chk == '0')
	 || (chk == '1')
	 || (chk == '2')
	 || (chk == '3')
	 || (chk == '4')
	 || (chk == '5')
	 || (chk == '6')
	 || (chk == '7')
	 || (chk == '8')
	 || (chk == '9'))
		return 0;
	else
		return 1;
}

/* F(X) TO CHECK ALPHABIT */
int myisalpha(char chk)
{
	if( (chk == 'a')
	 || (chk == 'b')
	 || (chk == 'c')
	 || (chk == 'd')
	 || (chk == 'e')
	 || (chk == 'f')
	 || (chk == 'g')
	 || (chk == 'h')
	 || (chk == 'i')
	 || (chk == 'j')
	 || (chk == 'k')
	 || (chk == 'l')
	 || (chk == 'm')
	 || (chk == 'n')
	 || (chk == 'o')
	 || (chk == 'p')
	 || (chk == 'q')
	 || (chk == 'r')
	 || (chk == 's')
	 || (chk == 't')
	 || (chk == 'u')
	 || (chk == 'v')
	 || (chk == 'w')
	 || (chk == 'x')
	 || (chk == 'y')
	 || (chk == 'z')
	 || (chk == 'A')
	 || (chk == 'B')
	 || (chk == 'C')
	 || (chk == 'D')
	 || (chk == 'E')
	 || (chk == 'F')
	 || (chk == 'G')
	 || (chk == 'H')
	 || (chk == 'I')
	 || (chk == 'J')
	 || (chk == 'K')
	 || (chk == 'L')
	 || (chk == 'M')
	 || (chk == 'N')
	 || (chk == 'O')
	 || (chk == 'P')
	 || (chk == 'Q')
	 || (chk == 'R')
	 || (chk == 'S')
	 || (chk == 'T')
	 || (chk == 'U')
	 || (chk == 'V')
	 || (chk == 'W')
	 || (chk == 'X')
	 || (chk == 'Y')
	 || (chk == 'Z'))
		return 0;
	else
		return 1;
}

/* F(X) TO CHECK ALPHA-NUMERIC */
int myisalnum(char chk)
{
	if( (chk == '0')
	 || (chk == '1')
	 || (chk == '2')
	 || (chk == '3')
	 || (chk == '4')
	 || (chk == '5')
	 || (chk == '6')
	 || (chk == '7')
	 || (chk == '8')
	 || (chk == '9')
	 || (chk == 'a')
	 || (chk == 'b')
	 || (chk == 'c')
	 || (chk == 'd')
	 || (chk == 'e')
	 || (chk == 'f')
	 || (chk == 'g')
	 || (chk == 'h')
	 || (chk == 'i')
	 || (chk == 'j')
	 || (chk == 'k')
	 || (chk == 'l')
	 || (chk == 'm')
	 || (chk == 'n')
	 || (chk == 'o')
	 || (chk == 'p')
	 || (chk == 'q')
	 || (chk == 'r')
	 || (chk == 's')
	 || (chk == 't')
	 || (chk == 'u')
	 || (chk == 'v')
	 || (chk == 'w')
	 || (chk == 'x')
	 || (chk == 'y')
	 || (chk == 'z')
	 || (chk == 'A')
	 || (chk == 'B')
	 || (chk == 'C')
	 || (chk == 'D')
	 || (chk == 'E')
	 || (chk == 'F')
	 || (chk == 'G')
	 || (chk == 'H')
	 || (chk == 'I')
	 || (chk == 'J')
	 || (chk == 'K')
	 || (chk == 'L')
	 || (chk == 'M')
	 || (chk == 'N')
	 || (chk == 'O')
	 || (chk == 'P')
	 || (chk == 'Q')
	 || (chk == 'R')
	 || (chk == 'S')
	 || (chk == 'T')
	 || (chk == 'U')
	 || (chk == 'V')
	 || (chk == 'W')
	 || (chk == 'X')
	 || (chk == 'Y')
	 || (chk == 'Z'))
		return 0;
	else
		return 1;
}

/* F(X) TO CHANGE CHAR TO UPPERCASE */
char mytoupper(char chk)
{
	char res;
	switch(chk)
	{
		case	'a':
			res = 'A';
			break;
		case	'b':
			res = 'B';
			break;
		case	'c':
			res = 'C';
			break;
		case	'd':
			res = 'D';
			break;
		case	'e':
			res = 'E';
			break;
		case	'f':
			res = 'F';
			break;
		case	'g':
			res = 'G';
			break;
		case	'h':
			res = 'H';
			break;
		case	'i':
			res = 'I';
			break;
		case	'j':
			res = 'J';
			break;
		case	'k':
			res = 'K';
			break;
		case	'l':
			res = 'L';
			break;
		case	'm':
			res = 'M';
			break;
		case	'n':
			res = 'N';
			break;
		case	'o':
			res = 'O';
			break;
		case	'p':
			res = 'P';
			break;
		case	'q':
			res = 'Q';
			break;
		case	'r':
			res = 'R';
			break;
		case	's':
			res = 'S';
			break;
		case	't':
			res = 'T';
			break;
		case	'u':
			res = 'U';
			break;
		case	'v':
			res = 'V';
			break;
		case	'w':
			res = 'W';
			break;
		case	'x':
			res = 'X';
			break;
		case	'y':
			res = 'Y';
			break;
		case	'z':
			res = 'Z';
			break;
		default:
			res = chk;
			break;
	}
	return res;
}
