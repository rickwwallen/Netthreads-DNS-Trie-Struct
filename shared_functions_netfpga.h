/*
 * * FILE NAME: shared_functions_netfpga.h
 * * HEADER FILE FOR shared_functions_netfpga.c
 * * CREATED BY:   RICK W. WALLEN
 * * DATE CREATED:	SEPTEMBER.29.2014
 * * DATE LAST MOD:	APRIL.24.2015
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
 * *	September.29.2014-Adapted from shared_functions.h
 * *	November.10.2014-Removed print functions
 * *	April.23.2015-Added mytolower
 * */
/**********************************************************************/
#ifndef _SHARED_FUNCTIONS_NETFPGA_
#define _SHARED_FUNCTIONS_NETFPGA_ 1
#include "dns_netfpga.h"

/* FUNCTION PROTOTYPES */
/* F(X) PUT QUERY IN STRING TO SEND UDP */
int qryToStr(char *dest, DnsQuery *org1, char *org2, int *offset);

/* F(X) PULL QUERY FROM STRING IN UDP */
int strToQry(char *org, DnsQuery *dest1, char *dest2, int *offset);

/* F(X) PUT HEADER IN STRING TO SEND UDP */
int hdrToStr(char *dest, DnsHeader *org);

/* F(X) PUT STRING TO HEADER FROM UDP */
int strToHdr(char *org, DnsHeader *dest);

/* F(X) CONVERT DNS NAME FROM STD NOTATION TO QUERY NOTATION PER UNIVERSAL USE*/
int conDnsNameToSend(char *org, char *dest);

/*F(X) CONVERT DNS NAME FROM QUERY TO STD NOTATION */
void conDnsNameToPars(char *org, char *dest);

/*F(X) CONVERT DNS FLAGS TO 16BIT INT */
int flagsToU16I(DnsHdrFlags fg, uint16_t *hdr);

/*F(X) CONVERT 16 BIT INT FLAG INTO DNS FLAGS */
int u16IToFlags(DnsHdrFlags *fg, uint16_t hdr);

/* F(X) TO CHECK NUMERIC */
int myisdigit(char chk);

/* F(X) TO CHECK ALPHABIT */
int myisalpha(char chk);

/* F(X) TO CHECK ALPHA-NUMERIC */
int myisalnum(char chk);

/* F(X) TO CHANGE CHAR TO UPPERCASE */
char mytoupper(char chk);

/* F(X) TO CHANGE CHAR TO LOWERCASE */
char mytolower(char chk);

#endif //end if shared_functions_netfpga.h
