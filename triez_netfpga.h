/*
 * * FILE NAME:		triez_netfpga.h
 * * HEADER FILE FOR triez_netfpga.c
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	SEPTEMBER.29.2014
 * * DATE LAST MOD:	JANUARY.21.2015
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
 * *	September.29.2014-Adapted from triez.h
 * *	January.21.2015-Commented out readZone function prototype
 * */
/**********************************************************************/
#ifndef _TRIEZ_NETFPGA_
#define _TRIEZ_NETFPGA_ 1
//#include <arpa/inet.h>
#include "dns_netfpga.h"
/* F(X) PROTOTYPES */
/* F(X) TO DAEMONIZE THE SERVER */
//int daemonInit(const char *pname, int facility);

/* F(X) TO CHECK DOMAIN NAME DOESN'T CONTAIN INVALID CHARACTERS */
uint16_t checkDN(char *domName);
//int checkDN(char *domName);

/* F(X) TO CREATE A RESOUCE RECORD */
RR *createResRec(char *rec, uint32_t *ttlMin, uint16_t *rclass);

/* F(X) TO CREATE A NODE IN TRIE */
Trie *createNode(char k, RR *v);

/* F(X) TO ADD TO TRIE */
void addTrie(Trie *root, char *name, RR *resrec);

/* F(X) TO SEARCH TRIE */
Trie *searchTrie(Trie *root, char *search, uint16_t qt, uint16_t qc);

/* F(X) TO PULL NAME FROM TRIE */
void findN(char *dest, Trie *start);

/* F(X) TO ADD TO TRIE */
void delTrie(Trie *root);

/* F(X) TO PULL DATA FROM NODE AND RETRIEVE KEY */
void putResRecStr(DnsHdrFlags *fl, DnsHeader *head, Trie *root, Trie *result, DnsQuery *qry, char *msg, int *offset, char *search);

/*F(X) TO MAKE DOMAIN NAME UPPER CASE FOR SEARCHING */
void uDN(char *dom);

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
//Trie *readZone(char *f );

/* F(X) TO REVERSE DOMAIN NAME */
int revDN(char *DN);

/* F(X) PROTOTYPES */
uint16_t chSup(DnsType clType, DnsClass clClass);

#endif //end if triez_netfpga.h
