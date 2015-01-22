/*
 * * FILE NAME:		my_zone_read.h
 * * HEADER FILE FOR my_zone_read.c
 * * CREATED BY:	RICK W. WALLEN
 * * DATE CREATED:	JANUARY.21.2015
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
 * *	January.21.2015-Initial create
 * *		-Pulled readZone function prototype from triez_netfpga.h
 * */
/**********************************************************************/
#ifndef _ZONE_READ_NETFPGA_
#define _ZONE_READ_NETFPGA_ 1

#include "dns_netfpga.h"

/* F(X) PROTOTYPES */
/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
Trie *readZone(char *f );

#endif //end if my_zone_read.h
