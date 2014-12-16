#ifndef DEV_H
#define DEV_H

#include "arp.h"
#include "pktbuff.h"

struct net_iface
{
	unsigned char mac[6];
	unsigned char ip[4];

	Trie *root;
	RR *rr_root;
//some stuff

};

void dev_init(struct net_iface *iface);

#endif
