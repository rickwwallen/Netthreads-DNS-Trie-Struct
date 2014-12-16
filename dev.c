#include <string.h>
#include "dev.h"

//new device to exclude arp and include triez
void dev_init(struct net_iface *iface)
{
	memset(iface, 0, sizeof(struct net_iface));
	trie_init(&iface->Trie);
}
