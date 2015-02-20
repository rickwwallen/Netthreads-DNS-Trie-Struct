/*
 * * FILE NAME:		my_zone_read.c
 * * READS ZONE FILE AND PLACES ON NETFPGA MEMORY DRAM?
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
 * *		-Pulled readZone from triez_netfpga.c
 * */
/**********************************************************************/
#include "dns_netfpga.h"

/* F(X) TO TAKE IN STRING OF ZONE FILE NAME AND CREATE DB */
Trie *readZone(char *fn)
{
	FILE *fp;
	char buff;
	char domNme[DNM_SZ];
	char domNme2[DNM_SZ];
	char rR[LNE_SZ];
	char rR2[LNE_SZ];
	int i;
	uint32_t dTtl = 0; //default ttl gets redefined by SOA
	uint16_t dClass = 0; //default class gets redefined by SOA
	RR *rrs;
	Trie *root;

	root = createNode('*',  NULL);

	if((fp = fopen(fn, "r")) == NULL)
		return NULL;

	while(!feof(fp))
	{
		buff = fgetc(fp);
		if(buff == EOF)
			break;

		// If line is a comment then ignore it
		else if(buff == ';')
		{
			while(buff != '\n' && buff != EOF)
				buff = fgetc(fp);
		}

		// Read in Domain Name
		if(buff != '\t' && buff != ' ' && buff != '\n')
		{
			i = 0;
			strcpy(domNme,"");
			while(buff != ';' && buff != '(' && buff != '\t' && buff != ' ' && buff != EOF)
			{
				domNme[i] = buff;
				i++;
				buff = fgetc(fp);
			}
			domNme[i] = '\0';
			strcpy(domNme2, domNme);
			revDN(domNme);
		}

		// Read in Resource Record
		strcpy(rR2,"");
		while(buff != '\n' && buff != EOF)
		{
			if(buff == ';' || buff == '(');
			else
				buff = fgetc(fp);
			// Reached the beginning of a comment therefore ignore ignore the rest of the line
			if(buff == ';')
			{
				while(buff != '\n' && buff != EOF)
					buff = fgetc(fp);
			}
			// Reached the beginning of a multilined statement, this usually is with the SOA
			else if(buff == '(')
			{
				while(buff != ')')
				{
					// Reached the beginning of a comment so we can ignore the rest of the line
					if(buff == ';')
					{
						while(buff != '\n' && buff != EOF)
							buff = fgetc(fp);
					}
					buff = fgetc(fp);
					i = 0;
					strcpy(rR, "");
					while(buff != ';' && buff != ')' && buff != '\t' && buff != ' ' && buff != '\n' && buff != EOF)
					{
						rR[i] = buff;
						i++;
						buff = fgetc(fp);
					}
					rR[i] = '\0';
					if(strcmp(rR, "") != 0)
					{
						strcat(rR2, rR);
						strcat(rR2, ",");
					}
				}
			}
			else
			{
				i = 0;
				strcpy(rR, "");
				while(buff != ';' && buff != '(' && buff != '\t' && buff != ' ' && buff != '\n' && buff != EOF)
				{
					rR[i] = buff;
					i++;
					buff = fgetc(fp);
				}
				rR[i] = '\0';
				if(strcmp(rR, "" ) != 0)
				{
					strcat(rR2, rR);
					strcat(rR2, ",");
				}
			}
		}
		//This is where we call to make trie but before do we need to put the chars into RR's?
		if(strcmp(rR2, "") != 0)
		{
			rrs = createResRec(rR2, &dTtl, &dClass);
			if(rrs != NULL)
			{
				if(rrs->ptrrs != NULL)
					addTrie(root, domNme, rrs);
				else if(checkDN(domNme2) == 0)
					addTrie(root, domNme, rrs);
			}
		}

	}

	fclose(fp);
	return root;
}

