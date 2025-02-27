/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: ip_black_list(struct sr_ip_hdr *iph)
* Scope:  Local
*
* This method is called each time the sr_handlepacket() is called.
* Block IP addresses in the blacklist and print the log.
* - Format : "[IP blocked] : <IP address>"
* - e.g.) [IP blocked] : 10.0.2.100
*
*---------------------------------------------------------------------*/
int ip_black_list(struct sr_ip_hdr *iph)
{
	int blk = 0;
	char ip_blacklist[20] = "10.0.2.0"; /* DO NOT MODIFY */
	char mask[20] = "255.255.255.0"; /* DO NOT MODIFY */
	/**************** fill in code here *****************/
	/* source address, destination address, subnet mask, static blacklist IP */
	uint32_t src = ntohl(iph->ip_src);
	uint32_t dst = ntohl(iph->ip_dst);
	uint32_t submask = (255 << 24) | (255 << 16) | (255 << 8);
	uint32_t blacklist = (10 << 24) | (2 << 8);

	/* Calculate blk */
	blk = (((src & submask) == blacklist) || ((dst & submask) == blacklist)) ? 1 : 0;

	/* blk == 1, Block IP, print the log */
	if (blk == 1) {
		fprintf(stderr, "[IP blocked] : ");
		if((src & submask) == blacklist) {
			print_addr_ip_int(src);
		} else {
			print_addr_ip_int(dst);
		}
	}
	/****************************************************/
	return blk;
}
/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope:  Global
*
* This method is called each time the router receives a packet on the
* interface.  The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr,
					 uint8_t *packet /* lent */,
					 unsigned int len,
					 char *interface /* lent */)
{

	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

    /*
        We provide local variables used in the reference solution.
        You can add or ignore local variables.
    */
	uint8_t *new_pck;	  /* new packet */
	unsigned int new_len; /* length of new_pck */

	unsigned int len_r; /* length remaining, for validation */
	uint16_t checksum;	/* checksum, for validation */

	struct sr_ethernet_hdr *e_hdr0, *e_hdr; /* Ethernet headers */
	struct sr_ip_hdr *i_hdr0, *i_hdr;		/* IP headers */
	struct sr_arp_hdr *a_hdr0, *a_hdr;		/* ARP headers */
	struct sr_icmp_hdr *ic_hdr0;			/* ICMP header */
	struct sr_icmp_t0_hdr *ict0_hdr;		/* ICMP type0 header */
	struct sr_icmp_t3_hdr *ict3_hdr;		/* ICMP type3 header */
	struct sr_icmp_t11_hdr *ict11_hdr;		/* ICMP type11 header */

	struct sr_if *ifc;			  /* router interface */
	uint32_t ipaddr;			  /* IP address */
	struct sr_rt *rtentry;		  /* routing table entry */
	struct sr_arpentry *arpentry; /* ARP table entry in ARP cache */
	struct sr_arpreq *arpreq;	  /* request entry in ARP cache */
	struct sr_packet *en_pck;	  /* encapsulated packet in ARP cache */

	/* validation */
	if (len < sizeof(struct sr_ethernet_hdr))
		return;
	len_r = len - sizeof(struct sr_ethernet_hdr);
	e_hdr0 = (struct sr_ethernet_hdr *)packet; /* e_hdr0 set */

	/* IP packet arrived */
	if (e_hdr0->ether_type == htons(ethertype_ip))
	{
		/* validation */
		if (len_r < sizeof(struct sr_ip_hdr))
			return;

		len_r = len_r - sizeof(struct sr_ip_hdr);
		i_hdr0 = (struct sr_ip_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* i_hdr0 set */

		if (i_hdr0->ip_v != 0x4)
			return;

		checksum = i_hdr0->ip_sum;
		i_hdr0->ip_sum = 0;
		if (checksum != cksum(i_hdr0, sizeof(struct sr_ip_hdr)))
			return;
		i_hdr0->ip_sum = checksum;

		/* check destination */
		for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next)
		{
			if (i_hdr0->ip_dst == ifc->ip) {
				fprintf(stderr, "i_hdr0->ip_dst:");
				print_addr_ip_int(ntohl(i_hdr0->ip_dst));
				break;
			}
		}

		/* check ip black list */
		if (ip_black_list(i_hdr0))
		{
			/* Drop the packet */
			return;
		}

		/* destined to router interface */
		if (ifc != NULL)
		{
			/* with ICMP */
			if (i_hdr0->ip_p == ip_protocol_icmp)
			{
				/* validation */
				if (len_r < sizeof(struct sr_icmp_hdr))
					return;

				ic_hdr0 = (struct sr_icmp_hdr *)(((uint8_t *)i_hdr0) + sizeof(struct sr_ip_hdr)); /* ic_hdr0 set */

				/* echo request type */
				if (ic_hdr0->icmp_type == 0x08)
				{
					/* generate ICMP echo reply packet*/
					new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t0_hdr);
					new_pck = (uint8_t *) calloc(1, new_len);

					/* validation */
					checksum = ic_hdr0->icmp_sum;
					ic_hdr0->icmp_sum = 0;
					if (checksum != cksum(ic_hdr0, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)))
						return;
					ic_hdr0->icmp_sum = checksum;

					/**************** fill in code here *****************/
					e_hdr = (struct sr_ethernet_hdr *)new_pck; /* e_hdr set */
					i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr)); /* i_hdr set */
					ict0_hdr = (struct sr_icmp_t0_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); /* ict0_hdr set */
					/* ICMP header*/
					ict0_hdr->icmp_type = 0x00;
					ict0_hdr->icmp_code = 0x00;
					ict0_hdr->icmp_sum = 0;
					ict0_hdr->icmp_identifier = ((struct sr_icmp_t0_hdr *)ic_hdr0)->icmp_identifier;
					ict0_hdr->icmp_seq_num = ((struct sr_icmp_t0_hdr *)ic_hdr0)->icmp_seq_num;
					fprintf(stderr, "ic_hdr0->icmp_seq_num: %d ict0_hdr->icmp_seq_num: %d\n",((struct sr_icmp_t0_hdr *)ic_hdr0)->icmp_seq_num, ict0_hdr->icmp_seq_num);
					memcpy(ict0_hdr->data, ((struct sr_icmp_t0_hdr *)ic_hdr0)->data, ICMP_PAYLOAD_SIZE);
					ict0_hdr->icmp_sum = cksum(ict0_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
					/* IP header */
					i_hdr->ip_hl = i_hdr0->ip_hl;
					i_hdr->ip_v = i_hdr0->ip_v;
					i_hdr->ip_tos = i_hdr0->ip_tos;
					fprintf(stderr, "i_hdr0->ip_tos: %d i_hdr->ip_tos:: %d\n",i_hdr0->ip_tos, i_hdr->ip_tos);
					i_hdr->ip_len = i_hdr0->ip_len;
					i_hdr->ip_id = i_hdr0->ip_id;
					i_hdr->ip_off = i_hdr0->ip_off;
					i_hdr->ip_ttl = INIT_TTL;
					i_hdr->ip_p = i_hdr0->ip_p;
					i_hdr->ip_sum = 0;
					i_hdr->ip_src = i_hdr0->ip_dst;
					i_hdr->ip_dst = i_hdr0->ip_src;
					fprintf(stderr, "i_hdr->ip_src:");
					print_addr_ip_int(i_hdr->ip_src);
					i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));
					/**************** fill in code here *****************/
					/* refer routing table */
					rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
					/* routing table hit */
					if (rtentry != NULL)
					{
						/**************** fill in code here *****************/
						ifc = sr_get_interface(sr, rtentry->interface);
						/* Ethernet header */
						e_hdr->ether_type = htons(ethertype_ip);
						memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
						/**************** fill in code here *****************/
						arpentry = sr_arpcache_lookup(&(sr->cache), i_hdr->ip_dst/*rtentry->gw.s_addr*/);
						fprintf(stderr, "i_hdr->ip_dst:");
						print_addr_ip_int(i_hdr->ip_dst);
						if (arpentry != NULL)
						{
							/**************** fill in code here *****************/
							/* Ethernet header */
							memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry);
							/* send */
							print_hdr_eth(new_pck);
							print_hdr_ip(new_pck + sizeof(struct sr_ethernet_hdr));
							print_hdr_icmp(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
							fprintf(stderr, "rtentry->interface: %s\n",rtentry->interface);
							sr_send_packet(sr, new_pck, new_len, rtentry->interface);
							/**************** fill in code here *****************/
						}
						else
						{
							/* queue */
							arpreq = sr_arpcache_queuereq(&(sr->cache), i_hdr->ip_dst/*rtentry->gw.s_addr*/, new_pck, new_len, rtentry->interface);
							sr_arpcache_handle_arpreq(sr, arpreq);
						}
					}

					/* done */
					free(new_pck);
					return;
				}

				/* other types */
				else
					return;
			}
			/* with TCP or UDP */
			else if (i_hdr0->ip_p == ip_protocol_tcp || i_hdr0->ip_p == ip_protocol_udp)
			{
				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;

				/* generate ICMP port unreachable packet */
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
				new_pck = (uint8_t *) calloc(1, new_len);
				
				/**************** fill in code here *****************/
				e_hdr = (struct sr_ethernet_hdr *)new_pck; /* e_hdr set */
				i_hdr = (struct sr_ip_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr)); /* i_hdr set */
				ict3_hdr = (struct sr_icmp_t3_hdr *)(new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); /* ict3_hdr set */
				/* ICMP header */
				ict3_hdr->icmp_type = 0x03;
				ict3_hdr->icmp_code = 0x03;
				ict3_hdr->icmp_sum = 0;
				memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
				ict3_hdr->icmp_sum = cksum(ict3_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
				/* IP header */
				i_hdr->ip_hl = 0x5;
				i_hdr->ip_v = 0x4;
				i_hdr->ip_tos = 0x00;
				i_hdr->ip_len = htons(4 * ((int) i_hdr->ip_hl) + sizeof(struct sr_icmp_t3_hdr));
				i_hdr->ip_id = 0x0000;
				i_hdr->ip_off = 0x0000;
				i_hdr->ip_ttl = INIT_TTL;
				i_hdr->ip_p = ip_protocol_icmp;
				i_hdr->ip_sum = 0;
				i_hdr->ip_src = i_hdr0->ip_dst;
				i_hdr->ip_dst = i_hdr0->ip_src;

				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL) {
					ifc = sr_get_interface(sr, rtentry->interface);
					/* Ethernet header */
					e_hdr->ether_type = htons(ethertype_ip);
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
					arpentry = sr_arpcache_lookup(&(sr->cache),i_hdr->ip_dst/*rtentry->gw.s_addr*/);
					if (arpentry != NULL) {
						memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
						free(arpentry);
						/* send */
						sr_send_packet(sr, new_pck, new_len, rtentry->interface);
					}
					else {
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache),i_hdr->ip_dst/*rtentry->gw.s_addr*/, new_pck, new_len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
				/* done */
				}
				/*****************************************************/
				free(new_pck);
				return;
			}
			/* with others */
			else
				return;
		}
		/* destined elsewhere, forward */
		else
		{
			fprintf(stderr, "ifc == NULL\n");
			/* refer routing table */
			rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);

			/* routing table hit */
			if (rtentry != NULL)
			{
				fprintf(stderr, "routing table hit!\n");
				/* check TTL expiration */
				if (i_hdr0->ip_ttl == 1)
				{
					/**************** fill in code here *****************/

					/* validation */
					if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
						return;
					/* generate ICMP time exceeded packet */
					new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr);
					new_pck = (uint8_t *) calloc(1, new_len);
					e_hdr = (struct sr_ethernet_hdr *) new_pck; /* e_hdr set */
					i_hdr = (struct sr_ip_hdr *) (new_pck + sizeof(struct sr_ethernet_hdr)); /* i_hdr set */
					ict11_hdr = (struct sr_icmp_t11_hdr *) (new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); /* ict11_hdr set */
					/* ICMP header */
					ict11_hdr->icmp_type = 0x0b;
					ict11_hdr->icmp_code = 0x00;
					ict11_hdr->icmp_sum = 0;
					memcpy(ict11_hdr->data, i_hdr0, ICMP_DATA_SIZE);
					ict11_hdr->icmp_sum = cksum(ict11_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
					/* IP header */
					i_hdr->ip_hl = 0x5;
					i_hdr->ip_v = 0x4;
					i_hdr->ip_tos = 0x00;
					i_hdr->ip_len = htons(4 * ((int) i_hdr->ip_hl) + sizeof(struct sr_icmp_t11_hdr));
					i_hdr->ip_id = 0x0000;
					i_hdr->ip_off = 0x0000;
					i_hdr->ip_ttl = INIT_TTL;
					i_hdr->ip_p = ip_protocol_icmp;					
					i_hdr->ip_sum = 0;
					i_hdr->ip_src = sr_get_interface(sr, interface)->ip;
					i_hdr->ip_dst = i_hdr0->ip_src;
					i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

					rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
					if (rtentry != NULL) {
						ifc = sr_get_interface(sr, rtentry->interface);
						/* Ethernet header */
						e_hdr->ether_type = htons(ethertype_ip);
						memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
						arpentry = sr_arpcache_lookup(&(sr->cache), i_hdr->ip_dst/*rtentry->gw.s_addr*/);
						if (arpentry != NULL) {
							memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
							free(arpentry);
							/* send */
							sr_send_packet(sr, new_pck, new_len, rtentry->interface);
						}
						else {
							/* queue */
							arpreq = sr_arpcache_queuereq(&(sr->cache), i_hdr->ip_dst/*rtentry->gw.s_addr*/, new_pck, new_len, rtentry->interface);
							sr_arpcache_handle_arpreq(sr, arpreq);
						}
					/* done */
					}
					/*****************************************************/
					free(new_pck);
					return;
				}
				/* TTL not expired */
				else {
					/**************** fill in code here *****************/
					ifc = sr_get_interface(sr, rtentry->interface);
					/* set src MAC addr */
					memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
					/* refer ARP table */
					arpentry = sr_arpcache_lookup(&(sr->cache),i_hdr0->ip_dst/*rtentry->gw.s_addr*/);
					fprintf(stderr, "i_hdr->ip_dst:");
					print_addr_ip_int(i_hdr->ip_dst);
					if (arpentry != NULL) {
						/* set dst MAC addr */
						memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
						free(arpentry);
						/* decrement TTL */
						i_hdr0->ip_ttl = i_hdr0->ip_ttl - 0x01;
						i_hdr0->ip_sum = 0;
						i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));
						/* forward */
						sr_send_packet(sr, packet, len, rtentry->interface);
					}
					else {
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache),i_hdr0->ip_dst/*rtentry->gw.s_addr*/, packet, len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					/*****************************************************/
					}
					/* done */
					return;
				}
			}
			/* routing table miss */
			else
			{
				/**************** fill in code here *****************/
				fprintf(stderr, "routing table miss!\n");
				/* validation */
				if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
					return;
				/* generate ICMP net unreachable packet */
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr);
				new_pck = (uint8_t *) calloc(1, new_len);
				e_hdr = (struct sr_ethernet_hdr *) new_pck; /* e_hdr set */
				i_hdr = (struct sr_ip_hdr *) (new_pck + sizeof(struct sr_ethernet_hdr)); /* i_hdr set */
				ict3_hdr = (struct sr_icmp_t3_hdr *) (new_pck + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr)); /* ict3_hdr set */
				/* ICMP header */ 
				ict3_hdr->icmp_type = 0x03;
				ict3_hdr->icmp_code = 0x00;
				ict3_hdr->icmp_sum = 0;
				memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
				ict3_hdr->icmp_sum = cksum(ict3_hdr, new_len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr));
				/* IP header */
				i_hdr->ip_hl = 0x5;
				i_hdr->ip_v = 0x4;
				i_hdr->ip_tos = 0x00;
				i_hdr->ip_len = htons(4 * ((int) i_hdr->ip_hl) + sizeof(struct sr_icmp_t3_hdr));
				i_hdr->ip_id = 0x0000;
				i_hdr->ip_off = 0x0000;
				i_hdr->ip_ttl = INIT_TTL;
				i_hdr->ip_p = ip_protocol_icmp;
				i_hdr->ip_sum = 0;
				i_hdr->ip_src = sr_get_interface(sr, interface)->ip;
				i_hdr->ip_dst = i_hdr0->ip_src;
				i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

				rtentry = sr_findLPMentry(sr->routing_table, i_hdr->ip_dst);
				if (rtentry != NULL) {
					ifc = sr_get_interface(sr, rtentry->interface);
					/* Ethernet header */
					e_hdr->ether_type = htons(ethertype_ip);
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
					arpentry = sr_arpcache_lookup(&(sr->cache),i_hdr->ip_dst/*rtentry->gw.s_addr*/);
					if (arpentry != NULL) {
						memcpy(e_hdr->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
						free(arpentry);
						/* send */
						sr_send_packet(sr, new_pck, new_len, rtentry->interface);
					}
					else {
						/* queue */
						arpreq = sr_arpcache_queuereq(&(sr->cache),i_hdr->ip_dst/*rtentry->gw.s_addr*/, new_pck, new_len, rtentry->interface);
						sr_arpcache_handle_arpreq(sr, arpreq);
					}
				/* done */
				}
				/*****************************************************/
				free(new_pck);
				return;
			}
		}
	}
	/* ARP packet arrived */
	else if (e_hdr0->ether_type == htons(ethertype_arp))
	{

		/* validation */
		if (len_r < sizeof(struct sr_arp_hdr))
			return;

		a_hdr0 = (struct sr_arp_hdr *)(((uint8_t *)e_hdr0) + sizeof(struct sr_ethernet_hdr)); /* a_hdr0 set */

		/* destined to me */
		ifc = sr_get_interface(sr, interface);
		if (a_hdr0->ar_tip == ifc->ip)
		{
			/* request code */
			if (a_hdr0->ar_op == htons(arp_op_request))
			{
				/**************** fill in code here *****************/
				fprintf(stderr, "received ARP request!\n");
				/* generate reply */
				new_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
				new_pck = (uint8_t *) calloc(1, new_len);
				e_hdr = (struct sr_ethernet_hdr *) new_pck;
				a_hdr = (struct sr_arp_hdr *)(((uint8_t *) e_hdr) + sizeof(struct sr_ethernet_hdr));
				/* ARP header */
				a_hdr->ar_hrd = htons(arp_hrd_ethernet);
				a_hdr->ar_pro = htons(ethertype_ip);
				a_hdr->ar_hln = ETHER_ADDR_LEN;
				a_hdr->ar_pln = 0x4;
				a_hdr->ar_op = htons(arp_op_reply);
				a_hdr->ar_sip = a_hdr0->ar_tip;
				memcpy(a_hdr->ar_tha, a_hdr0->ar_sha, ETHER_ADDR_LEN);
				a_hdr->ar_tip = a_hdr0->ar_sip;

				rtentry = sr_findLPMentry(sr->routing_table, a_hdr->ar_tip);
				if (rtentry != NULL) {
					ifc = sr_get_interface(sr, rtentry->interface);
					/* Ethernet header */
					e_hdr->ether_type = htons(ethertype_arp);
					memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
					memcpy(a_hdr->ar_sha, e_hdr->ether_shost, ETHER_ADDR_LEN);
					memcpy(e_hdr->ether_dhost, a_hdr->ar_tha, ETHER_ADDR_LEN);
					/* send */
					sr_send_packet(sr, new_pck, new_len, rtentry->interface);
				/* done */
				}
				/*****************************************************/
				free(new_pck);
				return;
			}

			/* reply code */
			else if (a_hdr0->ar_op == htons(arp_op_reply))
			{
				/**************** fill in code here *****************/
				fprintf(stderr, "received ARP reply!\n");
				/* pass info to ARP cache */
				fprintf(stderr, "a_hdr0->ar_sip:");
				print_addr_ip_int(ntohl(a_hdr0->ar_sip));
				arpreq = sr_arpcache_insert(&(sr->cache), a_hdr0->ar_sha, a_hdr0->ar_sip);
				/* pending request exist */
				if (arpreq != NULL) {
					for (en_pck = arpreq->packets; en_pck != NULL; en_pck = en_pck->next) {
						
						int matched = 0;
						struct sr_ethernet_hdr *en_eth_hdr = (struct sr_ethernet_hdr *)(en_pck->buf);
						struct sr_ip_hdr *en_ip_hdr = (struct sr_ip_hdr *)((uint8_t *)(en_pck->buf) + sizeof(struct sr_ethernet_hdr));
						/* set dst MAC addr */
						en_eth_hdr->ether_type = htons(ethertype_ip);
						memcpy(en_eth_hdr->ether_shost, a_hdr0->ar_tha, ETHER_ADDR_LEN);
						memcpy(en_eth_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
						print_hdr_eth(en_pck->buf);
						/* decrement TTL except for self-generated packets */
						for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next) {
							if (en_ip_hdr->ip_src == ifc->ip) {
								fprintf(stderr, "en_ip_hdr->ip_src:");
								print_addr_ip_int(ntohl(en_ip_hdr->ip_src));
								matched = 1;
								break;
							}
						}
						if (matched == 0) {
							en_ip_hdr->ip_ttl = en_ip_hdr->ip_ttl - 1;
						}
						/* modify checksum */
						en_ip_hdr->ip_sum = 0;
						en_ip_hdr->ip_sum = cksum(en_ip_hdr, sizeof(struct sr_ip_hdr));
						print_hdr_ip((struct sr_ip_hdr *)((uint8_t *)(en_pck->buf) + sizeof(struct sr_ethernet_hdr)));
						print_hdr_icmp((struct sr_ip_hdr *)((uint8_t *)(en_pck->buf) + sizeof(struct sr_ethernet_hdr)+sizeof(struct sr_ip_hdr)));
						/* send */
						sr_send_packet(sr, en_pck->buf, en_pck->len, en_pck->iface);
						fprintf(stderr, "en_pck->iface: %s\n",en_pck->iface);
					/* done */
					}
					sr_arpreq_destroy(&(sr->cache), arpreq);
					/*****************************************************/
					return;
				}
				/* no exist */
				else
					return;
			}

			/* other codes */
			else
				return;
		}

		/* destined to others */
		else
			return;
	}

	/* other packet arrived */
	else
		return;

} /* end sr_ForwardPacket */

struct sr_rt *sr_findLPMentry(struct sr_rt *rtable, uint32_t ip_dst)
{
	struct sr_rt *entry, *lpmentry = NULL;
	uint32_t mask, lpmmask = 0;

	ip_dst = ntohl(ip_dst);

	/* scan routing table */
	for (entry = rtable; entry != NULL; entry = entry->next)
	{
		mask = ntohl(entry->mask.s_addr);
		/* longest match so far */
		if ((ip_dst & mask) == (ntohl(entry->dest.s_addr) & mask) && mask > lpmmask)
		{
			lpmentry = entry;
			lpmmask = mask;
		}
	}

	return lpmentry;
}
