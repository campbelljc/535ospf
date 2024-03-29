/*
 * ethernet.c (Ethernet driver for the GINI router)
 * AUTHOR: Muthucumaru Maheswaran
 *
 * VERSION: 1.0
 */

#include <slack/err.h>

#include "packetcore.h"
#include "classifier.h"
#include "filter.h"
#include "protocols.h"
#include "message.h"
#include "gnet.h"
#include "arp.h"
#include "ip.h"
#include "ospf.h"
#include <netinet/in.h>
#include <stdlib.h>


extern pktcore_t *pcore;
extern classlist_t *classifier;
extern filtertab_t *filter;


extern router_config rconfig;

int findPacketSize(pkt_data_t *pkt)
{
	ip_packet_t *ip_pkt;

	if (pkt->header.prot == htons(IP_PROTOCOL))
	{
		ip_pkt = (ip_packet_t *) pkt->data;
		return (14 + ntohs(ip_pkt->ip_pkt_len));
	} else if (pkt->header.prot == htons(ARP_PROTOCOL))
		return 42;
	// above assumes IP and ARP; we can compute this length by
	// reading the address lengths from the packet.
	else
		return sizeof(pkt_data_t);
}


void *toEthernetDev(void *arg)
{
	gpacket_t *inpkt = (gpacket_t *)arg;
	interface_t *iface;
	arp_packet_t *apkt;
	char tmpbuf[MAX_TMPBUF_LEN];
	int pkt_size;

	verbose(2, "[toEthernetDev]:: entering the function.. ");
	// find the outgoing interface and device...
	if ((iface = findInterface(inpkt->frame.dst_interface)) != NULL)
	{
		/* send IP packet or ARP reply */
		if (inpkt->data.header.prot == htons(ARP_PROTOCOL))
		{
			apkt = (arp_packet_t *) inpkt->data.data;
			COPY_MAC(apkt->src_hw_addr, iface->mac_addr);
			COPY_IP(apkt->src_ip_addr, gHtonl(tmpbuf, iface->ip_addr));
		}
		pkt_size = findPacketSize(&(inpkt->data));
		verbose(2, "[toEthernetDev]:: vpl_sendto called for interface %d..%d bytes written ", iface->interface_id, pkt_size);
		vpl_sendto(iface->vpl_data, &(inpkt->data), pkt_size);
		free(inpkt);          // finally destroy the memory allocated to the packet..
	} else
		error("[toEthernetDev]:: ERROR!! Could not find outgoing interface ...");

	// this is just a dummy return -- return value not used.
	return arg;
}


/*
 * TODO: Some form of conformance check so that only packets
 * destined to the particular Ethernet protocol are being captured
 * by the handler... right now.. this might capture other packets as well.
 */
void* fromEthernetDev(void *arg)
{
	interface_t *iface = (interface_t *) arg;
	interface_array_t *iarr = (interface_array_t *)iface->iarray;
	uchar bcast_mac[] = MAC_BCAST_ADDR;
	uchar stub_mac[][6] = { MAC_STUB1_ADDR, MAC_STUB2_ADDR, MAC_STUB3_ADDR, MAC_STUB4_ADDR, MAC_STUB5_ADDR };
	uchar bcast_ip[] = IP_BCAST_ADDR;

	gpacket_t *in_pkt;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);		// die as soon as cancelled
	while (1)
	{
		verbose(2, "[fromEthernetDev]:: Receiving a packet ...");
		if ((in_pkt = (gpacket_t *)malloc(sizeof(gpacket_t))) == NULL)
		{
			fatal("[fromEthernetDev]:: unable to allocate memory for packet.. ");
			return NULL;
		}

		bzero(in_pkt, sizeof(gpacket_t));
		vpl_recvfrom(iface->vpl_data, &(in_pkt->data), sizeof(pkt_data_t));
		pthread_testcancel();
		// check whether the incoming packet is a layer 2 broadcast or
		// meant for this node... otherwise should be thrown..
		// TODO: fix for promiscuous mode packet snooping.
		if ((COMPARE_MAC(in_pkt->data.header.dst, iface->mac_addr) != 0) &&
			(COMPARE_MAC(in_pkt->data.header.dst, bcast_mac) != 0))
		{
			if ((COMPARE_MAC(in_pkt->data.header.dst, stub_mac[0]) != 0) &&
			    (COMPARE_MAC(in_pkt->data.header.dst, stub_mac[1]) != 0) &&
				(COMPARE_MAC(in_pkt->data.header.dst, stub_mac[2]) != 0) &&
				(COMPARE_MAC(in_pkt->data.header.dst, stub_mac[3]) != 0) &&
				(COMPARE_MAC(in_pkt->data.header.dst, stub_mac[4]) != 0))
			{
				char tmpbuf[MAX_TMPBUF_LEN];
								
				verbose(1, "[fromEthernetDev]:: Packet dropped .. not for this router!? MAC was %s ", MAC2Colon(tmpbuf, in_pkt->data.header.dst));
				free(in_pkt);
				continue;
			}
			else
			{				
				in_pkt->frame.src_interface = iface->interface_id;
				COPY_MAC(in_pkt->frame.src_hw_addr, iface->mac_addr);
				COPY_IP(in_pkt->frame.src_ip_addr, iface->ip_addr);
				
				OSPFSetStubNetwork(in_pkt);
				continue;
			}
		}

		// copy fields into the message from the packet..
		in_pkt->frame.src_interface = iface->interface_id;
		COPY_MAC(in_pkt->frame.src_hw_addr, iface->mac_addr);
		COPY_IP(in_pkt->frame.src_ip_addr, iface->ip_addr);

		// check for filtering.. if the it should be filtered.. then drop
		if (filteredPacket(filter, in_pkt))
		{
			verbose(2, "[fromEthernetDev]:: Packet filtered..!");
			free(in_pkt);
			continue;   // skip the rest of the loop
		}

		verbose(2, "[fromEthernetDev]:: Packet is sent for enqueuing..");
		enqueuePacket(pcore, in_pkt, sizeof(gpacket_t));
	}
}

