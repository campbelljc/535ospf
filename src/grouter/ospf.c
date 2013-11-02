#include "message.h"
#include "grouter.h"
#include "mtu.h"
#include "ospf.h"
#include "packetcore.h"
#include <stdlib.h>
#include <slack/err.h>
#include <netinet/in.h>
#include <string.h>

extern pktcore_t *pcore;
extern mtu_entry_t MTU_tbl[MAX_MTU];	   

void OSPFIncomingPacket(gpacket_t *pkt)
{ // process incoming OSPF packet
	ospf_hdr_t *ospf_pkt = (ospf_hdr_t*) &pkt->data.data;
	
	if (isOSPFHelloMessage(ospf_pkt))
	{
		verbose(2, "[OSPFIncomingPacket]:: received OSPF Hello message");
		// update hello database
		// check for bi-directional connectivity
	}
	else if (isOSPFLSUpdate(ospf_pkt))
	{
		verbose(2, "[OSPFIncomingPacket]:: received OSPF link state update");
		// check if we already know the information
			// if we do, discard packet
			// else, update routing graph, recompute shortest paths, and broadcast packet to all other interfaces
	}
	else
	{
		verbose(2, "[OSPFIncomingPacket]:: unknown OSPF packet received");
	}
}

bool isOSPFHelloMessage(ospf_hdr_t *ospf_hdr)
{
	return (ospf_hdr->ospf_type == 1);
}

bool isOSPFLSUpdate(ospf_hdr_t *ospf_pkt)
{
	
}

void OSPFSendHelloPacket(uchar *dst_ip)
{
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ospf_hdr_t *ospf_pkt = (ospf_hdr_t *)(out_pkt->data.data);
	ospf_pkt->ospf_message_length = 4;                                 
	hello_packet_t *hello_pkt = (hello_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);
		
	hello_pkt->hello_network_mask[0] = "255";
	hello_pkt->hello_network_mask[1] = "255";
	hello_pkt->hello_network_mask[2] = "255";
	hello_pkt->hello_network_mask[3] = "0";

	hello_pkt->hello_hello_interval = 10;
	hello_pkt->hello_priority = 0;
	hello_pkt->hello_dead_interval= 40;
	hello_pkt->hello_designated_ip[0] = "0"; 
	hello_pkt->hello_designated_ip[1] = "0";
	hello_pkt->hello_designated_ip[2] = "0";
	hello_pkt->hello_designated_ip[3] = "0";
	hello_pkt->hello_designated_ip_backup[0] = "0";
	hello_pkt->hello_designated_ip_backup[1] = "0";
	hello_pkt->hello_designated_ip_backup[2] = "0";
	hello_pkt->hello_designated_ip_backup[3] = "0";

	//hello_pkt->hello_neighbours = (uchar*) malloc(sizeof(NEIGHBOURS_LIST));

	gpacket_t* finished_pkt = createOSPFHeader(out_pkt, 1, sizeof(hello_pkt), hello_pkt->hello_designated_ip);
	
	// TODO: send out packet.
	OSPFSend2Output(finished_pkt);
}

void OSPFSendLSUPacket(uchar *dst_ip, int seqNum_, uchar* sourceIP)
{
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ospf_hdr_t *ospf_pkt = (ospf_hdr_t *)(out_pkt->data.data);
	ospf_pkt->ospf_message_length = 4;                                 
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);
	lsa_pkt->lsa_header_length = 5;
	lsu_packet_t *lsu_pkt = (lsu_packet_t *)((uchar *)lsa_pkt + lsa_pkt->lsa_header_length*4);
	
	uchar interfaceIPs[MAX_MTU][4];	
	int totalInterfaceIPs = findAllInterfaceIPs(MTU_tbl, interfaceIPs); // get num links
	
	// prepare lsu_packet	
	lsu_pkt->lsu_num_links = totalInterfaceIPs;
	//lsu_pkt->lsa_header_length = 1 + (4 * lsu_pkt->lsu_num_links); // 4 lines for each link, plus 1 header line.
	lsu_pkt->lsa_header_length = 1 + sizeof(lsu_packet_t);
	
//	lsu_link_t *currentLink = (lsu_link_t *)((uchar *)lsu_pkt + 1);
	
	int count;
	for (count = 0; count < lsu_pkt->lsu_num_links; count ++)
	{
		lsu_pkt->links[count].lsu_link_type = 0; // 2 for any-to-any, 3 for stub network.
//		lsu_pkt->links[count].lsu_link_ID = '0'; // TODO
		COPY_IP(lsu_pkt->links[count].lsu_link_data, interfaceIPs[count]);
		lsu_pkt->links[count].lsu_metric = 1;
		
//		currentLink = currentLink + sizeof(lsu_link_t);
	}
	
	int totalLength = sizeof(lsa_packet_t) + sizeof(lsu_packet_t);
//	gpacket_t *finished_pkt = createOSPFHeader(createLSAHeader(out_pkt, seqNum_, sourceIP), OSPF_LINK_STAT_UPDATE, totalLength, sourceIP);
	
	for (count = 0; count < totalInterfaceIPs; count ++)
	{ // send out on each interface, unless it is stub network
		//if (/* IS STUB NETWORK */) continue;
		
		//COPY_IP(finished_pkt->data.header.nxth_ip_addr, interfaceIPs[count]);
		//finished_pkt->data.header.dst_interface = count;		
		
		//OSPFSend2Output(finished_pkt);
	}
}

gpacket_t* OSPFSendLSAPacket(gpacket_t *gpkt, int seqNum_, uchar* sourceIP)
{
	ospf_hdr_t *ospf_pkt = (ospf_hdr_t *)(gpkt->data.data);
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);
	
	lsa_pkt->lsa_age = 0;
	lsa_pkt->lsa_type = 1;
	lsa_pkt->lsa_sequence_number = seqNum_;
	lsa_pkt->lsa_checksum = 0;
	lsa_pkt->lsa_length = sizeof(lsu_packet_t);
	
	COPY_IP(lsa_pkt->lsa_ID, sourceIP);
	COPY_IP(lsa_pkt->lsa_advertising_number, sourceIP);
	
	return gpkt;
}

int OSPFSend2Output(gpacket_t *pkt)
{
	int vlevel;

	if (pkt == NULL)
	{
		verbose(1, "[OSPFSend2Output]:: NULL pointer error... nothing sent");
		return EXIT_FAILURE;
	}

	vlevel = prog_verbosity_level();
	if (vlevel >= 3)
		printGPacket(pkt, vlevel, "OSPF_ROUTINE");

	return writeQueue(pcore->outputQ, (void *)pkt, sizeof(gpacket_t));
}

gpacket_t* createOSPFHeader(gpacket_t *gpacket, int type, int mlength, uchar* src[]) 
{
	ospf_hdr_t* header = (ospf_hdr_t *)(gpacket->data.data);

	header->ospf_version = OSPF_VERSION;
	header->ospf_type = type;
	header->ospf_message_length = mlength + sizeof(ospf_hdr_t);
	header->ospf_src[0] = src[0]; 
	header->ospf_aid = OSPF_AREAID;
	header->ospf_auth_type = OSPF_AUTHTYPE;
	header->ospf_cksum = 0;

	return gpacket;
}

// Add a new node and adjacency list to the graph if it does not exist, otherwise update its adjacency list
//void updateGraph(ospf_graph_t graph, ospf_gnode_t)
//{
//	//TO DO
//}
