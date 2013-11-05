#include "gnet.h"
#include "message.h"
#include "grouter.h"
#include "mtu.h"
#include "ospf.h"
#include "packetcore.h"
#include "routetable.h"
#include <stdlib.h>
#include <slack/err.h>
#include <netinet/in.h>
#include <string.h>

extern pktcore_t *pcore;
extern mtu_entry_t MTU_tbl[MAX_MTU];	 

neighbor_entry_t neighbor_tbl[MAX_ROUTES];  

void OSPFInit()
{
	int i;
	for(i = 0; i < MAX_ROUTES; i++)
		neighbor_tbl[i].isEmpty = TRUE;
	verbose(2, "[OSPFInit]:: neighbor table initialized");
}

void OSPFIncomingPacket(gpacket_t *pkt)
{ // process incoming OSPF packet
	ospf_hdr_t *ospf_pkt = (ospf_hdr_t*) &pkt->data.data;
	
	if (ospf_pkt->ospf_type == OSPF_HELLO)
	{
		verbose(2, "[OSPFIncomingPacket]:: received OSPF Hello message");
		OSPFProcessHelloMessage(pkt);
	}
	else if (ospf_pkt->ospf_type == OSPF_LINK_STAT_UPDATE)
	{
		verbose(2, "[OSPFIncomingPacket]:: received OSPF link state update");
		OSPFProcessLSUpdate(pkt);
	}
	else
	{
		verbose(2, "[OSPFIncomingPacket]:: unknown OSPF packet received");
	}
}

void OSPFProcessHelloMessage(gpacket_t *pkt)
{
	// update neighbor database
	addNeighborEntry(pkt->frame.src_ip_addr, OSPF_ROUTER, pkt->frame.src_interface);
	
	//check bidirectional
	uchar *currentIP = pkt->frame.nxth_ip_addr;
        ospf_hdr_t *ospf_pkt = (ospf_hdr_t *)(pkt->data.data);
        hello_packet_t *hello_pkt = (hello_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);

	int neighbor_size = sizeof(hello_pkt->hello_neighbours)/(sizeof(uchar)*4);

	int i;
	for (i=0; i< neighbor_size;i++){ 
		if (COMPARE_IP(currentIP, hello_pkt->hello_neighbours[i]) == 0){
			
		} 
	}
}

void OSPFProcessLSUpdate(gpacket_t *pkt)
{
		// check if we already know the information
			// if we do, discard packet
			// else, update routing graph, recompute shortest paths, and broadcast packet to all other interfaces
}

void OSPFSendHelloPacket(uchar *dst_ip)
{
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ospf_hdr_t *ospf_pkt = (ospf_hdr_t *)(out_pkt->data.data);
	ospf_pkt->ospf_message_length = 4;                                 
	hello_packet_t *hello_pkt = (hello_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);
		
	uchar netmask[4] = { '255', '255', '255', '0' };
	COPY_IP(hello_pkt->hello_network_mask, netmask);

	hello_pkt->hello_hello_interval = 10;
	hello_pkt->hello_priority = 0;
	hello_pkt->hello_dead_interval= 40;
	
	uchar zeroIP[4] = { '0', '0', '0', '0' };
	COPY_IP(hello_pkt->hello_designated_ip, zeroIP);
	COPY_IP(hello_pkt->hello_designated_ip_backup, zeroIP);

	//hello_pkt->hello_neighbours = (uchar*) malloc(sizeof(NEIGHBOURS_LIST));

	gpacket_t* finished_pkt = createOSPFHeader(out_pkt, OSPF_HELLO, sizeof(hello_pkt), hello_pkt->hello_designated_ip);	
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
	
	//uchar interfaceIPs[MAX_MTU][4];	
	//int totalInterfaceIPs = findAllInterfaceIPs(MTU_tbl, interfaceIPs); // get num links
			
	int currentLink = 0; // current position in lsu links array
	
	int count; // position in neighbor table
	for (count = 0; count < MAX_ROUTES; count ++)
	{
		if (neighbor_tbl[count].isEmpty == TRUE || neighbor_tbl[count].isAlive == FALSE) continue;
		
		lsu_pkt->links[currentLink].lsu_metric = 1;
		lsu_pkt->links[currentLink].lsu_link_type = neighbor_tbl[count].type;
		if (neighbor_tbl[count].type == OSPF_STUB)
		{
			uchar bcastmask[4] = { '255', '255', '255', '0' };
			COPY_IP(lsu_pkt->links[currentLink].lsu_link_data, bcastmask);
		}
		COPY_IP(lsu_pkt->links[currentLink].lsu_link_ID, neighbor_tbl[count].neighborIP);
		
		currentLink ++;
	}
	
	lsu_pkt->lsu_num_links = currentLink - 1;

	int totalLength = sizeof(lsa_packet_t) + sizeof(lsu_packet_t);
	gpacket_t *finished_pkt = createOSPFHeader(createLSAHeader(out_pkt, seqNum_, sourceIP), OSPF_LINK_STAT_UPDATE, totalLength, sourceIP);
	
	for (count = 0; count < MAX_ROUTES; count ++)
	{ // send out to each neighbor, unless it is stub network
		if (neighbor_tbl[count].isEmpty == TRUE
			|| neighbor_tbl[count].isAlive == FALSE
			|| neighbor_tbl[count].type == OSPF_STUB) continue;
		
		char tmpbuf[MAX_TMPBUF_LEN];
		COPY_IP(finished_pkt->data.header.nxth_ip_addr, gHtonl(tmpbuf, neighbor_tbl[count].neighborIP));
		finished_pkt->frame.dst_interface = neighbor_tbl[count].interface;
		
		OSPFSend2Output(finished_pkt);
	}
}

gpacket_t* createLSAHeader(gpacket_t *gpkt, int seqNum_, uchar* sourceIP)
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

// Adds an entry to the neighbor table with the specified IP, type, and interface.
// If an entry already exists with the specified IP, it is updated with the given type and interface.
// Either way, the entry is marked as "alive."
void addNeighborEntry(uchar* neighborIP_, int type_, int interface_)
{
	int i;
	int ifree = -1;

	// First check if the entry is already in the table, if it is, update it
	for (i = 0; i < MAX_ROUTES; i++)
	{
		if (neighbor_tbl[i].isEmpty == TRUE)
		{
			if (ifree < 0) ifree = i;

		}
		else if ((COMPARE_IP(neighborIP_, neighbor_tbl[i].neighborIP)) == 0)
		{ // match
			neighbor_tbl[i].type = type_;
			neighbor_tbl[i].isAlive = TRUE;
			verbose(2, "[addRouteEntry]:: updated neighbor table entry #%d", i);
			break;
		}
	}

	COPY_IP(neighbor_tbl[ifree].neighborIP, neighborIP_);
	neighbor_tbl[ifree].type = type_;
	neighbor_tbl[ifree].isEmpty = FALSE;
	neighbor_tbl[ifree].isAlive = TRUE;
	neighbor_tbl[ifree].interface = interface_;

	verbose(2, "[addNeighborEntry]:: added neighbor entry ");
	return;
}

// Marks the entry for the specified IP as dead, if the IP exists. If it does not, nothing happens.
void OSPFMarkDeadNeighbor(uchar* neighborIP_)
{
	int count;
	for (count = 0; count < MAX_ROUTES; count ++)
	{
		if (neighbor_tbl[count].isEmpty == TRUE) continue;
		else if ((COMPARE_IP(neighborIP_, neighbor_tbl[count].neighborIP)) == 0)
		{ // match
			neighbor_tbl[count].isAlive = FALSE;
			verbose(2, "[addRouteEntry]:: neighbor table entry #%d marked as dead ", count);
			break;
		}
	}
}

void OSPFSetStubNetwork(gpacket_t *pkt)
{
	addNeighborEntry(pkt->frame.src_ip_addr, OSPF_STUB, pkt->frame.src_interface);
}

void printNeighborTable()
{
	int i, rcount = 0;
	char tmpbuf[MAX_TMPBUF_LEN];
	interface_t *iface;

	printf("\n=================================================================\n");
	printf("      N E I G H B O R   T A B L E \n");
	printf("-----------------------------------------------------------------\n");
	printf("Index\tNeighbor IPt\tIs Alive\tType\t \n");

	for (i = 0; i < MAX_ROUTES; i++)
		if (neighbor_tbl[i].isEmpty != TRUE)
		{
			printf("[%d]\t%s\t%d\t%d\t\n", i, IP2Dot(tmpbuf, neighbor_tbl[i].neighborIP), neighbor_tbl[i].isAlive, neighbor_tbl[i].type);
			rcount++;
		}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of neighbors found. \n", rcount);
}

// Add a new node and adjacency list to the graph if it does not exist, otherwise update its adjacency list
//void updateGraph(ospf_graph_t graph, ospf_gnode_t)
//{
//	//TO DO
//}
