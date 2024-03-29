#include "gnet.h"
#include "message.h"
#include "grouter.h"
#include "mtu.h"
#include "ospf.h"
#include "ip.h"
#include "packetcore.h"
#include "routetable.h"
#include "protocols.h"
#include <stdlib.h>
#include <slack/err.h>
#include <netinet/in.h>
#include <string.h>

extern pktcore_t *pcore;
extern mtu_entry_t MTU_tbl[MAX_MTU];
extern route_entry_t route_tbl[MAX_ROUTES];

neighbor_entry_t neighbor_tbl[MAX_ROUTES];
ospf_graph_t *graph;
ospf_cost_entry_t cost_tbl[MAX_ROUTES];

int globalSeqNum;

void OSPFInit()
{
	int i;
	for(i = 0; i < MAX_ROUTES; i++)
		neighbor_tbl[i].isEmpty = TRUE;

	globalSeqNum = 0;

	graph = (ospf_graph_t *)malloc(sizeof(ospf_graph_t));

	for (i=0; i<MAX_NODES; i++)
	{
		graph -> nodes[i].is_empty = TRUE;
	}
	for (i=0; i<MAX_EDGES; i++)
	{
		graph -> edges[i].is_empty = TRUE;
	}

	verbose(1, "[OSPFInit]:: initialization complete");
}

void OSPFIncomingPacket(gpacket_t *pkt)
{ // process incoming OSPF packet
	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt->data.data;
	char tmpbuf[MAX_TMPBUF_LEN];
	if (ospf_pkt->ospf_type == OSPF_HELLO)
	{
		// verbose(1, "[OSPFIncomingPacket]:: received Hello message, source: %s", IP2Dot(tmpbuf, ospf_pkt->ospf_src));
		OSPFProcessHelloMessage(pkt);
	}
	else if (ospf_pkt->ospf_type == OSPF_LINK_STAT_UPDATE)
	{
		verbose(1, "[OSPFIncomingPacket]:: received LS update, source: %s", IP2Dot(tmpbuf, ospf_pkt->ospf_src));
		OSPFProcessLSUpdate(pkt, TRUE);
	}
	else
	{
		verbose(1, "[OSPFIncomingPacket]:: unknown OSPF packet received");
	}
}

void OSPFProcessHelloMessage(gpacket_t *pkt)
{
	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt->data.data;
    hello_packet_t *hello_pkt = (hello_packet_t *)((uchar *)ospf_pkt + 4*4);

	// update neighbor database
	int newUpdate = addNeighborEntry(ospf_pkt->ospf_src, OSPF_ROUTER, pkt->frame.src_interface);
//	if (newUpdate == FALSE) verbose(1, "Hello msg did not contain new neighbor info.");

	uchar zeroIP[] = ZEROED_IP;

	int count;
	for (count = 0; count < 10; count ++)
	{
		if (COMPARE_IP(hello_pkt->hello_neighbors[count].neighbor_ip, zeroIP) == 0) continue; // empty entry.

		// pkt->frame.src_ip_addr will be set to the IP of this router's interface which the packet arrived on.
		char tmpbuf[MAX_TMPBUF_LEN];
		char tmpbuf2[MAX_TMPBUF_LEN];
		if (COMPARE_IP(pkt->frame.src_ip_addr, hello_pkt->hello_neighbors[count].neighbor_ip) == 0)
		{ // the IP the packet is sending to is also contained in its neighbor table.
			// therefore, it knows about this router, and we know about it (entry added above)
			// so we have bidirectionality

			for (count = 0; count < MAX_ROUTES; count ++)
			{
				if (neighbor_tbl[count].isEmpty == TRUE /*|| neighbor_tbl[count].isAlive == FALSE*/) continue;

				if (COMPARE_IP(neighbor_tbl[count].neighborIP, ospf_pkt->ospf_src) == 0)
				{
					if (neighbor_tbl[count].bidirectional == FALSE)
					{
						char tmpbuf[MAX_TMPBUF_LEN];
						verbose(1, "[OSPFProcessHelloMessage]:: We have bidirectional connection with IP %s.", IP2Dot(tmpbuf, neighbor_tbl[count].neighborIP));
						neighbor_tbl[count].bidirectional = TRUE;
						broadcastLSUpdate(TRUE, NULL);
					}
				}
			}
		}
	}

	if (newUpdate)
	{ // if it's a new update, then send out a new link state update to all neighbors.
		verbose(1, "[OSPFProcessHelloMessage]:: Broadcasting new LS Update since we got new information from hello packet.");
		broadcastLSUpdate(TRUE, NULL);
	}
}

void OSPFProcessLSUpdate(gpacket_t *pkt, bool rebroadcast)
{
	char tmpbuf[MAX_TMPBUF_LEN];

	int i, num_links;

	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt -> data.data;
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + 4*4);
	lsu_packet_t *lsu_pkt = (lsu_packet_t *)((uchar *)lsa_pkt + lsa_pkt -> lsa_header_length*4);

	uchar src[4];
	COPY_IP(src, ospf_pkt->ospf_src); // get src address

	// check if node with the address already exists
	ospf_gnode_t *node = getNode(src);

	// if the node exists and the last sequence number received by the node is greater or equal to the current sequence number, ignore it
	if (node != NULL && node->last_LSN >= lsa_pkt->lsa_sequence_number)
	{
		// verbose(1, "[OSPFProcessLSUpdate]:: LS update is old so we are dropping it.");
		return;
	}

	// printLSData(pkt);

	removeNodes(graph, src);
	removeEdges(graph, src);

	num_links  = lsu_pkt -> lsu_num_links;

	uchar ips[num_links][4];

	for (i=0; i<num_links; i++)
	{
		lsu_link_t link = lsu_pkt->links[i];

		if (link.lsu_link_type == OSPF_STUB)
		{
			continue;
		}

		COPY_IP(ips[i], link.lsu_link_data);


		ospf_gnode_t *node = (ospf_gnode_t *)addNode(graph, ips[i]);


		node->last_LSN = lsa_pkt->lsa_sequence_number;

		// update the reachable networks of the node
		updateLinkData(lsu_pkt, node);
		// printGraphNodes(graph);

		// update the edges of the graph
		updateEdges(graph, node);
		// printGraphEdges(graph);
	}

	// update the routing table
	updateRoutingTable(graph);
	// printCostTable(graph);
	//printNeighborTable();
	printRouteTable(route_tbl);

	if (rebroadcast == TRUE)
	{
		// forward the update packet
		// verbose(1, "[OSPFProcessLSUpdate]:: Broadcasting the LS update we just received from %s", IP2Dot(tmpbuf, src));
		broadcastLSUpdate(FALSE, pkt);
	}
}

void OSPFSendHelloPacket(uchar src_ip[], int interface_)
{
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ospf_packet_t *ospf_pkt = (ospf_packet_t *)(out_pkt->data.data);
	ospf_pkt->ospf_message_length = 4;
	hello_packet_t *hello_pkt = (hello_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);

	uchar netmask[] = IP_BCAST_ADDR;
	COPY_IP(hello_pkt->hello_network_mask, netmask);

	hello_pkt->hello_hello_interval = 10;
	hello_pkt->hello_priority = 0;
	hello_pkt->hello_dead_interval = 40;

	uchar zeroIP[] = ZEROED_IP;
	COPY_IP(hello_pkt->hello_designated_ip, zeroIP);
	COPY_IP(hello_pkt->hello_designated_ip_backup, zeroIP);

	neighbor_entry_t neighborEntries[MAX_ROUTES];
	int numEntries = getNeighborEntries(neighborEntries);

	int count;
	for (count = 0; count < numEntries; count ++)
	{
		COPY_IP(hello_pkt->hello_neighbors[count].neighbor_ip, neighborEntries[count].neighborIP);
	}

	for (count = numEntries; count < 10; count ++)
	{
		COPY_IP(hello_pkt->hello_neighbors[count].neighbor_ip, zeroIP);
	}

	uchar bcast_addr[] = MAC_BCAST_ADDR;

	gpacket_t* finished_pkt = createOSPFHeader(out_pkt, OSPF_HELLO, sizeof(hello_pkt), src_ip);

	COPY_MAC(finished_pkt->data.header.dst, bcast_addr); // set MAC to be broadcast.
	finished_pkt->frame.dst_interface = interface_;
	finished_pkt->frame.arp_bcast = TRUE;
	COPY_IP(finished_pkt->frame.nxth_ip_addr, netmask);
	OSPFSend2Output(finished_pkt);
}

// Takes in a LS update packet of type gpacket and broadcasts it to your neighbors.
void broadcastLSUpdate(bool createPacket, gpacket_t *pkt)
{
	int count;
	for (count = 0; count < MAX_ROUTES; count ++)
	{ // send out to each non-stub, non-dead neighbor who we have established bidirectional connection with
		if (neighbor_tbl[count].isEmpty == TRUE
		/*	|| neighbor_tbl[count].isAlive == FALSE */
			|| neighbor_tbl[count].type == OSPF_STUB
		/*	|| neighbor_tbl[count].bidirectional == FALSE */) continue;

		char tmpbuf[MAX_TMPBUF_LEN];

		if (createPacket == TRUE)
		{
			interface_t* neighborInterface = findInterface(neighbor_tbl[count].interface);
			pkt = createLSUPacket(neighborInterface->ip_addr);
			char tmpbuf[MAX_TMPBUF_LEN];
		//	verbose(1, "Here is contents of the LSU packet we just created to send to %s: ", IP2Dot(tmpbuf, neighbor_tbl[count].neighborIP));
	//		printLSData(pkt);

			COPY_IP(pkt->frame.nxth_ip_addr, neighbor_tbl[count].neighborIP); //gNtohl(tmpbuf, neighbor_tbl[count].neighborIP));
			pkt->frame.dst_interface = neighbor_tbl[count].interface;

	//		if (count == 0)
	//		{
	//			OSPFProcessLSUpdate(pkt, FALSE);
	//		}

			OSPFSend2Output(pkt);
			verbose(1, "[broadcastLSUpdate]:: sent created LSU to IP %s", IP2Dot(tmpbuf, pkt->frame.nxth_ip_addr));
		}
		else
		{
			COPY_IP(pkt->frame.nxth_ip_addr, neighbor_tbl[count].neighborIP);
			pkt->frame.dst_interface = neighbor_tbl[count].interface;

			gpacket_t *newpkt = (gpacket_t *)malloc(sizeof(gpacket_t));
			memcpy(newpkt, pkt, sizeof(gpacket_t));

			newpkt->data.header.prot = htons(OSPF_PROTOCOL);
			verbose(1, "[broadcastLSUpdate]:: sent foreign LSU to IP %s", IP2Dot(tmpbuf, newpkt->frame.nxth_ip_addr));

			OSPFSend2Output(newpkt);
		}

	}
	if (count == 0) verbose(1, "[broadcastLSUpdate]:: Wanted to send LS update, but have no neighbors to send it to :( ");
}

void printLSData(gpacket_t *pkt)
{
	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt -> data.data;
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + 4*4);
	lsu_packet_t *lsu_pkt = (lsu_packet_t *)((uchar *)lsa_pkt + lsa_pkt->lsa_header_length*4);

	verbose(1, "===============L I N K   S T A T E   D A T A====================");
	verbose(1, "Index\tLink ID\t\tLink Data\tType");

	int count;
	char tmpbuf[MAX_TMPBUF_LEN];
	for (count = 0; count < lsu_pkt->lsu_num_links; count ++)
	{
		verbose(1, "[%d]\t\t%s\t%s\t%d", count, IP2Dot(tmpbuf, lsu_pkt->links[count].lsu_link_ID), IP2Dot(tmpbuf+20, lsu_pkt->links[count].lsu_link_data), lsu_pkt->links[count].lsu_link_type);
	}
	verbose(1, "================================================================");
}

gpacket_t* createLSUPacket(uchar sourceIP[])
{
//	verbose(1, "[createLSUPacket]:: Creating LSU packet");
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ospf_packet_t *ospf_pkt = (ospf_packet_t *)(out_pkt->data.data);
	ospf_pkt->ospf_message_length = 4;
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);
	lsa_pkt->lsa_header_length = 5;
	lsu_packet_t *lsu_pkt = (lsu_packet_t *)((uchar *)lsa_pkt + lsa_pkt->lsa_header_length*4);

	int currentLink = 0; // current position in lsu links array

	int neighborCount; // position in neighbor table
	for (neighborCount = 0; neighborCount < MAX_ROUTES; neighborCount ++)
	{
		if (neighbor_tbl[neighborCount].isEmpty == TRUE /*|| neighbor_tbl[neighborCount].isAlive == FALSE */ ) continue;

		lsu_pkt->links[currentLink].lsu_metric = 1;
		lsu_pkt->links[currentLink].lsu_link_type = neighbor_tbl[neighborCount].type;

		// Set link ID.
		uchar netIP[] = ZEROED_IP;
		COPY_IP(netIP, neighbor_tbl[neighborCount].neighborIP);
		netIP[0] = 0;
		COPY_IP(lsu_pkt->links[currentLink].lsu_link_ID, netIP);

		// Set link data.
		if (neighbor_tbl[neighborCount].type == OSPF_STUB)
		{
			uchar bcastmask[] = IP_BCAST_ADDR2; //MAC_BCAST_ADDR;
			COPY_IP(lsu_pkt->links[currentLink].lsu_link_data, bcastmask);
		}
		else // OSPF_ROUTER
		{
			interface_t* neighborInterface = findInterface(neighbor_tbl[neighborCount].interface);
			COPY_IP(lsu_pkt->links[currentLink].lsu_link_data, neighborInterface->ip_addr);
		}

		currentLink ++;
	}

	lsu_pkt->lsu_num_links = currentLink;

	int totalLength = sizeof(lsa_packet_t) + sizeof(lsu_packet_t);
	return createOSPFHeader(createLSAHeader(out_pkt, sourceIP), OSPF_LINK_STAT_UPDATE, totalLength, sourceIP);
}

gpacket_t* createLSAHeader(gpacket_t *gpkt, uchar sourceIP[])
{
	ospf_packet_t *ospf_pkt = (ospf_packet_t *)(gpkt->data.data);
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);

	lsa_pkt->lsa_age = 0;
	lsa_pkt->lsa_type = 1;
	lsa_pkt->lsa_sequence_number = globalSeqNum;
	globalSeqNum ++;
	lsa_pkt->lsa_checksum = 0;
	lsa_pkt->lsa_length = sizeof(lsu_packet_t);

	COPY_IP(lsa_pkt->lsa_ID, sourceIP);
	COPY_IP(lsa_pkt->lsa_advertising_number, sourceIP);
	return gpkt;
}

gpacket_t* createOSPFHeader(gpacket_t *gpacket, int type, int mlength, uchar sourceIP[])
{
	ospf_packet_t* header = (ospf_packet_t *)(gpacket->data.data);

	header->ospf_version = OSPF_VERSION;
	header->ospf_type = type;
	header->ospf_message_length = mlength + sizeof(ospf_packet_t);

	char tmpbuf[MAX_TMPBUF_LEN];
	COPY_IP(header->ospf_src, sourceIP);

	header->ospf_aid = OSPF_AREAID;
	header->ospf_auth_type = OSPF_AUTHTYPE;
	header->ospf_cksum = 0;

	gpacket->data.header.prot = htons(OSPF_PROTOCOL);

	return gpacket;
}

int OSPFSend2Output(gpacket_t *pkt)
{
	if (pkt == NULL)
	{
		verbose(1, "[OSPFSend2Output]:: NULL pointer error... nothing sent");
		return EXIT_FAILURE;
	}

	return writeQueue(pcore->outputQ, (void *)pkt, sizeof(gpacket_t));
}

// Adds an entry to the neighbor table with the specified IP, type, and interface.
// If an entry already exists with the specified IP, it is updated with the given type and interface.
// Either way, the entry is marked as "alive."
int addNeighborEntry(uchar* neighborIP_, int type_, int interface_)
{
	int i;
	int ifree = -1;

	int fresh = FALSE;

	// First check if the entry is already in the table, if it is, update it
	for (i = 0; i < MAX_ROUTES; i++)
	{
		if (neighbor_tbl[i].isEmpty == TRUE)
		{
			if (ifree < 0) ifree = i;
		}
		else if ((COMPARE_IP(neighborIP_, neighbor_tbl[i].neighborIP)) == 0)
		{ // match
	//		if (neighbor_tbl[i].isAlive == FALSE) fresh = TRUE;
			if (neighbor_tbl[i].type != type_) fresh = TRUE;

			neighbor_tbl[i].type = type_;
			neighbor_tbl[i].isAlive = TRUE;

	//		if (fresh != TRUE) verbose(1, "[addNeighborEntry]:: LS update did not contain new information. ");
		//	if (fresh == TRUE) verbose(1, "[addNeighborEntry]:: updated neighbor table entry #%d", i);
			return fresh;
		}
	}

	COPY_IP(neighbor_tbl[ifree].neighborIP, neighborIP_);
	neighbor_tbl[ifree].type = type_;
	neighbor_tbl[ifree].isEmpty = FALSE;
	neighbor_tbl[ifree].bidirectional = FALSE;
	neighbor_tbl[ifree].isAlive = TRUE;
	neighbor_tbl[ifree].interface = interface_;

	char tmpbuf[MAX_TMPBUF_LEN];
//	verbose(1, "[addNeighborEntry]:: added neighbor entry with IP %s", IP2Dot(tmpbuf, neighborIP_));
	return TRUE;
}

int getNeighborEntries(neighbor_entry_t buffer[])
{
	int count, bufferCount = 0;
	for (count = 0; count < MAX_ROUTES; count ++)
	{
		if (neighbor_tbl[count].isEmpty == TRUE /*|| neighbor_tbl[count].isAlive == FALSE*/) continue;

		COPY_IP(buffer[bufferCount].neighborIP, neighbor_tbl[count].neighborIP);
		buffer[bufferCount].interface = neighbor_tbl[count].interface;
		buffer[bufferCount].type = neighbor_tbl[count].type;

		bufferCount ++;
	}

	return bufferCount;
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
			verbose(1, "[addNeightborEntry]:: neighbor table entry #%d marked as dead ", count);
			break;
		}
	}
}

void OSPFSetStubNetwork(gpacket_t *pkt)
{
//	verbose(1, "[OSPFSetStubNetwork]:: received packet was using protocol %d", pkt->data.header.prot);
//	ip_packet_t *ip_pkt = (ip_packet_t *)pkt->data.data;

	int fresh = addNeighborEntry(pkt->frame.src_ip_addr, OSPF_STUB, pkt->frame.src_interface);

	if (fresh == TRUE)
	{
		char tmpbuf[MAX_TMPBUF_LEN];
		verbose(1, "[OSPFSetStubNetwork]:: Interface %d marked as stub with IP %s", pkt->frame.src_interface, IP2Dot(tmpbuf, pkt->frame.src_ip_addr));
	}
	broadcastLSUpdate(TRUE, NULL);
}

void printNeighborTable()
{
	int i, rcount = 0;
	char tmpbuf[MAX_TMPBUF_LEN];
	interface_t *iface;

	printf("\n=================================================================\n");
	printf("      N E I G H B O R   T A B L E \n");
	printf("-----------------------------------------------------------------\n");
	printf("Index\tNeighbor IP\tIs Alive\tType\tBidirectional\tInterface \n");

	for (i = 0; i < MAX_ROUTES; i++)
		if (neighbor_tbl[i].isEmpty != TRUE)
		{
			printf("[%d]\t%s\t%d\t\t%d\t\t%d\t%d\n", i, IP2Dot(tmpbuf, neighbor_tbl[i].neighborIP), neighbor_tbl[i].isAlive, neighbor_tbl[i].type, neighbor_tbl[i].bidirectional, neighbor_tbl[i].interface);
			rcount++;
		}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of neighbors found. \n", rcount);
}

// Gets the node from the graph with the supplied IP address, or NULL if it does not exist
ospf_gnode_t* getNode(uchar src[])
{
	int i;

	for (i=0; i<MAX_NODES; i++)
	{
		ospf_gnode_t *node = &(graph->nodes[i]);

		if (node == NULL || node -> is_empty)
		{
			continue;
		}

		else if ((COMPARE_IP(node -> src, src)) == 0)
		{
			return node;
		}
	}

	return NULL;
}

// Add a new node to the graph and return it
ospf_gnode_t* addNode(ospf_graph_t *graph, uchar src[])
{
	int i;
	ospf_gnode_t *node;

	// Check for an unused node
	for (i=0; i<MAX_NODES; i++)
	{
		node = &graph -> nodes[i];

		if (node -> is_empty)
		{
			break;
		}
	}

	node -> is_empty = FALSE;
	COPY_IP(node -> src, src);

//	verbose(1, "[addNode]:: node added");

	return node;
}

// Update the reachable networks of the given node
void updateLinkData(lsu_packet_t *lsu_pkt, ospf_gnode_t *node)
{
	int i, num_links;

	num_links  = lsu_pkt -> lsu_num_links;

	for (i=0; i<num_links; i++)
	{
		lsu_link_t link = lsu_pkt->links[i];

		COPY_IP(node->networks[i], link.lsu_link_ID);
		node->types[i] = link.lsu_link_type;
	}

	node -> num_networks = num_links;

//	verbose(1, "[updateLinkData]:: link data updated");
}

void removeNodes(ospf_graph_t *graph, uchar ip[4])
{
	int i;

	ospf_gnode_t *node;

	// Check for an unused node
	for (i=0; i<MAX_NODES; i++)
	{
		node = &graph -> nodes[i];

		if (node -> is_empty)
		{
			return;
		}

		if (node -> src[0] == ip[0])
		{
			node -> is_empty = TRUE;
		}
	}
}

// Update the edges of the graph
void updateEdges(ospf_graph_t *graph, ospf_gnode_t *node)
{
	int i, j, k, num_networks, crt_num_networks;
	uchar crt_networks[MAX_ROUTES][4];
	uchar networks[MAX_ROUTES][4];
	uchar crt_addr[4];

	num_networks = node -> num_networks;

	// Compare the reachable networks of the given node to the reachable networks of all other nodes in the graph
	// If there are any matches, then create an edge between those nodes.
	for (i=0; i<MAX_NODES; i++)
	{
		ospf_gnode_t *crt_node = &graph -> nodes[i];

		if (crt_node == NULL || crt_node -> is_empty)
		{
			continue;
		}

		if (COMPARE_IP(crt_node -> src, node -> src) == 0)
		{
			continue;
		}

		crt_num_networks = crt_node -> num_networks;

		for (j=0; j<num_networks; j++)
		{
			for (k=0; k<crt_num_networks; k++)
			{
				char tmpbuf[MAX_TMPBUF_LEN];
			//	verbose(1, "[updateEdges]:: comparing %s with %s.", IP2Dot(tmpbuf, node -> networks[j]), IP2Dot(tmpbuf+20, crt_node -> networks[k]));

				if (COMPARE_IP(node -> networks[j], crt_node -> networks[k]) == 0)
				{
					addEdge(node -> src, crt_node -> src);
					continue;
				}
			}
		}
	}

	//verbose(1, "[updateEdges]:: edges updated");
}

// Add an edge to the graph
void addEdge(uchar addr1[], uchar addr2[])
{
	//verbose(1, "613");
	uchar interfaceIPs[MAX_MTU][4];
	int	totalInterfaceIPs = findAllInterfaceIPs(MTU_tbl, interfaceIPs);

	if (containsIP(interfaceIPs, addr1, totalInterfaceIPs) == TRUE && containsIP(interfaceIPs, addr2, totalInterfaceIPs) == TRUE)
	{
		return;
	}

	if (containsIP(interfaceIPs, addr1, totalInterfaceIPs == TRUE))
	{
		if (isNeighbor(addr2) == FALSE)
		{
			return;
		}
	}

	if (containsIP(interfaceIPs, addr2, totalInterfaceIPs == TRUE))
	{
		if (isNeighbor(addr1) == FALSE)
		{
			return;
		}
	}

	if (addr1[1] != addr2[1])
	{
		return;
	}

	int i;
	//verbose(1, "623");
	for (i=0; i<MAX_EDGES; i++)
	{
		ospf_gedge_t *edge = &graph -> edges[i];
		//verbose(1, "627");
		if (edge -> is_empty)
		{
			COPY_IP(edge -> addr1, addr1);
			COPY_IP(edge -> addr2, addr2);
			edge -> is_empty = FALSE;
			//verbose(1, "[addEdges]:: edge added");
			return;
		}
	}
}

void removeEdges(ospf_graph_t *graph, uchar ip[4])
{
	int i;

	for (i=0; i<MAX_EDGES; i++)
	{
		ospf_gedge_t *edge = &graph -> edges[i];

		if (edge -> is_empty == TRUE)
		{
			continue;
		}

		if (edge -> addr1[0] == ip[0] || edge -> addr2[0] == ip[0])
		{
			edge -> is_empty = TRUE;
		}
	}
}

void removeIPFromGraph(uchar ip[4])
{
	char tmpbuf[MAX_TMPBUF_LEN];
	verbose(1, "Neighbor down, removing all nodes and edges related to %s", IP2Dot(tmpbuf, ip));

	int i, numNodeIPs;
	uchar ips[MAX_NODES][4];

	numNodeIPs = getAllIpsFromNode(graph, ip, ips);

	for (i=0; i<numNodeIPs; i++)
	{
		removeNodes(graph, ips[i]);
		removeEdges(graph, ips[i]);
	}

	updateRoutingTable(graph);
}

int containsIP(uchar ip_list[][4], uchar *ip, int list_size)
{
	char tmpbuf[MAX_TMPBUF_LEN];
	int i;

	for (i=0; i<list_size; i++)
	{
		// verbose(1, "comparing %s with %s", IP2Dot(tmpbuf, ip_list[i]), IP2Dot(tmpbuf+20, ip));

		if (COMPARE_IP(ip_list[i], ip) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

void updateRoutingTable(ospf_graph_t *graph)
{
	char tmpbuf[MAX_TMPBUF_LEN];
	int i, j, totalInterfaceIPs, num_neighbors, cost, vindex = 0;
	uchar interfaceIPs[MAX_MTU][4];
	ospf_gnode_t *this_node;
	ospf_gnode_t* neighbors[MAX_ROUTES];
	uchar visited[MAX_NODES][4];
	uchar null_ip_addr[] = ZEROED_IP;

	for (i=0; i<MAX_NODES; i++)
	{
		COPY_IP(visited[i], null_ip_addr);
	}

	cost = 1;

	// reset routing table to be empty
	RouteTableInit(route_tbl);

	// reset cost table
	for(i = 0; i < MAX_ROUTES; i++)
	{
		cost_tbl[i].is_empty = TRUE;
	}

	totalInterfaceIPs = findAllInterfaceIPs(MTU_tbl, interfaceIPs); // get num links

	// verbose(1, "found %d interfaces", totalInterfaceIPs);

	// for (i=0; i<totalInterfaceIPs; i++)
	// {
	// 	verbose(1, "IP-%d: \t %s", i, IP2Dot(tmpbuf, interfaceIPs[i]));
	// }

	for (i=0; i<totalInterfaceIPs; i++)
	{
		this_node = getNode(interfaceIPs[i]);

		if (this_node == NULL)
		{
			// verbose(1, "762 - node is null");

			continue;
		}

		findNetworks(graph, this_node, visited, vindex, cost);

		// break;
	}
}

void findNetworks(ospf_graph_t *graph, ospf_gnode_t *node, uchar visited[][4], int vindex, int cost)
{
	char tmpbuf[MAX_TMPBUF_LEN];
	int i, j, interface, totalInterfaceIPs, numNodeIPs, nxtHopPos = 0;
	uchar ips[MAX_NODES][4];
	uchar interfaceIPs[MAX_MTU][4];
	uchar null_ip_addr[] = ZEROED_IP;
	uchar netmask[] = IP_BCAST_ADDR2;
	uchar neighbor[4];

	COPY_IP(visited[vindex], node -> src);
	vindex++;

	// verbose(1, "searching from node with ip %s", IP2Dot(tmpbuf, node -> src));

	// for (i=0; i<vindex; i++)
	// {
	// 	verbose(1, "visited: %s", IP2Dot(tmpbuf, visited[i]));
	// }

	// if this is the original router
	if (vindex == 1)
	{
		// verbose(1, "scanning through %d networks\n",  node -> num_networks);

		for (i=0; i<node -> num_networks; i++)
		{
			// get the interface ID to this network
			interface = getIfaceIDByNetwork(node -> networks[i]);

			// verbose(1, "getting interface of the network %s, found %d\n",  IP2Dot(tmpbuf, node -> networks[i]), interface);

			// add the entry to the cost table and routing table
			if (isCheaper(cost_tbl, node -> networks[i], cost) == TRUE)
			{
				addRouteEntry(route_tbl, node -> networks[i], netmask, null_ip_addr, interface);
			}
		}
	}
	else
	{
		totalInterfaceIPs = findAllInterfaceIPs(MTU_tbl, interfaceIPs);

		// for (i=0; i<totalInterfaceIPs; i++)
		// {
		// 	if (containsIP(visited, interfaceIPs[i], vindex) == TRUE)
		// 	{
		// 		nxtHopPos++;
		// 	}
		// }

		for (i=0; i<vindex; i++)
		{
			if (containsIP(interfaceIPs, visited[i], totalInterfaceIPs) == TRUE)
			{
				nxtHopPos++;
			}
			else
			{
				break;
			}
		}


		for (i=0; i<node -> num_networks; i++)
		{
			// get the interface ID to this network
			interface = getIfaceIDByIP(visited[nxtHopPos]);

			// verbose(1, "859getting the interface to %s, found %d\n",  IP2Dot(tmpbuf, visited[nxtHopPos]), interface);

			// add the entry to the cost table and routing table
			if (isCheaper(cost_tbl, node -> networks[i], cost) == TRUE)
			{
				addRouteEntry(route_tbl, node -> networks[i], netmask, visited[nxtHopPos], interface);
			}
		}
	}

	numNodeIPs = getAllIpsFromNode(graph, node -> src, ips);

	cost++;

	for (i=0; i<numNodeIPs; i++)
	{

		ospf_gnode_t *nxt_node = getNode(ips[i]);

		// verbose(1, "checking neighbors from %s", IP2Dot(tmpbuf, ips[i]));

		if (getNodeNeighbor(graph, nxt_node, neighbor) == FALSE)
		{
			// verbose(1, "no neighbor found.");
			continue;
		}

		if (containsIP(visited, neighbor, vindex) == TRUE)
		{
			// verbose(1, "neighbor %s already visited in list of size %d", IP2Dot(tmpbuf, neighbor), vindex);
			continue;
		}

		// verbose(1, "found a neighbor - %s", IP2Dot(tmpbuf, neighbor));

		COPY_IP(visited[vindex], ips[i]);
		vindex++;

		// verbose(1, "checking neighbor with IP %s\n",  IP2Dot(tmpbuf, neighbor));

		findNetworks(graph, getNode(neighbor), visited, vindex, cost);
	}
}

int getNodeNeighbor(ospf_graph_t *graph, ospf_gnode_t *node, uchar neighbor[4])
{
	char tmpbuf[MAX_TMPBUF_LEN];
	// verbose(1, "getting neighbor of %s\n",  IP2Dot(tmpbuf, node -> src));

	int i, j;

	for (i=0; i<MAX_EDGES; i++)
	{
		ospf_gedge_t *edge = &graph -> edges[i];

		if (edge -> is_empty == TRUE)
		{
			continue;
		}

		if (COMPARE_IP(node -> src, edge -> addr1) == 0 || COMPARE_IP(node -> src, edge -> addr2) == 0)
		{
			if (COMPARE_IP(node -> src, edge -> addr1) == 0)
			{
				COPY_IP(neighbor, edge -> addr2);
			}
			else
			{

				COPY_IP(neighbor, edge -> addr1);
			}

			return TRUE;
		}
	}

	return FALSE;
}

int getAllIpsFromNode(ospf_graph_t *graph, uchar *addr, uchar ips[][4])
{
	int i, ncount = 0;

	for (i=0; i<MAX_NODES; i++)
	{
		if (graph -> nodes[i].is_empty == TRUE)
		{
			continue;
		}

		if (graph -> nodes[i].src[0] == addr[0])
		{
			COPY_IP(ips[ncount], graph -> nodes[i].src);
			ncount++;
		}
	}

	return ncount;
}

int getIfaceIDByNetwork(uchar *net_addr)
{
	int i;
	uchar netmask[] = IP_BCAST_ADDR2;

	for (i=0; i<MAX_ROUTES; i++)
	{
		if (neighbor_tbl[i].isEmpty == TRUE)
		{
			continue;
		}

		char tmpbuf[MAX_TMPBUF_LEN];
		// verbose(1, "Comparing neighbor IP %s with net address %s.", IP2Dot(tmpbuf, neighbor_tbl[i].neighborIP), IP2Dot(tmpbuf+20, net_addr));

		if (compareIPUsingMask(neighbor_tbl[i].neighborIP, net_addr, netmask) == 0)
		{
			// verbose(1, "Found match, interface is %d.", neighbor_tbl[i].interface);

			return neighbor_tbl[i].interface;
		}
	}

	// return -1;
}

int getIfaceIDByIP(uchar *ip_addr)
{
	int i;

	for (i=0; i<MAX_ROUTES; i++)
	{
		if (neighbor_tbl[i].isEmpty == TRUE)
		{
			continue;
		}

		if (COMPARE_IP(neighbor_tbl[i].neighborIP, ip_addr) == 0)
		{
			return neighbor_tbl[i].interface;
		}
	}

	// return -1;
}

int isNeighbor(uchar *ip)
{
	int i;

	for (i = 0; i < MAX_ROUTES; ++i)
	{
		if (neighbor_tbl[i].isEmpty == TRUE)
		{
			continue;
		}

		if (COMPARE_IP(neighbor_tbl[i].neighborIP, ip) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

int isCheaper(ospf_cost_entry_t ctable[], uchar *dest_ip_, int cost_)
{
	char tmpbuf[MAX_TMPBUF_LEN];
	int i, free_index;

	for (i=0; i<MAX_ROUTES; i++)
	{
		if (ctable[i].is_empty == TRUE)
		{
			free_index = i;
			continue;
		}

		if (COMPARE_IP(dest_ip_, ctable[i].dest_ip) == 0)
		{
			if (cost_ < ctable[i].cost)
			{
				ctable[i].cost = cost_;
				return TRUE;

				// verbose(1, "updating routing table entry for network %s\n",  IP2Dot(tmpbuf, dest_ip_));
			}
			else
			{
				return FALSE;
			}
		}
	}

	// verbose(1, "adding routing table entry for network %s\n",  IP2Dot(tmpbuf, dest_ip_));

	// If entry for this network does not exist, add it
	ctable[free_index].is_empty = FALSE;
	COPY_IP(ctable[free_index].dest_ip, dest_ip_);
	ctable[free_index].cost = cost_;
	return TRUE;


}

void printGraphNodes(ospf_graph_t *graph)
{
	int i, ncount = 0;
	char tmpbuf[MAX_TMPBUF_LEN];
	ospf_gnode_t *node;

	printf("\n=================================================================\n");
	printf("      G R A P H   N O D E S \n");
	printf("-----------------------------------------------------------------\n");
	printf("Index\tIP\t\tLSN\t\tNum Networks \n");

	for (i = 0; i < MAX_NODES; i++)
		if (graph -> nodes[i].is_empty != TRUE)
		{
			node = &graph -> nodes[i];
			printf("[%d]\t%s\t%d\t\t%d\n", i, IP2Dot(tmpbuf, node -> src),
			       node -> last_LSN, node -> num_networks);
			ncount++;

			// printNodeNetworks(node);
		}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of nodes found. \n", ncount);
	return;
}

void printGraphEdges(ospf_graph_t *graph)
{
	int i, ecount = 0;
	char tmpbuf[MAX_TMPBUF_LEN];
	ospf_gedge_t *edge;

	printf("\n=================================================================\n");
	printf("      G R A P H   E D G E S \n");
	printf("-----------------------------------------------------------------\n");
	printf("Index\tIP 1\t\tIP 2 \n");

	for (i = 0; i < MAX_EDGES; i++)
		if (graph -> edges[i].is_empty != TRUE)
		{
			edge = &graph -> edges[i];
			printf("[%d]\t%s\t%s\n", i, IP2Dot(tmpbuf, edge -> addr1),
			       IP2Dot((tmpbuf+20), edge -> addr2));
			ecount++;
		}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of edges found. \n", ecount);
	return;
}

void printCostTable(ospf_graph_t *graph)
{
	int i, ecount = 0;
	char tmpbuf[MAX_TMPBUF_LEN];

	printf("\n=================================================================\n");
	printf("     C O S T   T A B L E \n");
	printf("-----------------------------------------------------------------\n");
	printf("Index\tIP\t\tCost \n");

	for (i = 0; i < MAX_ROUTES; i++)
		if (cost_tbl[i].is_empty != TRUE)
		{
			printf("[%d]\t%s\t%d\n", i, IP2Dot(tmpbuf, cost_tbl[i].dest_ip),
			        cost_tbl[i].cost);
			ecount++;
		}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of entries found. \n", ecount);
	return;
}

void printNodeNetworks(ospf_gnode_t *node)
{
	int i, num_networks, ncount = 0;
	char tmpbuf[MAX_TMPBUF_LEN];

	num_networks = node -> num_networks;

	printf("\n=================================================================\n");
	printf("      R E A C H A B L E   N E T W O R K S \n");
	printf("-----------------------------------------------------------------\n");
	printf("Index\tIP \n");

	for (i = 0; i < num_networks; i++)
	{
		printf("[%d]\t%s\n", i, IP2Dot(tmpbuf, node -> networks[i]));
		ncount++;
	}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of networks found. \n", ncount);
	return;
}
