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

	for (i=0; i<MAX_ROUTES; i++)
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

	if (ospf_pkt->ospf_type == OSPF_HELLO)
	{
		verbose(1, "[OSPFIncomingPacket]:: received OSPF Hello message");
		OSPFProcessHelloMessage(pkt);
	}
	else if (ospf_pkt->ospf_type == OSPF_LINK_STAT_UPDATE)
	{
		verbose(1, "[OSPFIncomingPacket]:: received OSPF link state update");
		OSPFProcessLSUpdate(pkt);
	}
	else
	{
		verbose(1, "[OSPFIncomingPacket]:: unknown OSPF packet received");
	}
}

void OSPFProcessHelloMessage(gpacket_t *pkt)
{
	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt->data.data;
    hello_packet_t *hello_pkt = (hello_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);

	// update neighbor database
	int newUpdate = addNeighborEntry(ospf_pkt->ospf_src, OSPF_ROUTER, pkt->frame.src_interface);

	verbose(1, "Analyzing hello packet");
	int count;
	for (count = 0; count < hello_pkt->hello_numneighbors; count ++)
	{
		verbose(1, "Looking at received hello packet neighbor %d", count);
		if (COMPARE_IP(pkt->frame.nxth_ip_addr, hello_pkt->hello_neighbors[count]) == 0)
		{ // the IP the packet is sending to is also contained in its neighbor table.
			// therefore, it knows about this router, and we know about it (entry added above)
			// so we have bidirectionality
			
			verbose(1, "This router's IP matches an IP in received hello packet neighbor table.");

			for (count = 0; count < MAX_ROUTES; count ++)
			{
				if (neighbor_tbl[count].isEmpty == TRUE || neighbor_tbl[count].isAlive == FALSE) continue;

				if (COMPARE_IP(neighbor_tbl[count].neighborIP, ospf_pkt->ospf_src) == 0)
				{
					verbose(1, "[OSPFProcessHelloMessage]:: We got bidirectionality with neighbor index %d.", count);
					neighbor_tbl[count].bidirectional = TRUE;
				}
			}
		}
	}

	if (newUpdate)
	{ // if it's a new update, then send out a new link state update to all neighbors.
		verbose(1, "[OSPFProcessHelloMessage]:: Broadcasting new LS Update since we got new information.");
		broadcastLSUpdate(TRUE, NULL);
	}
}

void OSPFProcessLSUpdate(gpacket_t *pkt)
{
	verbose(1, "[OSPFProcessLSUpdate]:: Received LS update");

	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt -> data.data;
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + ospf_pkt -> ospf_message_length*4);
	lsu_packet_t *lsu_pkt = (lsu_packet_t *)((uchar *)lsa_pkt + lsa_pkt -> lsa_header_length*4);

	uchar src[4];
	COPY_IP(src, ospf_pkt->ospf_src); // get src address

	// check if node with the address already exists
	ospf_gnode_t *node = (ospf_gnode_t *)getNode(graph, src);

	// if the node exists and the last sequence number received by the node is greater or equal to the current sequence number, ignore it
	if (node != NULL)
	{
		if (node -> last_LSN >= lsa_pkt->lsa_sequence_number)
		{
			verbose(1, "[OSPFProcessLSUpdate]:: LS update is old so we are dropping it.");
			return;
		}
	}
	// if the node doesn't exist, create it
	else
	{
		node = (ospf_gnode_t *)addNode(graph, src);
	}
	verbose(1, "HERE");
	printLSData(pkt);

	node -> last_LSN = lsa_pkt->lsa_sequence_number;

	verbose(1, "[OSPFProcessLSUpdate]:: New node created.");

	// update the reachable networks of the node
	updateLinkData(lsu_pkt, node);

	// update the edges of the graph
	updateEdges(graph, node);

	// update the routing table
	updateRoutingTable(graph);

	// forward the update packet
	broadcastLSUpdate(FALSE, pkt);
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
	hello_pkt->hello_numneighbors = numEntries;

	int count;
	for (count = 0; count < numEntries; count ++)
	{
		COPY_IP(hello_pkt->hello_neighbors[count], neighborEntries[count].neighborIP);
	}

	uchar bcast_addr[6];
	memset(bcast_addr, 0xFF, 6);

	char tmpbuf[MAX_TMPBUF_LEN];
	verbose(1, "[OSPFSendHelloPacket]:: Broadcasting Hello packet with source IP %s", IP2Dot(tmpbuf, gNtohl((uchar *)tmpbuf, src_ip)));

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
			|| neighbor_tbl[count].isAlive == FALSE
			|| neighbor_tbl[count].type == OSPF_STUB
			|| neighbor_tbl[count].bidirectional == FALSE) continue;

		char tmpbuf[MAX_TMPBUF_LEN];
		verbose(1, "[broadcastLSUpdate]:: Sending LS update to IP %s.", IP2Dot(tmpbuf, gNtohl((uchar *)tmpbuf, neighbor_tbl[count].neighborIP)));

		if (createPacket)
		{
			pkt = createLSUPacket(neighbor_tbl[count].neighborIP);
			verbose(1, "[broadcastLSUpdate]:: Creating update from scratch");
			printLSData(pkt);
		}

		COPY_IP(pkt->frame.nxth_ip_addr, gHtonl(tmpbuf, neighbor_tbl[count].neighborIP));
		pkt->frame.dst_interface = neighbor_tbl[count].interface;

		OSPFSend2Output(pkt);
	}
	if (count == 0) verbose(1, "[broadcastLSUpdate]:: Wanted to send LS update, but have no neighbors to send it to :( ");
}

void printLSData(gpacket_t *pkt)
{
	ospf_packet_t *ospf_pkt = (ospf_packet_t*) &pkt -> data.data;
	lsa_packet_t *lsa_pkt = (lsa_packet_t *)((uchar *)ospf_pkt + ospf_pkt->ospf_message_length*4);
	lsu_packet_t *lsu_pkt = (lsu_packet_t *)((uchar *)lsa_pkt + lsa_pkt->lsa_header_length*4);
	
	printf("LINK STATE DATA");
	
	verbose(1, "=================================================================");
	verbose(1, "               L I N K   S T A T E   D A T A \n");
	verbose(1, "-----------------------------------------------------------------");
	verbose(1, "Index\tLink IDt\tLink Data\tType");

	int count;
	char tmpbuf[MAX_TMPBUF_LEN];
	for (count = 0; count < lsu_pkt->lsu_num_links; count ++)
	{
		verbose(1, "[%d]\t%s\t%s\t%d", count, IP2Dot(tmpbuf, lsu_pkt->links[count].lsu_link_ID), IP2Dot(tmpbuf, lsu_pkt->links[count].lsu_link_data), lsu_pkt->links[count].lsu_link_type);
	}
	verbose(1, "-----------------------------------------------------------------\n");
}

gpacket_t* createLSUPacket(uchar sourceIP[])
{
	verbose(1, "[createLSUPacket]:: Creating LSU packet");
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
		if (neighbor_tbl[neighborCount].isEmpty == TRUE || neighbor_tbl[neighborCount].isAlive == FALSE) continue;

		lsu_pkt->links[currentLink].lsu_metric = 1;
		lsu_pkt->links[currentLink].lsu_link_type = neighbor_tbl[neighborCount].type;
		if (neighbor_tbl[neighborCount].type == OSPF_STUB)
		{
			uchar bcastmask[] = MAC_BCAST_ADDR;
			COPY_IP(lsu_pkt->links[currentLink].lsu_link_data, bcastmask);
		}
		else
		{ // for a router addr 192.168.x.y, we want link data to be set 192.168.x.0
			uchar netIP[4];
			COPY_IP(netIP, neighbor_tbl[neighborCount].neighborIP);
			netIP[3] = '0';
			COPY_IP(lsu_pkt->links[currentLink].lsu_link_ID, netIP);
		}
		COPY_IP(lsu_pkt->links[currentLink].lsu_link_ID, neighbor_tbl[neighborCount].neighborIP);

		currentLink ++;
	}

	lsu_pkt->lsu_num_links = currentLink - 1;

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
			if (neighbor_tbl[i].isAlive == FALSE) fresh = TRUE;
			else if (neighbor_tbl[i].type != type_) fresh = TRUE;

			neighbor_tbl[i].type = type_;
			neighbor_tbl[i].isAlive = TRUE;

			if (fresh == TRUE) verbose(1, "[addNeighborEntry]:: updated neighbor table entry #%d", i);
			else verbose(1, "[addNeighborEntry]:: LS update did not contain new information. ");
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
	verbose(1, "[addNeighborEntry]:: added neighbor entry with IP %s", IP2Dot(tmpbuf, neighborIP_));
	return TRUE;
}

int getNeighborEntries(neighbor_entry_t buffer[])
{
	int count, bufferCount = 0;
	for (count = 0; count < MAX_ROUTES; count ++)
	{
		if (neighbor_tbl[count].isEmpty == TRUE || neighbor_tbl[count].isAlive == FALSE) continue;

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
	ip_packet_t *ip_pkt = (ip_packet_t *)pkt->data.data;
	
	addNeighborEntry(ip_pkt->ip_src, OSPF_STUB, pkt->frame.src_interface);
	
	char tmpbuf[MAX_TMPBUF_LEN];
	verbose(1, "[OSPFSetStubNetwork]:: Interface %d marked as stub with IP %s", pkt->frame.src_interface, IP2Dot(tmpbuf, ip_pkt->ip_src));
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
			printf("[%d]\t%s\t%d\t\t%d\t\n", i, IP2Dot(tmpbuf, neighbor_tbl[i].neighborIP), neighbor_tbl[i].isAlive, neighbor_tbl[i].type);
			rcount++;
		}
	printf("-----------------------------------------------------------------\n");
	printf("      %d number of neighbors found. \n", rcount);
}

// Gets the node from the graph with the supplied IP address, or NULL if it does not exist
ospf_gnode_t* getNode(ospf_graph_t *graph, uchar src[])
{
	int i;

	for (i=0; i<MAX_ROUTES; i++)
	{
		ospf_gnode_t *node = &graph -> nodes[i];

		if (node -> is_empty)
		{
			continue;
		}

		if ((COMPARE_IP(node -> src, src)) == 0)
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
	for (i=0; i<MAX_ROUTES; i++)
	{
		node = &graph -> nodes[i];

		if (node -> is_empty)
		{
			break;
		}
	}

	node -> is_empty = FALSE;
	COPY_IP(node -> src, src);

	verbose(1, "[addNode]:: node added");

	return node;
}

// Update the reachable networks of the given node
void updateLinkData(lsu_packet_t *lsu_pkt, ospf_gnode_t *node)
{
	int i, num_links;

	num_links  = lsu_pkt -> lsu_num_links;

	for (i=0; i<num_links; i++)
	{
		lsu_link_t *link = &lsu_pkt -> links[i];

		COPY_IP(node -> networks[i], link -> lsu_link_ID);
		node -> types[i] = link -> lsu_link_type;
	}

	node -> num_networks = num_links;

	verbose(1, "[updateLinkData]:: link data updated");
}

// Update the edges of the graph
void updateEdges(ospf_graph_t *graph, ospf_gnode_t *node)
{
	int i, j, k, num_networks, crt_num_networks;
	uchar crt_networks[MAX_ROUTES][4];
	uchar networks[MAX_ROUTES][4];
	uchar crt_addr[4];

	// First free all edges currently in the graph that contain the given node
	for (i=0; i<MAX_EDGES; i++)
	{
		ospf_gedge_t *edge = &graph -> edges[i];

		if (edge -> is_empty == TRUE)
		{
			continue;
		}

		if (COMPARE_IP(edge -> addr1, node -> src) == 0 || COMPARE_IP(edge -> addr2, node -> src) == 0)
		{
			edge -> is_empty = TRUE;
		}
	}

	num_networks = node -> num_networks;

	// Compare the reachable networks of the given node to the reachable networks of all other nodes in the graph
	// If there are any matches, then create an edge between those nodes.
	for (i=0; i<MAX_ROUTES; i++)
	{
		ospf_gnode_t *crt_node = &graph -> nodes[i];

		if (crt_node -> is_empty)
		{
			continue;
		}

		crt_num_networks = crt_node -> num_networks;

		for (j=0; j<num_networks; j++)
		{
			for (k=0; j<crt_num_networks; k++)
			{
				if (COMPARE_IP(node -> networks[j], crt_node -> networks[k]) == 0)
				{
					addEdge(node -> src, crt_node -> src);
					continue;
				}
			}
		}
	}

	verbose(1, "[updateEdges]:: edges updated");
}

// Add an edge to the graph
void addEdge(uchar *addr1, uchar *addr2)
{
	int i;

	for (i=0; i<MAX_EDGES; i++)
	{
		ospf_gedge_t *edge = &graph -> edges[i];

		if (edge -> is_empty)
		{
			COPY_IP(edge -> addr1, addr1);
			COPY_IP(edge -> addr2, addr2);
			edge -> is_empty = FALSE;
			verbose(1, "[addEdges]:: edge added");
			return;
		}
	}
}

void updateRoutingTable(ospf_graph_t *graph)
{
	int i, totalInterfaceIPs, num_neighbors, cost;
	uchar interfaceIPs[MAX_MTU][4];
	ospf_gnode_t *this_node;
	uchar null_ip_addr[] = {0, 0, 0, 0};
	uchar netmask[] = {255, 255, 255, 0};
	ospf_gnode_t* neighbors[MAX_ROUTES];

	cost = 1;

	// reset routing table to be empty
	RouteTableInit(route_tbl);

	// reset graph traversal
	uncheckNodes(graph);

	// reset cost table
	for(i = 0; i < MAX_ROUTES; i++)
	{
		cost_tbl[i].is_empty = TRUE;
	}

	totalInterfaceIPs = findAllInterfaceIPs(MTU_tbl, interfaceIPs); // get num links

	// find a node corresponding to this router
	for (i=0; i<totalInterfaceIPs; i++)
	{
		this_node = (ospf_gnode_t *)getNode(graph, interfaceIPs[i]);
		if (this_node != NULL)
		{
			break;
		}
	}

	// If the graph does not contain a node for this router yet, do nothing
	if (this_node == NULL)
	{
		return;
	}

	for (i=0; i<this_node -> num_networks; i++)
	{
		// get the interface ID to this network
		int interface = getIfaceIDByNetwork(this_node -> networks[i]);

		// add the entry to the cost table and routing table
		if (isCheaper(cost_tbl, this_node -> networks[i], cost))
		{
			addRouteEntry(route_tbl, this_node -> networks[i], netmask, null_ip_addr, interface);
			verbose(1, "[updateRoutingTable]:: New route entry added.");
		}
	}

	// mark this node as visited
	this_node -> checked = TRUE;

	// get the neighbors of this node
	num_neighbors = getNodeNeighbors(graph, this_node, neighbors);

	for (i=0; i<num_neighbors; i++)
	{
		// ignore already visited neighbors
		if (neighbors[i]->checked == TRUE)
		{
			continue;
		}

		cost++;

		// Search for new reachable networks from each neighbor
		findNetworks(graph, neighbors[i], neighbors[i]->src, getIfaceIDByIP(neighbors[i]->src), cost);
	}
}

int getNodeNeighbors(ospf_graph_t *graph, ospf_gnode_t *node, ospf_gnode_t* neighbors[])
{
	int i, ncount = 0;

	// Search through the edges of the graph for any which contain the given node as a vertex
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
				neighbors[ncount] = getNode(graph, edge -> addr2);
			}
			else
			{
				neighbors[ncount] = getNode(graph, edge -> addr1);
			}

			ncount++;
		}
	}

	return ncount;
}

void findNetworks(ospf_graph_t *graph, ospf_gnode_t *node, uchar *nxt_hop, int iface, int cost)
{
	int i, num_neighbors;
	uchar netmask[] = {255, 255, 255, 0};
	ospf_gnode_t* neighbors[MAX_ROUTES];

	// mark node as visited
	node -> checked = TRUE;

	for (i=0; i<node -> num_networks; i++)
	{
		// For each reachable network from this node, add it to the routing table if
		// it does not already exist, otherwise update if the current path is cheaper
		if (isCheaper(cost_tbl, node -> networks[i], cost))
		{
			addRouteEntry(route_tbl, node -> networks[i], netmask, nxt_hop, iface);
			verbose(1, "[findNetworks]:: Routing table and cost table updated.");
		}
	}

	num_neighbors = getNodeNeighbors(graph, node, neighbors);

	for (i=0; i<num_neighbors; i++)
	{
		// ignore already visited neighbors
		if (neighbors[i]->checked == TRUE)
		{
			continue;
		}

		cost++;

		findNetworks(graph, neighbors[i], nxt_hop, iface, cost);
	}
}

int getIfaceIDByNetwork(uchar *net_addr)
{
	int i;
	uchar netmask[] = {255,255,255,0};

	for (i=0; i<MAX_ROUTES; i++)
	{
		if (compareIPUsingMask(neighbor_tbl[i].neighborIP, net_addr ,netmask) == 0)
		{
			return neighbor_tbl[i].interface;
		}
	}
}

int getIfaceIDByIP(uchar *ip_addr)
{
	int i;

	for (i=0; i<MAX_ROUTES; i++)
	{
		if (COMPARE_IP(neighbor_tbl[i].neighborIP, ip_addr) == 0)
		{
			return neighbor_tbl[i].interface;
		}
	}
}

void uncheckNodes(ospf_graph_t *graph)
{
	int i;

	for (i=0; i<MAX_ROUTES; i++)
	{
		graph -> nodes[i].checked = FALSE;
	}
}

int isCheaper(ospf_cost_entry_t ctable[], uchar *dest_ip_, int cost_)
{
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
			}
			else
			{
				return FALSE;
			}
		}
	}

	// If entry for this network does not exist, add it
	ctable[free_index].is_empty = FALSE;
	COPY_IP(ctable[free_index].dest_ip, dest_ip_);
	ctable[free_index].cost = cost_;
	return TRUE;
}
