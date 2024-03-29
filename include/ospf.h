#ifndef __OSPF_H_
#define __OSPF_H_

#include "grouter.h"
#include "message.h"
#include "routetable.h"
#include <stdint.h>

#define OSPF_HELLO       	  	 1      /* Hello           	       	    */
#define OSPF_DB_DSC     	   	 2      /* Database description         */
#define OSPF_LINK_STAT_REQUEST   3      /* Link status request	        */
#define OSPF_LINK_STAT_UPDATE    4      /* Link status update           */
#define OSPF_LINK_STAT_ACK       5      /* Link status acknowledgement  */

#define OSPF_VERSION		 2
#define OSPF_AREAID			 0
#define OSPF_AUTHTYPE		 0

#define OSPF_ROUTER			 2
#define OSPF_STUB			 3

#define MAX_NODES			 (MAX_ROUTES * MAX_ROUTES)
#define MAX_EDGES			 ((MAX_ROUTES * (MAX_ROUTES-1)) / 2)

#define ZEROED_IP	  		{0x00, 0x00, 0x00, 0x00}

typedef struct _neighbor_entry_t
{
	bool isEmpty; // indicates whether entry is free or not
	uchar neighborIP[4];
	bool isAlive;
	int type; // either OSPF_ROUTER or OSPF_STUB
	int interface;
	int bidirectional;
} neighbor_entry_t;

typedef struct _lsu_link_t
{
	uchar lsu_link_ID[4]; // network address
	uchar lsu_link_data[4]; // the router address for any-to-any networks and network mask for stub networks
	uint8_t lsu_link_type; // either OSPF_ROUTER or OSPF_STUB
	uint8_t lsu_metric;
} lsu_link_t;

typedef struct _lsu_packet_t
{
	uint8_t lsu_num_links;
	lsu_link_t links[DEFAULT_MTU/2];
} lsu_packet_t;

typedef struct _lsa_packet_t
{
	uint8_t lsa_header_length;
	uint8_t lsa_age;
	uint8_t lsa_type; //cant have :0 that means 0 bytes
	uchar lsa_ID[4]; // ip of originating router
	uchar lsa_advertising_number[4]; // same as above
	uint8_t lsa_sequence_number; // always incrementing by 1
	uint8_t lsa_checksum;
	uint16_t lsa_length;
} lsa_packet_t;

typedef struct _hello_neighbor_t
{
	uchar neighbor_ip[4];
} hello_neighbor_t;

typedef struct _hello_packet_t
{
	uchar    hello_network_mask[4];            // network mask - ALWAYS 255.255.255.0
	uint16_t hello_hello_interval;          // hello interval - ALWAYS 10
	uint8_t  hello_options;                 // options - ALWAYS 0
	uint8_t  hello_priority;                // priority - ALWAYS 0
	uint32_t hello_dead_interval;           // router dead interval - ALWAYS 40
	uchar    hello_designated_ip[4];        // designated router ip address 0
	uchar    hello_designated_ip_backup[4]; // backup designated router ip address 0
	hello_neighbor_t hello_neighbors[10];
//	uchar    hello_neighbors[10][4];		// neighbors list
} hello_packet_t;

typedef struct _ospf_packet_t
{
	uint8_t ospf_version;                   // version
	uint8_t ospf_type;                   	// type
	uint16_t ospf_message_length;           // message length

	uchar ospf_src[4];          	     	// source address
	uint32_t ospf_aid;                   	// area ID

	uint16_t ospf_cksum;                    // checksum
	uint16_t ospf_auth_type;                // authentication type
} ospf_packet_t;

typedef struct _ospf_gnode_t
{
	bool is_empty;							// whether node is used or not
	uchar src[4];							// IP address
	uchar networks[MAX_ROUTES][4];			// reachable networks
	int num_networks;						// number of reachable networks
	int types[MAX_ROUTES];					// type of network, 2 for any-to-any, 3 for stub
	int last_LSN;							// Link Sequence Number of the last update sent by this node
} ospf_gnode_t;

typedef struct _ospf_gedge_t
{
	bool is_empty;							// whether edge is used or not
	uchar addr1[4];							// IP address of first node
	uchar addr2[4];							// IP address of second node
} ospf_gedge_t;

typedef struct _ospf_graph_t
{
	ospf_gnode_t nodes[MAX_NODES];			// set of nodes
	ospf_gedge_t edges[MAX_EDGES];			// set of edges
} ospf_graph_t;

typedef struct _ospf_cost_entry_t
{
	bool is_empty;							// whether entry is used or not
	uchar dest_ip[4];						// network ip
	int cost;								// current lowest cost to this network
} ospf_cost_entry_t;

void OSPFInit();

// OSPF packet processing.
void OSPFIncomingPacket(gpacket_t *pkt);
void OSPFProcessHelloMessage(gpacket_t *pkt);
void OSPFProcessLSUpdate(gpacket_t *pkt, bool rebroadcast);

// Creating and sending Hello/LSU packets.
gpacket_t* createOSPFHeader(gpacket_t *gpacket, int type, int mlength, uchar sourceIP[]);
gpacket_t* createLSAHeader(gpacket_t *gpkt, uchar sourceIP[]);
gpacket_t* createLSUPacket(uchar sourceIP[]);
void OSPFSendHelloPacket(uchar src_ip[], int interface_);
void broadcastLSUpdate(bool createPacket, gpacket_t *pkt);
int OSPFSend2Output(gpacket_t *pkt);

// Neighbor table functions.
int addNeighborEntry(uchar* neighborIP_, int type_, int interface_);
int getNeighborEntries(neighbor_entry_t buffer[]);
void OSPFMarkDeadNeighbor(uchar* neighborIP_);
void OSPFSetStubNetwork(gpacket_t *pkt);

// Debug functions
void printNeighborTable();
void printLSData(gpacket_t *pkt);
void printGraphNodes(ospf_graph_t *graph);
void printGraphEdges(ospf_graph_t *graph);
void printCostTable(ospf_graph_t *graph);
void printNodeNetworks(ospf_gnode_t *node);

// Graph management functions
ospf_gnode_t* getNode(uchar src[]);
ospf_gnode_t* addNode(ospf_graph_t *graph, uchar src[]);
void removeNodes(ospf_graph_t *graph, uchar ip[4]);
void updateLinkData(lsu_packet_t *lsu_pkt, ospf_gnode_t *node);
void updateEdges(ospf_graph_t *graph, ospf_gnode_t *node);
void addEdge(uchar addr1[], uchar addr2[]);
void removeEdges(ospf_graph_t *graph, uchar ip[4]);
void removeIPFromGraph(uchar ip[4]);

// Routing table updating functions
void updateRoutingTable(ospf_graph_t *graph);
int getNodeNeighbor(ospf_graph_t *graph, ospf_gnode_t *node, uchar neighbor[4]);
void findNetworks(ospf_graph_t *graph, ospf_gnode_t *node, uchar visited[][4], int vindex, int cost);
int getIfaceIDByNetwork(uchar *net_addr);
int getIfaceIDByIP(uchar *ip_addr);
int isCheaper(ospf_cost_entry_t ctable[], uchar dest_ip_[], int cost_);
int isNeighbor(uchar *ip);
int getAllIpsFromNode(ospf_graph_t *graph, uchar *addr, uchar ips[][4]);
int containsIP(uchar ip_list[][4], uchar *ip, int list_size);

#endif