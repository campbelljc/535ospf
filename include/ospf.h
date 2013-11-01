#ifndef __OSPF_H_
#define __OSPF_H_

#include "grouter.h"
#include <stdint.h>

#define OSPF_HELLO       	  	 1      /* Hello           	       	    */
#define OSPF_DB_DSC     	   	 2      /* Database description         */
#define OSPF_LINK_STAT_REQUEST   3      /* Link status request	        */
#define OSPF_LINK_STAT_UPDATE    4      /* Link status update           */
#define OSPF_LINK_STAT_ACK       5      /* Link status acknowledgement  */

#define OSPF_VERSION		 2
#define OSPF_AREAID			 0
#define OSPF_AUTHTYPE		 0

typedef struct _lsu_link_t
{
	uint8_t lsu_header_length:4;
	uchar lsu_link_ID[4]; // network address
	uchar lsu_link_data[4]; // the router address for any-to-any networks and network mask for stub networks
	uint8_t lsu_link_type; // 2 for any-to-any networks and 3 for stub networks
	uint8_t lsu_metric:1;
} lsu_link_t;

typedef struct _lsu_packet_t
{
	uint8_t lsa_header_length:1; // plus the link information.
	uint8_t lsu_num_links;
	lsu_link_t links[DEFAULT_MTU/2];
} lsu_packet_t;

typedef struct _lsa_packet_t
{
	uint8_t lsa_header_length:5;
	uint8_t lsa_age:1;
	uint8_t lsa_type:1; //cant have :0 that means 0 bytes
	uchar lsa_ID[4]; // ip of originating router
	uchar lsa_advertising_number[4]; // same as above
	uint8_t lsa_sequence_number:1; // always incrementing by 1
	uint8_t lsa_checksum:1;
	uint16_t lsa_length;
} lsa_packet_t;

typedef struct _hello_packet_t
{
	uchar*    hello_network_mask[4];            // network mask - ALWAYS 255.255.255.0
	uint16_t hello_hello_interval;          // hello interval - ALWAYS 10
	uint8_t  hello_options;                 // options - ALWAYS 0
	uint8_t  hello_priority;                // priority - ALWAYS 0
	uint32_t hello_dead_interval;           // router dead interval - ALWAYS 40
	uchar*    hello_designated_ip[4];        // designated router ip address 0
	uchar*    hello_designated_ip_backup[4]; // backup designated router ip address 0
	uchar    hello_neighbours[DEFAULT_MTU/2];		// neighbors list 
} hello_packet_t;

typedef struct _ospf_hdr_t
{
	uint8_t ospf_version;                   // version
	uint8_t ospf_type;                   	// type 
	uint16_t ospf_message_length;           // message length 

	uchar* ospf_src[4];          	     	// source address
	uint32_t ospf_aid;                   	// area ID
 
	uint16_t ospf_cksum;                    // checksum
	uint16_t ospf_auth_type;                // authentication type
 
	/* uint32_t ospf_auth;                     // authentication */
} ospf_hdr_t;

//typedef struct _ospf_gnode_t
//{
//	uchar addr[4];				// node address
//	ospf_gnode_t *neighbours;		// adjacency list
//	int size;				// number of neighbours
//} ospf_gnode_t


//typedef struct _ospf_graph_t
//{
//	ospf_gnode_t *nodes;			// set of nodes
//	int size;				// number of nodes
//} ospf_graph_t

gpacket_t *createOSPFHeader(gpacket_t *gpacket, int type, int mlength, uchar* src[]);
//void updateGraph(ospf_graph_t graph, ospf_gnode_t);
void OSPFIncomingPacket(gpacket_t *pkt);
bool isOSPFHelloMessage(ospf_hdr_t *ospf_pkt);
bool isOSPFLSUpdate(ospf_hdr_t *ospf_pkt);
void OSPFSendLSUPacket(uchar *dst_ip, int seqNum_, uchar* sourceIP);
void OSPFSendHelloPacket(uchar *dst_ip);
//gpacket_t *OSPFSendLSAPacket(g_router_t *gpkt, int seqNum_, uchar* sourceIP);
int OSPFSend2Output(gpacket_t *pkt);

#endif
