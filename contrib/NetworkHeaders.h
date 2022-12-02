// HHD Software Hex Editor Neo
// Structure Definition File
// Creation date: 02.12.2022 18:20:25
//
// Consult the Structure Viewer documentation for more information:
//
// * Structure Viewer Overview: https://www.hhdsoftware.com/online-doc/hex/structure-viewer
// * Language Reference: https://www.hhdsoftware.com/online-doc/hex/language-reference

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;

public struct Ipv4Header
{
	uint8_t ihl : 4;
	uint8_t version : 4;
	uint8_t tos;
	uint16_t total_length_bytes;
	uint16_t identification;
	uint16_t flags : 3;
	uint16_t fragment_offset : 13;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t header_checksum;
	uint32_t source_ip;
	uint32_t destination_ip;
	uint32_t options[ihl - 5];
};

public struct UdpHeader
{
	uint16_t source_port;
	uint16_t destination_port;
	uint16_t length_bytes;
	uint16_t checksum;
};

public struct EthernetHeader
{
	uint8_t dest_mac[6];
	uint8_t source_mac[6];
	uint16_t ethertype;
};
