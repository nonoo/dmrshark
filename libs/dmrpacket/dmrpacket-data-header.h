/*
 * This file is part of dmrshark.
 *
 * dmrshark is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dmrshark is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dmrshark.  If not, see <http://www.gnu.org/licenses/>.
**/

#ifndef DMRPACKET_DATA_HEADER_H_
#define DMRPACKET_DATA_HEADER_H_

#include <libs/coding/bptc-196-96.h>

#define DMRPACKET_DATA_HEADER_DPF_UDT							0b0000
#define DMRPACKET_DATA_HEADER_DPF_RESPONSE						0b0001
#define DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA				0b0010
#define DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA				0b0011
#define DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED			0b1101
#define DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW				0b1110
#define DMRPACKET_DATA_HEADER_DPF_PROPRIETARY_DATA				0b1111
typedef uint8_t dmrpacket_data_header_dpf_t;

#define DMRPACKET_DATA_HEADER_SAP_UDT							0b0000
#define DMRPACKET_DATA_HEADER_SAP_TCPIP_HEADER_COMPRESSION		0b0010
#define DMRPACKET_DATA_HEADER_SAP_UDPIP_HEADER_COMPRESSION		0b0011
#define DMRPACKET_DATA_HEADER_SAP_IP_BASED_PACKET_DATA			0b0100
#define DMRPACKET_DATA_HEADER_SAP_ARP							0b0101
#define DMRPACKET_DATA_HEADER_SAP_PROPRIETARY_PACKET_DATA		0b1001
#define DMRPACKET_DATA_HEADER_SAP_SHORT_DATA					0b1010
typedef uint8_t dmrpacket_data_header_sap_t;

#define DMRPACKET_DATA_HEADER_RESPONSETYPE_ACK					0
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT		1
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_PACKET_CRC_FAILED	2
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_MEMORY_FULL			3
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_FSN_OUT_OF_SEQ	4
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_UNDELIVERABLE		5
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_PKT_OUT_OF_SEQ	6
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_DISALLOWED			7
#define DMRPACKET_DATA_HEADER_RESPONSETYPE_SELECTIVE_ACK		8
typedef uint8_t dmrpacket_data_header_responsetype_t;

#define DMRPACKET_DATA_HEADER_DD_FORMAT_BINARY					0b000000
#define DMRPACKET_DATA_HEADER_DD_FORMAT_BCD						0b000001
#define DMRPACKET_DATA_HEADER_DD_FORMAT_7BIT_CHAR				0b000010
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_1			0b000011
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_2			0b000100
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_3			0b000101
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_4			0b000110
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_5			0b000111
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_6			0b001000
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_7			0b001001
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_8			0b001010
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_9			0b001011
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_10			0b001100
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_11			0b001101
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_13			0b001110
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_14			0b001111
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_15			0b010000
#define DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_16			0b010001
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF8					0b010010
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16					0b010011
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16BE					0b010100
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE					0b010101
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32					0b010110
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32BE					0b010111
#define DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32LE					0b011000
typedef uint8_t dmrpacket_data_header_dd_format_t;

#define DMRPACKET_DATA_HEADER_UDT_FORMAT_BINARY					0b0000
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_MS_ADDRESS				0b0001
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_4BIT_BCD				0b0010
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_ISO_7BIT_CHARS			0b0011
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_ISO_8BIT_CHARS			0b0100
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_NMEA_LOCATION			0b0101
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_IP_ADDRESS				0b0110
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_16BIT_UNICODE_CHARS	0b0111
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_CUSTOM_CODED1			0b1000
#define DMRPACKET_DATA_HEADER_UDT_FORMAT_CUSTOM_CODED2			0b1001
typedef uint8_t dmrpacket_data_header_udt_format_t;

typedef uint32_t dmrpacket_data_header_llid_t;
typedef uint8_t dmrpacket_data_header_bf_t;
typedef uint8_t dmrpacket_data_header_poc_t;
typedef uint8_t dmrpacket_data_header_seqnum_t;
typedef uint8_t dmrpacket_data_header_fragmentseqnum_t;
typedef uint8_t dmrpacket_data_header_class_t;
typedef uint8_t dmrpacket_data_header_type_t;
typedef uint8_t dmrpacket_data_header_status_t;
typedef uint16_t dmrpacket_data_header_crc_t;
typedef uint8_t dmrpacket_data_manufacturer_id_t;
typedef uint8_t dmrpacket_data_header_port_t;
typedef uint8_t dmrpacket_data_header_bit_padding_t;
typedef uint8_t dmrpacket_data_header_appended_blocks_t;
typedef uint8_t dmrpacket_data_header_pad_nibble_t;
typedef uint8_t dmrpacket_data_header_udt_opcode_t;

typedef struct {
	struct {
		flag_t dst_is_a_group;
		flag_t response_requested;
		dmrpacket_data_header_llid_t dst_llid;
		dmrpacket_data_header_llid_t src_llid;
		dmrpacket_data_header_dpf_t data_packet_format;
		dmrpacket_data_header_sap_t service_access_point;
		dmrpacket_data_header_crc_t crc;
	} common;
	struct {
		dmrpacket_data_manufacturer_id_t manufacturer_id;
		uint8_t data[8];
	} proprietary;
	struct {
		dmrpacket_data_header_poc_t pad_octet_count;
		flag_t full_message;
		dmrpacket_data_header_bf_t blocks_to_follow;
		dmrpacket_data_header_fragmentseqnum_t fragmentseqnum;
	} unconfirmed_data;
	struct {
		dmrpacket_data_header_poc_t pad_octet_count;
		flag_t full_message;
		dmrpacket_data_header_bf_t blocks_to_follow;
		dmrpacket_data_header_fragmentseqnum_t fragmentseqnum;
		flag_t resync;
		dmrpacket_data_header_seqnum_t sendseqnum;
	} confirmed_data;
	struct {
		dmrpacket_data_header_bf_t blocks_to_follow;
		dmrpacket_data_header_class_t class;
		dmrpacket_data_header_type_t type;
		dmrpacket_data_header_status_t status;
		dmrpacket_data_header_responsetype_t responsetype;
	} response;
	struct {
		dmrpacket_data_header_appended_blocks_t appended_blocks;
		dmrpacket_data_header_port_t source_port;
		dmrpacket_data_header_port_t destination_port;
		flag_t resync;
		flag_t full_message;
		dmrpacket_data_header_bit_padding_t bit_padding;
	} short_data_raw;
	struct {
		dmrpacket_data_header_appended_blocks_t appended_blocks;
		dmrpacket_data_header_dd_format_t dd_format;
		flag_t resync;
		flag_t full_message;
		dmrpacket_data_header_bit_padding_t bit_padding;
	} short_data_defined;
	struct {
		dmrpacket_data_header_udt_format_t format;
		dmrpacket_data_header_pad_nibble_t pad_nibble;
		dmrpacket_data_header_appended_blocks_t appended_blocks;
		flag_t supplementary_flag;
		dmrpacket_data_header_udt_opcode_t opcode;
	} udt;
} dmrpacket_data_header_t;

char *dmrpacket_data_header_get_readable_dpf(dmrpacket_data_header_dpf_t dpf);
char *dmrpacket_data_header_get_readable_sap(dmrpacket_data_header_sap_t sap);
char *dmrpacket_data_header_get_readable_response_type(dmrpacket_data_header_responsetype_t response_type);
char *dmrpacket_data_header_get_readable_dd_format(dmrpacket_data_header_dd_format_t dd_format);

dmrpacket_data_header_t *dmrpacket_data_header_decode(bptc_196_96_data_bits_t *data_bits, flag_t proprietary_header);
dmrpacket_data_header_responsetype_t dmrpacket_data_header_decode_response(dmrpacket_data_header_t *header);
bptc_196_96_data_bits_t *dmrpacket_data_header_construct(dmrpacket_data_header_t *data_header, flag_t proprietary_header);

#endif
