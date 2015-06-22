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

#include <config/defaults.h>

#include "dmrpacket.h"

#include <libs/base/crc.h>
#include <libs/base/base.h>
#include <libs/daemon/console.h>

#include <stdlib.h>
#include <string.h>

static char *dmrpacket_data_header_get_readable_dpf(dmrpacket_data_header_dpf_t dpf) {
	switch (dpf) {
		case DMRPACKET_DATA_HEADER_DPF_UDT: return "udt";
		case DMRPACKET_DATA_HEADER_DPF_RESPONSE: return "response";
		case DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA: return "unconfirmed data";
		case DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA: return "confirmed data";
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED: return "short data defined";
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW: return "short data raw";
		case DMRPACKET_DATA_HEADER_DPF_PROPRIETARY_DATA: return "proprietary data";
		default: return "unknown";
	}
}

static char *dmrpacket_data_header_get_readable_sap(dmrpacket_data_header_sap_t sap) {
	switch (sap) {
		case DMRPACKET_DATA_HEADER_SAP_UDT: return "udt";
		case DMRPACKET_DATA_HEADER_SAP_TCPIP_HEADER_COMPRESSION: return "tcp/ip header compression";
		case DMRPACKET_DATA_HEADER_SAP_UDPIP_HEADER_COMPRESSION: return "udp/ip header compression";
		case DMRPACKET_DATA_HEADER_SAP_IP_BASED_PACKET_DATA: return "ip based packet data";
		case DMRPACKET_DATA_HEADER_SAP_ARP: return "arp";
		case DMRPACKET_DATA_HEADER_SAP_PROPRIETARY_PACKET_DATA: return "proprietary packet data";
		case DMRPACKET_DATA_HEADER_SAP_SHORT_DATA: return "short data";
		default: return "unknown";
	}
}

char *dmrpacket_data_header_get_readable_response_type(dmrpacket_data_header_responsetype_t response_type) {
	switch (response_type) {
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_ACK: return "ack";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT: return "illegal format";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_PACKET_CRC_FAILED: return "crc failed";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_MEMORY_FULL: return "memory full";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_FSN_OUT_OF_SEQ: return "recv fsn out of seq";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_UNDELIVERABLE: return "undeliverable";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_PKT_OUT_OF_SEQ: return "recv pkt out of seq";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_DISALLOWED: return "disallowed";
		case DMRPACKET_DATA_HEADER_RESPONSETYPE_SELECTIVE_ACK: return "selective ack";
		default: return "unknown";
	}
}

char *dmrpacket_data_header_get_readable_dd_format(dmrpacket_data_header_dd_format_t dd_format) {
	switch (dd_format) {
		case DMRPACKET_DATA_HEADER_DD_FORMAT_BINARY: return "binary";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_BCD: return "bcd";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_7BIT_CHAR: return "7bit char";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_1: return "iso8859-1";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_2: return "iso8859-2";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_3: return "iso8859-3";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_4: return "iso8859-4";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_5: return "iso8859-5";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_6: return "iso8859-6";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_7: return "iso8859-7";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_8: return "iso8859-8";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_9: return "iso8859-9";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_10: return "iso8859-10";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_11: return "iso8859-11";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_13: return "iso8859-13";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_14: return "iso8859-14";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_15: return "iso8859-15";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_16: return "iso8859-16";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF8: return "utf-8";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16: return "utf-16";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16BE: return "utf-16be";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE: return "utf-16le";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32: return "utf-32";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32BE: return "utf-32be";
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32LE: return "utf-32le";
		default: return "unknown";
	}
}

static char *dmrpacket_data_header_get_readable_udt_format(dmrpacket_data_header_udt_format_t udt_format) {
	switch (udt_format) {
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_BINARY: return "binary";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_MS_ADDRESS: return "ms address";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_4BIT_BCD: return "4bit bcd";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_ISO_7BIT_CHARS: return "iso 7bit chars";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_ISO_8BIT_CHARS: return "iso 8bit chars";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_NMEA_LOCATION: return "nmea location";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_IP_ADDRESS: return "ip address";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_16BIT_UNICODE_CHARS: return "16bit unicode chars";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_CUSTOM_CODED1: return "custom coded 1";
		case DMRPACKET_DATA_HEADER_UDT_FORMAT_CUSTOM_CODED2: return "custom coded 2";
		default: return "unknown";
	}
}

static uint16_t dmrpacket_data_header_crc_calc(dmrpacket_payload_bptc_data_bits_t *data_bits) {
	int i;
	// In true CRC16-CCITT, initial CRC value should be 0xffff, but DMR spec. uses 0.
	// See DMR AI spec. page 139.
	uint16_t crcval = 0;

	if (data_bits == NULL)
		return 0;

	for (i = 0; i < 10; i++)
		crc_calc_crc16_ccitt(&crcval, base_bitstobyte(&data_bits->bits[i*8]));
	crc_calc_crc16_ccitt_finish(&crcval);

	// Inverting according to the inversion polynomial.
	crcval = ~crcval;
	// Applying CRC mask, see DMR AI spec. page 143.
	crcval ^= 0xcccc;

	return crcval;
}

dmrpacket_data_header_t *dmrpacket_data_header_decode(dmrpacket_payload_bptc_data_bits_t *data_bits, flag_t proprietary_header) {
	static dmrpacket_data_header_t header;

	if (data_bits == NULL)
		return NULL;

	memset(&header, 0, sizeof(dmrpacket_data_header_t));

	// The CRC field is common for all data header packet formats.
	header.common.crc =									data_bits->bits[80] << 15 |
														data_bits->bits[81] << 14 |
														data_bits->bits[82] << 13 |
														data_bits->bits[83] << 12 |
														data_bits->bits[84] << 11 |
														data_bits->bits[85] << 10 |
														data_bits->bits[86] << 9 |
														data_bits->bits[87] << 8 |
														data_bits->bits[88] << 7 |
														data_bits->bits[89] << 6 |
														data_bits->bits[90] << 5 |
														data_bits->bits[91] << 4 |
														data_bits->bits[92] << 3 |
														data_bits->bits[93] << 2 |
														data_bits->bits[94] << 1 |
														data_bits->bits[95];

	if (dmrpacket_data_header_crc_calc(data_bits) != header.common.crc) {
		console_log("dmrpacket data error: header crc mismatch\n");
		return NULL;
	}

	if (proprietary_header) {
		console_log(LOGLEVEL_COMM_DMR "dmrpacket data: decoding proprietary header\n");
		header.common.service_access_point =			data_bits->bits[0] << 3 |
														data_bits->bits[1] << 2 |
														data_bits->bits[2] << 1 |
														data_bits->bits[3];
		console_log(LOGLEVEL_COMM_DMR "  service access point: %.2x (%s)\n", header.common.service_access_point, dmrpacket_data_header_get_readable_sap(header.common.service_access_point));
		header.common.data_packet_format =				data_bits->bits[4] << 3 |
														data_bits->bits[5] << 2 |
														data_bits->bits[6] << 1 |
														data_bits->bits[7];
		console_log(LOGLEVEL_COMM_DMR "  data packet format: %.2x (%s)\n", header.common.data_packet_format, dmrpacket_data_header_get_readable_dpf(header.common.data_packet_format));
		header.proprietary.manufacturer_id =			data_bits->bits[8] << 7 |
														data_bits->bits[9] << 6 |
														data_bits->bits[10] << 5 |
														data_bits->bits[11] << 4 |
														data_bits->bits[12] << 3 |
														data_bits->bits[13] << 2 |
														data_bits->bits[14] << 1 |
														data_bits->bits[15];
		console_log(LOGLEVEL_COMM_DMR "  manufacturer id: %.2x\n", header.proprietary.manufacturer_id);
		console_log(LOGLEVEL_COMM_DMR "  crc: %.4x\n", header.common.crc);
		return &header;
	}

	header.common.data_packet_format =					data_bits->bits[4] << 3 |
														data_bits->bits[5] << 2 |
														data_bits->bits[6] << 1 |
														data_bits->bits[7];
	console_log(LOGLEVEL_COMM_DMR "dmrpacket data: decoding header format %s (%.2x)\n", dmrpacket_data_header_get_readable_dpf(header.common.data_packet_format), header.common.data_packet_format);

	// These fields are common for each data packet format.
	header.common.dst_is_a_group =						data_bits->bits[0];
	console_log(LOGLEVEL_COMM_DMR "  dst is a group: %u\n", header.common.dst_is_a_group);
	header.common.response_requested =					data_bits->bits[1];
	console_log(LOGLEVEL_COMM_DMR "  response requested: %u\n", header.common.response_requested);
	header.common.service_access_point =				data_bits->bits[8] << 3 |
														data_bits->bits[9] << 2 |
														data_bits->bits[10] << 1 |
														data_bits->bits[11];
	console_log(LOGLEVEL_COMM_DMR "  service access point: %.2x (%s)\n", header.common.service_access_point, dmrpacket_data_header_get_readable_sap(header.common.service_access_point));
	header.common.dst_llid =							data_bits->bits[16] << 23 |
														data_bits->bits[17] << 22 |
														data_bits->bits[18] << 21 |
														data_bits->bits[19] << 20 |
														data_bits->bits[20] << 19 |
														data_bits->bits[21] << 18 |
														data_bits->bits[22] << 17 |
														data_bits->bits[23] << 16 |
														data_bits->bits[24] << 15 |
														data_bits->bits[25] << 14 |
														data_bits->bits[26] << 13 |
														data_bits->bits[27] << 12 |
														data_bits->bits[28] << 11 |
														data_bits->bits[29] << 10 |
														data_bits->bits[30] << 9 |
														data_bits->bits[31] << 8 |
														data_bits->bits[32] << 7 |
														data_bits->bits[33] << 6 |
														data_bits->bits[34] << 5 |
														data_bits->bits[35] << 4 |
														data_bits->bits[36] << 3 |
														data_bits->bits[37] << 2 |
														data_bits->bits[38] << 1 |
														data_bits->bits[39];
	console_log(LOGLEVEL_COMM_DMR "  dst llid: %u\n", header.common.dst_llid);
	header.common.src_llid =							data_bits->bits[40] << 23 |
														data_bits->bits[41] << 22 |
														data_bits->bits[42] << 21 |
														data_bits->bits[43] << 20 |
														data_bits->bits[44] << 19 |
														data_bits->bits[45] << 18 |
														data_bits->bits[46] << 17 |
														data_bits->bits[47] << 16 |
														data_bits->bits[48] << 15 |
														data_bits->bits[49] << 14 |
														data_bits->bits[50] << 13 |
														data_bits->bits[51] << 12 |
														data_bits->bits[52] << 11 |
														data_bits->bits[53] << 10 |
														data_bits->bits[54] << 9 |
														data_bits->bits[55] << 8 |
														data_bits->bits[56] << 7 |
														data_bits->bits[57] << 6 |
														data_bits->bits[58] << 5 |
														data_bits->bits[59] << 4 |
														data_bits->bits[60] << 3 |
														data_bits->bits[61] << 2 |
														data_bits->bits[62] << 1 |
														data_bits->bits[63];
	console_log(LOGLEVEL_COMM_DMR "  src llid: %u\n", header.common.src_llid);

	switch (header.common.data_packet_format) {
		case DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA:
			header.unconfirmed_data.pad_octet_count =	data_bits->bits[3] << 4 |
														data_bits->bits[12] << 3 |
														data_bits->bits[13] << 2 |
														data_bits->bits[14] << 1 |
														data_bits->bits[15];
			console_log(LOGLEVEL_COMM_DMR "  pad octet count: %u\n", header.unconfirmed_data.pad_octet_count);
			header.unconfirmed_data.full_message =		data_bits->bits[64];
			console_log(LOGLEVEL_COMM_DMR "  full message: %u\n", header.unconfirmed_data.full_message);
			header.unconfirmed_data.blocks_to_follow =	data_bits->bits[65] << 6 |
														data_bits->bits[66] << 5 |
														data_bits->bits[67] << 4 |
														data_bits->bits[68] << 3 |
														data_bits->bits[69] << 2 |
														data_bits->bits[70] << 1 |
														data_bits->bits[71];
			console_log(LOGLEVEL_COMM_DMR "  blocks to follow: %u\n", header.unconfirmed_data.blocks_to_follow);
			header.unconfirmed_data.fragmentseqnum =	data_bits->bits[76] << 3 |
														data_bits->bits[77] << 2 |
														data_bits->bits[78] << 1 |
														data_bits->bits[79];
			console_log(LOGLEVEL_COMM_DMR "  fragment seqnum: %u\n", header.unconfirmed_data.fragmentseqnum);
			break;
		case DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA:
			header.confirmed_data.pad_octet_count =		data_bits->bits[3] << 4 |
														data_bits->bits[12] << 3 |
														data_bits->bits[13] << 2 |
														data_bits->bits[14] << 1 |
														data_bits->bits[15];
			console_log(LOGLEVEL_COMM_DMR "  pad octet count: %u\n", header.confirmed_data.pad_octet_count);
			header.confirmed_data.full_message =		data_bits->bits[64];
			console_log(LOGLEVEL_COMM_DMR "  full message: %u\n", header.confirmed_data.full_message);
			header.confirmed_data.blocks_to_follow =	data_bits->bits[65] << 6 |
														data_bits->bits[66] << 5 |
														data_bits->bits[67] << 4 |
														data_bits->bits[68] << 3 |
														data_bits->bits[69] << 2 |
														data_bits->bits[70] << 1 |
														data_bits->bits[71];
			console_log(LOGLEVEL_COMM_DMR "  blocks to follow: %u\n", header.confirmed_data.blocks_to_follow);
			header.confirmed_data.resync =				data_bits->bits[72];
			console_log(LOGLEVEL_COMM_DMR "  resync: %u\n", header.confirmed_data.resync);
			header.confirmed_data.fragmentseqnum =		data_bits->bits[76] << 3 |
														data_bits->bits[77] << 2 |
														data_bits->bits[78] << 1 |
														data_bits->bits[79];
			console_log(LOGLEVEL_COMM_DMR "  fragment seqnum: %u\n", header.confirmed_data.fragmentseqnum);
			header.confirmed_data.sendseqnum =			data_bits->bits[73] << 2 |
														data_bits->bits[74] << 1 |
														data_bits->bits[75];
			console_log(LOGLEVEL_COMM_DMR "  send seqnum: %u\n", header.confirmed_data.sendseqnum);
			break;
		case DMRPACKET_DATA_HEADER_DPF_RESPONSE:
			header.response.blocks_to_follow =			data_bits->bits[65] << 6 |
														data_bits->bits[66] << 5 |
														data_bits->bits[67] << 4 |
														data_bits->bits[68] << 3 |
														data_bits->bits[69] << 2 |
														data_bits->bits[70] << 1 |
														data_bits->bits[71];
			console_log(LOGLEVEL_COMM_DMR "  blocks to follow: %u\n", header.response.blocks_to_follow);
			header.response.class =						data_bits->bits[72] << 1 |
														data_bits->bits[73];
			console_log(LOGLEVEL_COMM_DMR "  class: %.2x\n", header.response.class);
			header.response.type =						data_bits->bits[74] << 2 |
														data_bits->bits[75] << 1 |
														data_bits->bits[76];
			console_log(LOGLEVEL_COMM_DMR "  type: %.2x\n", header.response.type);
			header.response.status =					data_bits->bits[77] << 2 |
														data_bits->bits[78] << 1 |
														data_bits->bits[79];
			console_log(LOGLEVEL_COMM_DMR "  status: %.2x\n", header.response.status);
			break;
		case DMRPACKET_DATA_HEADER_DPF_PROPRIETARY_DATA: // This is handled at the beginning of this function.
			return &header;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW:
			header.short_data_raw.appended_blocks =		data_bits->bits[2] << 5 |
														data_bits->bits[3] << 4 |
														data_bits->bits[12] << 3 |
														data_bits->bits[13] << 2 |
														data_bits->bits[14] << 1 |
														data_bits->bits[15];
			console_log(LOGLEVEL_COMM_DMR "  appended blocks: %u\n", header.short_data_raw.appended_blocks);
			header.short_data_raw.source_port =			data_bits->bits[72] << 2 |
														data_bits->bits[73] << 1 |
														data_bits->bits[74];
			console_log(LOGLEVEL_COMM_DMR "  source port: %u\n", header.short_data_raw.source_port);
			header.short_data_raw.destination_port =	data_bits->bits[75] << 2 |
														data_bits->bits[76] << 1 |
														data_bits->bits[77];
			console_log(LOGLEVEL_COMM_DMR "  destination port: %u\n", header.short_data_raw.destination_port);
			header.short_data_raw.resync =				data_bits->bits[78];
			console_log(LOGLEVEL_COMM_DMR "  resync: %u\n", header.short_data_raw.resync);
			header.short_data_raw.full_message =		data_bits->bits[79];
			console_log(LOGLEVEL_COMM_DMR "  full message: %u\n", header.short_data_raw.full_message);
			header.short_data_raw.bit_padding =				data_bits->bits[80] << 7 |
														data_bits->bits[81] << 6 |
														data_bits->bits[82] << 5 |
														data_bits->bits[83] << 4 |
														data_bits->bits[84] << 3 |
														data_bits->bits[85] << 2 |
														data_bits->bits[86] << 1 |
														data_bits->bits[87];
			console_log(LOGLEVEL_COMM_DMR "  bit padding: %.2x\n", header.short_data_raw.bit_padding);
			break;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED:
			header.short_data_defined.appended_blocks =	data_bits->bits[2] << 5 |
														data_bits->bits[3] << 4 |
														data_bits->bits[12] << 3 |
														data_bits->bits[13] << 2 |
														data_bits->bits[14] << 1 |
														data_bits->bits[15];
			console_log(LOGLEVEL_COMM_DMR "  appended blocks: %u\n", header.short_data_defined.appended_blocks);
			header.short_data_defined.dd_format =		data_bits->bits[72] << 5 |
														data_bits->bits[73] << 4 |
														data_bits->bits[74] << 3 |
														data_bits->bits[75] << 2 |
														data_bits->bits[76] << 1 |
														data_bits->bits[77];
			console_log(LOGLEVEL_COMM_DMR "  dd format: %.2x (%s)\n", header.short_data_defined.dd_format, dmrpacket_data_header_get_readable_dd_format(header.short_data_defined.dd_format));
			header.short_data_defined.resync =			data_bits->bits[78];
			console_log(LOGLEVEL_COMM_DMR "  resync: %u\n", header.short_data_defined.resync);
			header.short_data_defined.full_message =	data_bits->bits[79];
			console_log(LOGLEVEL_COMM_DMR "  full message: %u\n", header.short_data_defined.full_message);
			header.short_data_defined.bit_padding =		data_bits->bits[80] << 7 |
														data_bits->bits[81] << 6 |
														data_bits->bits[82] << 5 |
														data_bits->bits[83] << 4 |
														data_bits->bits[84] << 3 |
														data_bits->bits[85] << 2 |
														data_bits->bits[86] << 1 |
														data_bits->bits[87];
			console_log(LOGLEVEL_COMM_DMR "  bit padding: %.2x\n", header.short_data_defined.bit_padding);
			break;
		case DMRPACKET_DATA_HEADER_DPF_UDT:
			header.udt.format =							data_bits->bits[12] << 3 |
														data_bits->bits[13] << 2 |
														data_bits->bits[14] << 1 |
														data_bits->bits[15];
			console_log(LOGLEVEL_COMM_DMR "  udt format: %.2x (%s)\n", header.udt.format, dmrpacket_data_header_get_readable_udt_format(header.udt.format));
			header.udt.pad_nibble =						data_bits->bits[73] << 4 |
														data_bits->bits[74] << 3 |
														data_bits->bits[75] << 2 |
														data_bits->bits[76] << 1 |
														data_bits->bits[77];
			console_log(LOGLEVEL_COMM_DMR "  pad nibble: %u\n", header.udt.pad_nibble);
			header.udt.appended_blocks =				data_bits->bits[78] << 1 |
														data_bits->bits[79];
			console_log(LOGLEVEL_COMM_DMR "  appended blocks: %u\n", header.udt.appended_blocks);
			header.udt.supplementary_flag =				data_bits->bits[80];
			console_log(LOGLEVEL_COMM_DMR "  supplementary flag: %u\n", header.udt.supplementary_flag);
			break;
		default:
			console_log("dmrpacket data error: unknown header data packet format\n");
			return NULL;
	}

	return &header;
}

// Determines the response type from the data response header.
// See DMR AI spec. page 86.
dmrpacket_data_header_responsetype_t dmrpacket_data_header_decode_response(dmrpacket_data_header_t *header) {
	if (header == NULL || header->common.data_packet_format != DMRPACKET_DATA_HEADER_DPF_RESPONSE)
		return DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;

	switch (header->response.class) {
		case 0b00:
			switch (header->response.type) {
				case 0b001:	return DMRPACKET_DATA_HEADER_RESPONSETYPE_ACK;
				default: break;
			}
			break;
		case 0b01:
			switch (header->response.type) {
				case 0b000:	return DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;
				case 0b001: return DMRPACKET_DATA_HEADER_RESPONSETYPE_PACKET_CRC_FAILED;
				case 0b010: return DMRPACKET_DATA_HEADER_RESPONSETYPE_MEMORY_FULL;
				case 0b011: return DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_FSN_OUT_OF_SEQ;
				case 0b100: return DMRPACKET_DATA_HEADER_RESPONSETYPE_UNDELIVERABLE;
				case 0b101: return DMRPACKET_DATA_HEADER_RESPONSETYPE_RECV_PKT_OUT_OF_SEQ;
				case 0b110: return DMRPACKET_DATA_HEADER_RESPONSETYPE_DISALLOWED;
				default: break;
			}
			break;
		case 0b10:
			switch (header->response.type) {
				case 0b000: return DMRPACKET_DATA_HEADER_RESPONSETYPE_SELECTIVE_ACK;
				default: break;
			}
			break;
		default: break;
	}
	return DMRPACKET_DATA_HEADER_RESPONSETYPE_ILLEGAL_FORMAT;
}
