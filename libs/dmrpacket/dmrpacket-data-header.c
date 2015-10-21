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

#include DEFAULTCONFIG

#include "dmrpacket-data-header.h"
#include "dmrpacket-data.h"

#include <libs/coding/crc.h>
#include <libs/base/base.h>
#include <libs/daemon/console.h>

#include <stdlib.h>
#include <string.h>

char *dmrpacket_data_header_get_readable_dpf(dmrpacket_data_header_dpf_t dpf) {
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

char *dmrpacket_data_header_get_readable_sap(dmrpacket_data_header_sap_t sap) {
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

static uint16_t dmrpacket_data_header_crc_calc(uint8_t data_bytes[12]) {
	uint8_t i;
	// In true CRC16-CCITT, initial CRC value should be 0xffff, but DMR spec. uses 0.
	// See DMR AI spec. page 139.
	uint16_t crcval = 0;

	if (data_bytes == NULL)
		return 0;

	for (i = 0; i < 10; i++)
		crc_calc_crc16_ccitt(&crcval, data_bytes[i]);
	crc_calc_crc16_ccitt_finish(&crcval);

	// Inverting according to the inversion polynomial.
	crcval = ~crcval;
	// Applying CRC mask, see DMR AI spec. page 143.
	crcval ^= 0xcccc;

	return crcval;
}

dmrpacket_data_header_t *dmrpacket_data_header_decode(bptc_196_96_data_bits_t *data_bits, flag_t proprietary_header) {
	static dmrpacket_data_header_t header;
	uint8_t data_bytes[sizeof(bptc_196_96_data_bits_t)/8];

	if (data_bits == NULL)
		return NULL;

	base_bitstobytes(data_bits->bits, sizeof(bptc_196_96_data_bits_t), data_bytes, sizeof(data_bytes));
	memset(&header, 0, sizeof(dmrpacket_data_header_t));

	// The CRC field is common for all data header packet formats.
	header.common.crc =	data_bytes[10] << 8 | data_bytes[11];

	if (dmrpacket_data_header_crc_calc(data_bytes) != header.common.crc) {
		console_log(LOGLEVEL_DMRDATA "dmrpacket data error: header crc mismatch\n");
		return NULL;
	}

	if (proprietary_header) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "dmrpacket data: decoding proprietary header\n");
		header.common.service_access_point = (data_bytes[0] & 0b11110000) >> 4;
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  service access point: %.2x (%s)\n", header.common.service_access_point, dmrpacket_data_header_get_readable_sap(header.common.service_access_point));
		header.common.data_packet_format = data_bytes[0] & 0b1111;
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  data packet format: %.2x (%s)\n", header.common.data_packet_format, dmrpacket_data_header_get_readable_dpf(header.common.data_packet_format));
		header.proprietary.manufacturer_id = data_bytes[1];
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  manufacturer id: %.2x\n", header.proprietary.manufacturer_id);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  crc: %.4x\n", header.common.crc);
		return &header;
	}

	// These fields are common for each data packet format.
	header.common.data_packet_format = data_bytes[0] & 0b1111;
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "dmrpacket data:\n");
	console_log(LOGLEVEL_DMRDATA "  data packet format: %s\n", dmrpacket_data_header_get_readable_dpf(header.common.data_packet_format));

	header.common.dst_is_a_group = ((data_bytes[0] & 0b10000000) > 0);
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  dst is a group: %u\n", header.common.dst_is_a_group);
	header.common.response_requested = ((data_bytes[0] & 0b01000000) > 0);
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  response requested: %u\n", header.common.response_requested);
	header.common.service_access_point = (data_bytes[1] & 0b11110000) >> 4;
	console_log(LOGLEVEL_DMRDATA "  service access point: %.2x (%s)\n", header.common.service_access_point, dmrpacket_data_header_get_readable_sap(header.common.service_access_point));
	header.common.dst_llid = data_bytes[2] << 16 | data_bytes[3] << 8 | data_bytes[4];
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  dst llid: %u\n", header.common.dst_llid);
	header.common.src_llid = data_bytes[5] << 16 | data_bytes[6] << 8 | data_bytes[7];
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  src llid: %u\n", header.common.src_llid);

	switch (header.common.data_packet_format) {
		case DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA:
			header.unconfirmed_data.pad_octet_count = (data_bytes[0] & 0b10000) | (data_bytes[1] & 0b01111);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  pad octet count: %u\n", header.unconfirmed_data.pad_octet_count);
			header.unconfirmed_data.full_message = ((data_bytes[8] & 0b10000000) > 0);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  full message: %u\n", header.unconfirmed_data.full_message);
			header.unconfirmed_data.blocks_to_follow = data_bytes[8] & 0b01111111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  blocks to follow: %u\n", header.unconfirmed_data.blocks_to_follow);
			header.unconfirmed_data.fragmentseqnum = data_bytes[9] & 0b1111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  fragment seqnum: %u\n", header.unconfirmed_data.fragmentseqnum);
			break;
		case DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA:
			header.confirmed_data.pad_octet_count = (data_bytes[0] & 0b10000) | (data_bytes[1] & 0b01111);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  pad octet count: %u\n", header.confirmed_data.pad_octet_count);
			header.confirmed_data.full_message = ((data_bytes[8] & 0b10000000) > 0);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  full message: %u\n", header.confirmed_data.full_message);
			header.confirmed_data.blocks_to_follow = data_bytes[8] & 0b01111111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  blocks to follow: %u\n", header.confirmed_data.blocks_to_follow);
			header.confirmed_data.resync = ((data_bytes[9] & 0b10000000) > 0);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  resync: %u\n", header.confirmed_data.resync);
			header.confirmed_data.fragmentseqnum = data_bytes[9] & 0b1111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  fragment seqnum: ");
			if (header.confirmed_data.fragmentseqnum & 0b1000)
				console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "last fragment (%u)\n", header.confirmed_data.fragmentseqnum);
			else
				console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%u\n", header.confirmed_data.fragmentseqnum);
			header.confirmed_data.sendseqnum = (data_bytes[9] & 0b01110000) >> 4;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  send seqnum: %u\n", header.confirmed_data.sendseqnum);
			break;
		case DMRPACKET_DATA_HEADER_DPF_RESPONSE:
			header.response.blocks_to_follow = data_bytes[8] & 0b01111111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  blocks to follow: %u\n", header.response.blocks_to_follow);
			header.response.class =	(data_bytes[9] & 0b11000000) >> 6;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  class: %.2x\n", header.response.class);
			header.response.type = (data_bytes[9] & 0b00111000) >> 3;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  type: %.2x\n", header.response.type);
			header.response.status = data_bytes[9] & 0b111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  status: %.2x\n", header.response.status);
			break;
		case DMRPACKET_DATA_HEADER_DPF_PROPRIETARY_DATA: // This is handled at the beginning of this function.
			return &header;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW:
			header.short_data_raw.appended_blocks = (data_bytes[0] & 0b00110000) | (data_bytes[1] & 0b1111);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  appended blocks: %u\n", header.short_data_raw.appended_blocks);
			header.short_data_raw.source_port = (data_bytes[8] & 0b11100000) >> 5;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  source port: %u\n", header.short_data_raw.source_port);
			header.short_data_raw.destination_port = (data_bytes[8] & 0b11100) >> 2;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  destination port: %u\n", header.short_data_raw.destination_port);
			header.short_data_raw.resync =  (data_bytes[8] & 0b10) > 0;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  resync: %u\n", header.short_data_raw.resync);
			header.short_data_raw.full_message = (data_bytes[8] & 0b1) > 0;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  full message: %u\n", header.short_data_raw.full_message);
			header.short_data_raw.bit_padding = data_bytes[9];
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  bit padding: %u\n", header.short_data_raw.bit_padding);
			break;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED:
			header.short_data_defined.appended_blocks = (data_bytes[0] & 0b00110000) | (data_bytes[1] & 0b1111);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  appended blocks: %u\n", header.short_data_defined.appended_blocks);
			header.short_data_defined.dd_format = (data_bytes[8] & 0b11111100) >> 2;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  dd format: %.2x (%s)\n", header.short_data_defined.dd_format, dmrpacket_data_header_get_readable_dd_format(header.short_data_defined.dd_format));
			header.short_data_defined.resync = (data_bytes[8] & 0b10) > 0;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  resync: %u\n", header.short_data_defined.resync);
			header.short_data_defined.full_message = (data_bytes[8] & 0b1) > 0;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  full message: %u\n", header.short_data_defined.full_message);
			header.short_data_defined.bit_padding =	data_bytes[9];
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  bit padding: %u\n", header.short_data_defined.bit_padding);
			break;
		case DMRPACKET_DATA_HEADER_DPF_UDT:
			header.udt.format =	data_bytes[1] & 0b1111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  udt format: %.2x (%s)\n", header.udt.format, dmrpacket_data_header_get_readable_udt_format(header.udt.format));
			header.udt.pad_nibble =	(data_bytes[8] & 0b11111000) >> 3;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  pad nibble: %u\n", header.udt.pad_nibble);
			header.udt.appended_blocks = data_bytes[8] & 0b11;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  appended blocks: %u\n", header.udt.appended_blocks);
			header.udt.supplementary_flag = (data_bytes[9] & 0b10000000) > 0;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  supplementary flag: %u\n", header.udt.supplementary_flag);
			header.udt.opcode = data_bytes[9] & 0b00111111;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  opcode: %u\n", header.udt.opcode);
			break;
		default:
			console_log(LOGLEVEL_DMRDATA "dmrpacket data error: unknown header data packet format\n");
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

bptc_196_96_data_bits_t *dmrpacket_data_header_construct(dmrpacket_data_header_t *header, flag_t proprietary_header) {
	static bptc_196_96_data_bits_t data_bits;
	uint8_t data_bytes[sizeof(bptc_196_96_data_bits_t)/8] = {0,};
	uint16_t crcval;

	if (header == NULL)
		return NULL;

	if (proprietary_header) {
		data_bytes[0] = (header->common.service_access_point & 0b1111) << 4 |
						(header->common.data_packet_format & 0b1111);
		data_bytes[1] = header->proprietary.manufacturer_id;
		memcpy(&data_bytes[2], header->proprietary.data, 8);
	} else {
		// These fields are common for each data packet format.
		data_bytes[0] = (header->common.data_packet_format & 0b1111) |
						(header->common.dst_is_a_group > 0) << 7 |
						(header->common.response_requested > 0) << 6;
		data_bytes[1] = (header->common.service_access_point & 0b1111) << 4;
		data_bytes[2] = (header->common.dst_llid & 0xff0000) >> 16;
		data_bytes[3] = (header->common.dst_llid & 0x00ff00) >> 8;
		data_bytes[4] = (header->common.dst_llid & 0x0000ff);
		data_bytes[5] = (header->common.src_llid & 0xff0000) >> 16;
		data_bytes[6] = (header->common.src_llid & 0x00ff00) >> 8;
		data_bytes[7] = (header->common.src_llid & 0x0000ff);

		switch (header->common.data_packet_format) {
			case DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA:
				data_bytes[0] |=	(header->unconfirmed_data.pad_octet_count & 0b10000);
				data_bytes[2] |=	(header->unconfirmed_data.pad_octet_count & 0b01111);
				data_bytes[8] |=	(header->unconfirmed_data.full_message > 0) << 7 |
									(header->unconfirmed_data.blocks_to_follow & 0b01111111);
				data_bytes[9] |=	(header->unconfirmed_data.fragmentseqnum & 0b1111);
				break;
			case DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA:
				data_bytes[0] |=	(header->confirmed_data.pad_octet_count & 0b10000);
				data_bytes[1] |=	(header->confirmed_data.pad_octet_count & 0b01111);
				data_bytes[8] |=	(header->confirmed_data.full_message > 0) << 7 |
									(header->confirmed_data.blocks_to_follow & 0b01111111);
				data_bytes[9] |=	(header->confirmed_data.fragmentseqnum & 0b1111) |
									(header->confirmed_data.resync > 0) << 7 |
									(header->confirmed_data.sendseqnum & 0b111) << 4;
				break;
			case DMRPACKET_DATA_HEADER_DPF_RESPONSE:
				data_bytes[8] |=	(header->response.blocks_to_follow & 0b01111111);
				data_bytes[9] |=	(header->response.class & 0b11) << 6 |
									(header->response.type & 0b111) << 3 |
									(header->response.status & 0b111);
				break;
			case DMRPACKET_DATA_HEADER_DPF_PROPRIETARY_DATA: // This is handled at the beginning of this function.
				break;
			case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW:
				data_bytes[0] |=	(header->short_data_raw.appended_blocks & 0b110000);
				data_bytes[1] |=	(header->short_data_raw.appended_blocks & 0b001111);
				data_bytes[8] |=	(header->short_data_raw.source_port & 0b111) << 5 |
									(header->short_data_raw.destination_port & 0b111) << 2 |
									(header->short_data_raw.resync > 0) << 1 |
									(header->short_data_raw.full_message > 0);
				data_bytes[9] = header->short_data_raw.bit_padding;
				break;
			case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED:
				data_bytes[0] |=	(header->short_data_defined.appended_blocks & 0b110000);
				data_bytes[1] |=	(header->short_data_defined.appended_blocks & 0b001111);
				data_bytes[8] |=	(header->short_data_defined.dd_format & 0b111111) << 2 |
									(header->short_data_defined.resync > 0) << 1 |
									(header->short_data_defined.full_message > 0);
				data_bytes[9] = header->short_data_defined.bit_padding;
				break;
			case DMRPACKET_DATA_HEADER_DPF_UDT:
				data_bytes[1] |=	(header->udt.format & 0b1111);
				data_bytes[8] |=	(header->udt.pad_nibble & 0b11111) << 3 |
									(header->udt.appended_blocks & 0b11);
				data_bytes[9] |=	(header->udt.supplementary_flag > 0) << 7 |
									(header->udt.opcode & 0b111111);
				break;
			default:
				return NULL;
		}
	}

	crcval = dmrpacket_data_header_crc_calc(data_bytes);
	data_bytes[10] = (crcval & 0xff00) >> 8;
	data_bytes[11] = crcval & 0xff;

	base_bytestobits(data_bytes, sizeof(data_bytes), data_bits.bits, sizeof(bptc_196_96_data_bits_t));
	return &data_bits;
}
