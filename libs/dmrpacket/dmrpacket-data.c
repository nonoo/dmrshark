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

#include "dmrpacket-data.h"
#include "dmrpacket.h"

#include <libs/coding/crc.h>
#include <libs/daemon/console.h>
#include <libs/base/base.h>
#include <libs/comm/comm.h>

#include <string.h>
#include <math.h>
#include <stdlib.h>

char *dmrpacket_data_get_readable_data_type(dmrpacket_data_type_t data_type) {
	switch (data_type) {
		case DMRPACKET_DATA_TYPE_PI_HEADER: return "pi header";
		case DMRPACKET_DATA_TYPE_VOICE_LC_HEADER: return "voice lc header";
		case DMRPACKET_DATA_TYPE_TERMINATOR_WITH_LC: return "terminator with lc";
		case DMRPACKET_DATA_TYPE_CSBK: return "csbk";
		case DMRPACKET_DATA_TYPE_MBC_HEADER: return "mbc header";
		case DMRPACKET_DATA_TYPE_MBC_CONTINUATION: return "mbc continuation";
		case DMRPACKET_DATA_TYPE_DATA_HEADER: return "data header";
		case DMRPACKET_DATA_TYPE_RATE_12_DATA: return "rate 1/2 data";
		case DMRPACKET_DATA_TYPE_RATE_34_DATA: return "rate 3/4 data";
		case DMRPACKET_DATA_TYPE_IDLE: return "idle";
		case DMRPACKET_DATA_TYPE_RATE_1_DATA: return "rate 1 data";
		default: return "unknown";
	}
}

bptc_196_96_data_bits_t *dmrpacket_data_extract_and_repair_bptc_data(dmrpacket_payload_bits_t *packet_payload_bits) {
	dmrpacket_payload_info_bits_t *packet_payload_info_bits = NULL;

	packet_payload_info_bits = dmrpacket_extract_info_bits(packet_payload_bits);
	packet_payload_info_bits = dmrpacket_data_bptc_deinterleave(packet_payload_info_bits);
	if (bptc_196_96_check_and_repair(packet_payload_info_bits->bits))
		return bptc_196_96_extractdata(packet_payload_info_bits->bits);
	else
		return NULL;
}

// Deinterleaves given info bits according to the used BPTC(196,96) interleaving in the DMR standard (see DMR AI spec. page 120).
dmrpacket_payload_info_bits_t *dmrpacket_data_bptc_deinterleave(dmrpacket_payload_info_bits_t *info_bits) {
	static dmrpacket_payload_info_bits_t deint_info_bits;
	int i;

	if (info_bits == NULL)
		return NULL;

	for (i = 0; i < sizeof(info_bits->bits); i++)
		deint_info_bits.bits[i] = info_bits->bits[(i*181) % sizeof(info_bits->bits)];

	return &deint_info_bits;
}

// Interleaves given info bits according to the used BPTC(196,96) interleaving in the DMR standard (see DMR AI spec. page 120).
dmrpacket_payload_info_bits_t *dmrpacket_data_bptc_interleave(dmrpacket_payload_info_bits_t *deint_info_bits) {
	static dmrpacket_payload_info_bits_t int_info_bits;
	int i;

	if (deint_info_bits == NULL)
		return NULL;

	for (i = 0; i < sizeof(deint_info_bits->bits); i++)
		int_info_bits.bits[(i*181) % sizeof(int_info_bits.bits)] = deint_info_bits->bits[i];

	return &int_info_bits;
}

dmrpacket_data_block_bytes_t *dmrpacket_data_convert_binary_to_block_bytes(dmrpacket_data_binary_t *binary) {
	static dmrpacket_data_block_bytes_t bytes;
	uint8_t i;
	//loglevel_t loglevel = console_get_loglevel();

	if (binary == NULL)
		return NULL;

	/*if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "dmrpacket data: converting binary data to bytes\n");
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  input: ");
		for (i = 0; i < sizeof(binary->bits); i++) {
			if (i > 0 && i % 8 == 0)
				console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG " ");
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%u", binary->bits[i]);
		}
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");
	}*/

	for (i = 0; i < sizeof(binary->bits)/8; i++)
		bytes.bytes[i] = base_bitstobyte(&binary->bits[i*8]);

	/*if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  output: ");
		for (i = 0; i < sizeof(binary->bits)/8; i++)
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%.2x ", bytes.bytes[i]);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");
	}*/

	return &bytes;
}

dmrpacket_data_block_bytes_t *dmrpacket_data_convert_payload_bptc_data_bits_to_block_bytes(bptc_196_96_data_bits_t *binary) {
	static dmrpacket_data_block_bytes_t bytes;
	uint8_t i;
	loglevel_t loglevel = console_get_loglevel();

	if (binary == NULL)
		return NULL;

	if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "dmrpacket data: converting payload data bits to bytes\n");
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  input: ");
		for (i = 0; i < sizeof(binary->bits); i++) {
			if (i > 0 && i % 8 == 0)
				console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG " ");
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%u", binary->bits[i]);
		}
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");
	}

	for (i = 0; i < sizeof(binary->bits)/8; i++)
		bytes.bytes[i] = base_bitstobyte(&binary->bits[i*8]);

	if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  output: ");
		for (i = 0; i < sizeof(binary->bits)/8; i++)
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%.2x ", bytes.bytes[i]);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");
	}

	return &bytes;
}

// See DMR AI spec. page. 73. for block sizes.
uint8_t dmrpacket_data_get_block_size(dmrpacket_data_type_t data_type, flag_t confirmed) {
	switch (data_type) {
		case DMRPACKET_DATA_TYPE_RATE_1_DATA: return (confirmed ? 22 : 24);
		case DMRPACKET_DATA_TYPE_RATE_34_DATA: return (confirmed ? 16 : 18);
		case DMRPACKET_DATA_TYPE_RATE_12_DATA: return (confirmed ? 10 : 12);
		default: return 0;
	}
}

dmrpacket_data_block_t *dmrpacket_data_decode_block(dmrpacket_data_block_bytes_t *bytes, dmrpacket_data_type_t data_type, flag_t confirmed) {
	static dmrpacket_data_block_t data_block;
	uint16_t crcval = 0; // See DMR AI spec. page 142.
	uint8_t i;
	loglevel_t loglevel = console_get_loglevel();

	if (bytes == NULL)
		return NULL;

	console_log(LOGLEVEL_DMRDATA "dmrpacket data: decoding ");
	if (!confirmed)
		console_log(LOGLEVEL_DMRDATA "un");
	console_log(LOGLEVEL_DMRDATA "confirmed data block type %s\n", dmrpacket_data_get_readable_data_type(data_type));

	memset(&data_block, 0, sizeof(dmrpacket_data_block_t));
	data_block.data_length = dmrpacket_data_get_block_size(data_type, confirmed);

	if (confirmed) {
		data_block.serialnr = bytes->bytes[0] >> 1;
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  serialnr: %u\n", data_block.serialnr);

		data_block.crc = ((bytes->bytes[0] & 0b00000001) << 8) | bytes->bytes[1];
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  crc: 0x%.4x\n", data_block.crc);

		memcpy(data_block.data, &bytes->bytes[2], sizeof(data_block.data));
		if (loglevel.flags.dmrdata && loglevel.flags.debug) {
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  data (len. %u): ", data_block.data_length);
			for (i = 0; i < data_block.data_length; i++)
				console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%.2x", data_block.data[i]);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");
		}

		for (i = 0; i < data_block.data_length; i++)
			crc_calc_crc9(&crcval, data_block.data[i], 8);
		crc_calc_crc9(&crcval, data_block.serialnr, 7);
		// Getting out only 8 bits from the shift registers as previously we only put in 7 bits.
		crc_calc_crc9_finish(&crcval, 8);

		// Inverting according to the inversion polynomial.
		crcval = ~crcval;
		crcval &= 0x01ff;
		// Applying CRC mask, see DMR AI spec. page 143.
		crcval ^= 0x01ff;

		if (crcval == data_block.crc) {
			data_block.received_ok = 1;
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  crc ok\n", crcval);
			return &data_block;
		} else {
			console_log(LOGLEVEL_DMRDATA "dmrpacket data: block crc error (calculated: 0x%.4x)\n", crcval);
			return NULL;
		}
	} else {
		memcpy(data_block.data, bytes->bytes, sizeof(data_block.data));
		if (loglevel.flags.dmrdata && loglevel.flags.debug) {
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  data (len. %u): ", data_block.data_length);
			for (i = 0; i < data_block.data_length; i++)
				console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "%.2x", data_block.data[i]);
			console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "\n");
		}

		data_block.received_ok = 1;

		return &data_block;
	}
}

dmrpacket_data_fragment_t *dmrpacket_data_extract_fragment_from_blocks(dmrpacket_data_block_t *blocks, uint8_t blocks_count) {
	static dmrpacket_data_fragment_t data;
	uint16_t i;
	uint32_t crcval = 0;
	loglevel_t loglevel = console_get_loglevel();

	if (blocks == NULL || blocks_count == 0)
		return NULL;

	memset(&data, 0, sizeof(dmrpacket_data_fragment_t));

	console_log(LOGLEVEL_DMRDATA "dmrpacket data: extracting fragment from %u blocks\n", blocks_count);
	for (i = 0; i < blocks_count; i++) {
		if (blocks[i].data_length == 0)
			continue;

		if (i < blocks_count-1) {
			if (data.bytes_stored+blocks[i].data_length < sizeof(data.bytes)) {
				memcpy(&data.bytes[data.bytes_stored], blocks[i].data, blocks[i].data_length);
				data.bytes_stored += blocks[i].data_length;
			}
		} else {
			if (data.bytes_stored+blocks[i].data_length-4 < sizeof(data.bytes)) {
				memcpy(&data.bytes[data.bytes_stored], blocks[i].data, blocks[i].data_length);
				data.bytes_stored += blocks[i].data_length;
			}
			data.crc =	blocks[i].data[blocks[i].data_length-1] << 24 |
						blocks[i].data[blocks[i].data_length-2] << 16 |
						blocks[i].data[blocks[i].data_length-3] << 8 |
						blocks[i].data[blocks[i].data_length-4];
		}
	}

	if (loglevel.flags.dmrdata) {
		console_log(LOGLEVEL_DMRDATA "  data (len. %u): ", data.bytes_stored);
		for (i = 0; i < data.bytes_stored-4; i++)
			console_log(LOGLEVEL_DMRDATA "%.2x", data.bytes[i]);
		// Printing the CRC separated.
		console_log(LOGLEVEL_DMRDATA " ");
		for (; i < data.bytes_stored; i++)
			console_log(LOGLEVEL_DMRDATA "%.2x", data.bytes[i]);
		console_log(LOGLEVEL_DMRDATA "\n");
	}

	for (i = 0; i < data.bytes_stored-4; i += 2) {
		crc_calc_crc32(&crcval, data.bytes[i+1]);
		crc_calc_crc32(&crcval, data.bytes[i]);
	}
	crc_calc_crc32_finish(&crcval);
	console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  fragment crc: %.8x, calculated: %.8x (", data.crc, crcval);

	if (crcval == data.crc) {
		console_log(LOGLEVEL_DMRDATA "ok)\n");
		return &data;
	} else {
		console_log(LOGLEVEL_DMRDATA "error)\n");
		return NULL;
	}
}

char *dmrpacket_data_convertmsg(uint8_t *data, uint16_t data_length, uint16_t *out_length, dmrpacket_data_header_dd_format_t src_dd_format, dmrpacket_data_header_dd_format_t dst_dd_format, uint8_t add_to_left) {
	iconv_t iconv_handle;
	int result;
	size_t insize = 0;
	char *inptr;
	static char outbuf[DMRPACKET_MAX_FRAGMENTSIZE*4+1]; // Max. char width is 4 bytes.
	char *outptr = outbuf+add_to_left;
	size_t outsize = sizeof(outbuf)-add_to_left;

	if (data == NULL || data_length == 0)
		return NULL;

	memset(outbuf, 0, sizeof(outbuf));
	console_log(LOGLEVEL_DMRDATA "dmrpacket data: converting message from format %s (%.2x) to %s (%.2x)\n", dmrpacket_data_header_get_readable_dd_format(src_dd_format), src_dd_format,
		dmrpacket_data_header_get_readable_dd_format(dst_dd_format), dst_dd_format);

	iconv_handle = iconv_open(dmrpacket_data_header_get_readable_dd_format(dst_dd_format), dmrpacket_data_header_get_readable_dd_format(src_dd_format));
	if (iconv_handle == (iconv_t)-1) {
		if (errno == EINVAL)
			console_log(LOGLEVEL_DMRDATA "dmrpacket data: can't convert data from %s to %s, charset not supported by iconv\n", dmrpacket_data_header_get_readable_dd_format(src_dd_format), dmrpacket_data_header_get_readable_dd_format(dst_dd_format));
		else
			console_log(LOGLEVEL_DMRDATA "dmrpacket data: can't convert data from %s to %s, iconv init error\n", dmrpacket_data_header_get_readable_dd_format(src_dd_format), dmrpacket_data_header_get_readable_dd_format(dst_dd_format));
		return NULL;
	}

	insize = data_length;
	inptr = (char *)data;
	result = iconv(iconv_handle, &inptr, &insize, &outptr, &outsize);
	iconv_close(iconv_handle);
	if (result < 0) {
		console_log(LOGLEVEL_DMRDATA "dmrpacket data warning: can't convert data from %s to %s, iconv error\n", dmrpacket_data_header_get_readable_dd_format(src_dd_format), dmrpacket_data_header_get_readable_dd_format(src_dd_format));
		*out_length = min(data_length, sizeof(outbuf));
		memcpy(outbuf, data, *out_length);
	}

	if (out_length != NULL)
		*out_length = sizeof(outbuf)-outsize;
	return outbuf;
}

dmrpacket_data_block_bytes_t *dmrpacket_data_construct_block_bytes(dmrpacket_data_block_t *data_block, flag_t confirmed) {
	static dmrpacket_data_block_bytes_t bytes;

	if (data_block == NULL)
		return NULL;

	memset(bytes.bytes, 0, sizeof(dmrpacket_data_block_bytes_t));
	if (confirmed) {
		bytes.bytes[0] = (data_block->serialnr << 1) | ((data_block->crc & 0x0100) >> 8);
		bytes.bytes[1] = data_block->crc & 0xff;
		memcpy(bytes.bytes+2, data_block->data, data_block->data_length);
	} else
		memcpy(bytes.bytes, data_block->data, data_block->data_length);
	return &bytes;
}

dmrpacket_data_block_t *dmrpacket_data_construct_data_blocks(dmrpacket_data_fragment_t *fragment, dmrpacket_data_type_t data_type, flag_t confirmed) {
	uint16_t bytes_stored_in_blocks = 0;
	uint8_t bytes_to_store;
	uint8_t i;
	uint16_t j;
	dmrpacket_data_block_t *data_blocks;

	if (fragment == NULL || fragment->data_blocks_needed == 0)
		return NULL;

	data_blocks = (dmrpacket_data_block_t *)calloc(1, fragment->data_blocks_needed*sizeof(dmrpacket_data_block_t));
	if (data_blocks == NULL) {
		console_log("  error: can't allocate memory for data blocks\n");
		return NULL;
	}

	for (i = 0; i < fragment->data_blocks_needed; i++) {
		data_blocks[i].serialnr = i % 128;
		data_blocks[i].data_length = dmrpacket_data_get_block_size(data_type, confirmed);

		if (i == fragment->data_blocks_needed-1) { // Storing the fragment CRC in the last block.
			data_blocks[i].data[data_blocks[i].data_length-1] = (fragment->crc >> 24) & 0xff;
			data_blocks[i].data[data_blocks[i].data_length-2] = (fragment->crc >> 16) & 0xff;
			data_blocks[i].data[data_blocks[i].data_length-3] = (fragment->crc >> 8) & 0xff;
			data_blocks[i].data[data_blocks[i].data_length-4] = fragment->crc & 0xff;
		}

		bytes_to_store = min(data_blocks[i].data_length, fragment->bytes_stored-bytes_stored_in_blocks);
		memcpy(data_blocks[i].data, fragment->bytes+bytes_stored_in_blocks, bytes_to_store);
		bytes_stored_in_blocks += bytes_to_store;

		data_blocks[i].crc = 0;
		for (j = 0; j < data_blocks[i].data_length; j++)
			crc_calc_crc9(&data_blocks[i].crc, data_blocks[i].data[j], 8);
		crc_calc_crc9(&data_blocks[i].crc, data_blocks[i].serialnr, 7);
		// Getting out only 8 bits from the shift registers as previously we only put in 7 bits.
		crc_calc_crc9_finish(&data_blocks[i].crc, 8);

		// Inverting according to the inversion polynomial.
		data_blocks[i].crc = ~data_blocks[i].crc;
		data_blocks[i].crc &= 0x01ff;
		// Applying CRC mask, see DMR AI spec. page 143.
		data_blocks[i].crc ^= 0x01ff;

		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "  block #%u length: %u crc: %.4x bytes: ", i, data_blocks[i].data_length, data_blocks[i].crc);
		for (j = 0; j < data_blocks[i].data_length; j++)
			console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "%.2x", data_blocks[i].data[j]);
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "\n");
	}
	return data_blocks;
}

// See DMR AI spec. page. 73. for block sizes.
void dmrpacket_data_get_needed_blocks_count(uint16_t data_bytes_count, dmrpacket_data_type_t data_type, flag_t confirmed, uint8_t *data_blocks_needed) {
	uint8_t block_size = dmrpacket_data_get_block_size(data_type, confirmed);

	*data_blocks_needed = ceil(data_bytes_count / (float)block_size);

	// Checking if there's no space left in the last data block for the fragment CRC.
	if ((*data_blocks_needed)*block_size-data_bytes_count < 4)
		(*data_blocks_needed)++;
}

void dmrpacket_data_construct_fragment(uint8_t *data, uint16_t data_size, dmrpacket_data_type_t data_type, flag_t confirmed, dmrpacket_data_fragment_t *fragment) {
	uint8_t block_size;
	uint16_t i;
	loglevel_t loglevel = console_get_loglevel();

	if (data == NULL || data_size == 0)
		return;

	memset((uint8_t *)fragment, 0, sizeof(dmrpacket_data_fragment_t));
	fragment->bytes_stored = min(data_size, DMRPACKET_MAX_FRAGMENTSIZE);
	memcpy(fragment->bytes, data, fragment->bytes_stored);

	dmrpacket_data_get_needed_blocks_count(fragment->bytes_stored, data_type, confirmed, &fragment->data_blocks_needed);
	block_size = dmrpacket_data_get_block_size(data_type, confirmed);
	for (i = 0; i < fragment->data_blocks_needed*block_size-4; i += 2) {
		if (i+1 < fragment->bytes_stored)
			crc_calc_crc32(&fragment->crc, fragment->bytes[i+1]);
		else
			crc_calc_crc32(&fragment->crc, 0);
		if (i < fragment->bytes_stored)
			crc_calc_crc32(&fragment->crc, fragment->bytes[i]);
		else
			crc_calc_crc32(&fragment->crc, 0);
	}
	crc_calc_crc32_finish(&fragment->crc);

	if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  data length: %u bytes, fragment crc: %.8x, needed blocks: %u, total data length: %u\n",
			fragment->bytes_stored, fragment->crc, fragment->data_blocks_needed, fragment->data_blocks_needed*block_size);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  data bytes: ");
		for (i = 0; i < fragment->bytes_stored; i++)
			console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "%.2x", fragment->bytes[i]);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG " %.8x\n", fragment->crc);
	}
}

// Constructs a DMR-compatible IP/UDP packet. Returned memory area must be freed after use.
static struct iphdr *dmrpacket_construct_payload_ip_packet(uint16_t dstport, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, uint8_t *payload, uint16_t payload_size) {
	uint8_t *ip_packet_bytes;
	struct iphdr *ip_packet;
	struct udphdr *udp_packet;

	if (payload == NULL || payload_size == 0)
		return NULL;

	ip_packet_bytes = (uint8_t *)calloc(1, sizeof(struct iphdr)+sizeof(struct udphdr)+payload_size);
	if (ip_packet_bytes == NULL) {
		console_log("  error: can't allocate memory for ip packet bytes\n");
		return NULL;
	}

	ip_packet = (struct iphdr *)ip_packet_bytes;
	udp_packet = (struct udphdr *)(ip_packet_bytes+20);

	ip_packet->saddr = htonl(0x0c000000 + srcid);
	if (calltype == DMR_CALL_TYPE_PRIVATE) // See DMR data protocol spec. page 15. 0x0c is the network ID.
		ip_packet->daddr = htonl(0x0c000000 + dstid);
	else
		ip_packet->daddr = htonl((0b11100001 << 24) + dstid);
	ip_packet->ihl = 5;
	ip_packet->version = 4;
	ip_packet->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
	ip_packet->id = htonl(7777);
	ip_packet->ttl = (calltype == DMR_CALL_TYPE_PRIVATE ? 64 : 1);
	ip_packet->protocol = IPPROTO_UDP;
	ip_packet->check = comm_calcipheaderchecksum((struct ip *)ip_packet);
	udp_packet->source = htons(dstport);
	udp_packet->dest = htons(dstport);
	udp_packet->len = htons(sizeof(struct udphdr) + payload_size);
	memcpy(ip_packet_bytes+20+sizeof(struct udphdr), payload, payload_size);
	udp_packet->check = comm_calcudpchecksum((struct ip *)ip_packet, udp_packet);

	return (struct iphdr *)ip_packet_bytes;
}

// Constructs a Motorola TMS ACK UDP packet. Returned memory area must be freed after use.
struct iphdr *dmrpacket_construct_payload_motorola_tms_ack(dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, uint8_t rx_seqnum) {
	static uint8_t ack_payload[] = { 0x00, 0x03, 0xbf, 0x00, 0x00 };

	ack_payload[4] = rx_seqnum & 0b11111;
	return dmrpacket_construct_payload_ip_packet(4007, dstid, srcid, calltype, ack_payload, sizeof(ack_payload));
}

// Constructs a Motorola TMS message UDP packet. Returned memory area must be freed after use.
// See TMS patent at http://www.google.com/patents/US8023973
struct iphdr *dmrpacket_construct_payload_motorola_sms(char *msg, dmr_id_t dstid, dmr_id_t srcid, dmr_call_type_t calltype, uint8_t tx_seqnum) {
	// If the 3rd byte is 0xa0, then the receiving party won't send a TMS ACK. 0xe0 implies a TMS ACK packet.
	static uint8_t motorola_header[] = { 0x00, 0x00, 0xe0, 0x00, 0x00, 0x04, 0x0d, 0x00, 0x0a, 0x00 };
	uint8_t *payload;
	uint16_t payload_size;
	uint16_t tms_packet_length;
	char *utf16le_msg;
	uint16_t utf16le_msg_length;

	if (msg == NULL)
		return NULL;

	utf16le_msg = dmrpacket_data_convertmsg((uint8_t *)msg, strlen(msg), &utf16le_msg_length, DMRPACKET_DATA_HEADER_DD_FORMAT_UTF8, DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE, 0);
	payload_size = sizeof(motorola_header)+utf16le_msg_length;
	payload = (uint8_t *)calloc(1, payload_size);
	if (payload == NULL) {
		console_log("  error: can't allocate memory for motorola sms packet bytes\n");
		return NULL;
	}

	memcpy(payload, motorola_header, sizeof(motorola_header));
	tms_packet_length = sizeof(struct udphdr)+utf16le_msg_length;
	payload[0] = (tms_packet_length >> 8) & 0xff;
	payload[1] = tms_packet_length & 0xff;
	payload[4] = (tx_seqnum & 0b11111) | 0b10000000;
	memcpy(payload+sizeof(motorola_header), utf16le_msg, utf16le_msg_length);

	return dmrpacket_construct_payload_ip_packet(4007, dstid, srcid, calltype, payload, payload_size);
}
