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
		case DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION: return "rate 1/2 data continuation";
		case DMRPACKET_DATA_TYPE_RATE_34_DATA_CONTINUATION: return "rate 3/4 data continuation";
		case DMRPACKET_DATA_TYPE_IDLE: return "idle";
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
	loglevel_t loglevel = console_get_loglevel();

	if (binary == NULL)
		return NULL;

	if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "dmrpacket data: converting binary data to bytes\n");
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
	console_log(LOGLEVEL_DMRDATA "confirmed data type %s\n", dmrpacket_data_get_readable_data_type(data_type));

	memset(&data_block, 0, sizeof(dmrpacket_data_block_t));

	if (confirmed) {
		switch (data_type) {
			case DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION: data_block.data_length = 10; break;
			case DMRPACKET_DATA_TYPE_RATE_34_DATA_CONTINUATION: data_block.data_length = 16; break;
			default:
				console_log(LOGLEVEL_DMRDATA "dmrpacket data: can't decode block, unsupported data type %.2x\n", data_type);
				return NULL;
		}

		data_block.serialnr = bytes->bytes[0] >> 1;
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  serialnr: %u\n", data_block.serialnr);

		data_block.crc = ((bytes->bytes[0] & 0b00000001) << 8) | bytes->bytes[1];
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  crc: 0x%.4x\n", data_block.crc);
	} else {
		switch (data_type) {
			case DMRPACKET_DATA_TYPE_RATE_12_DATA_CONTINUATION: data_block.data_length = 12; break;
			case DMRPACKET_DATA_TYPE_RATE_34_DATA_CONTINUATION: data_block.data_length = 18; break;
			default:
				console_log(LOGLEVEL_DMRDATA "dmrpacket data: can't decode block, unsupported data type %.2x\n", data_type);
				return NULL;
		}
	}

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
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  crc ok\n", crcval);
		return &data_block;
	} else {
		console_log(LOGLEVEL_DMRDATA "dmrpacket data: block crc error (calculated: 0x%.4x)\n", crcval);
		return NULL;
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
				memcpy(&data.bytes[data.bytes_stored], blocks[i].data, blocks[i].data_length - 4); // Leaving out the last 4 CRC bytes.
				data.bytes_stored += blocks[i].data_length - 4;
			}
			data.crc =	blocks[i].data[blocks[i].data_length-1] << 24 |
						blocks[i].data[blocks[i].data_length-2] << 16 |
						blocks[i].data[blocks[i].data_length-3] << 8 |
						blocks[i].data[blocks[i].data_length-4];
		}
	}

	if (loglevel.flags.dmrdata) {
		console_log(LOGLEVEL_DMRDATA "  data (len. %u): ", data.bytes_stored);
		for (i = 0; i < data.bytes_stored; i++)
			console_log(LOGLEVEL_DMRDATA "%.2x", data.bytes[i]);
		console_log(LOGLEVEL_DMRDATA "\n");
	}

	for (i = 0; i < data.bytes_stored; i += 2) {
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

char *dmrpacket_data_convertmsg(dmrpacket_data_fragment_t *fragment, dmrpacket_data_header_dd_format_t dd_format) {
	iconv_t iconv_handle;
	int result;
	size_t insize = 0;
	char *deinterleaved_msg = NULL;
	char *inptr;
	static char outbuf[DMRPACKET_MAX_FRAGMENTSIZE*4+1]; // Max. char width is 4 bytes.
	size_t outsize = sizeof(outbuf);
	char *outptr = outbuf;

	if (fragment == NULL)
		return NULL;

	memset(outbuf, 0, sizeof(outbuf));
	console_log(LOGLEVEL_DMRDATA "dmrpacket data: converting message from format %s (%.2x)\n", dmrpacket_data_header_get_readable_dd_format(dd_format), dd_format);

	switch (dd_format) {
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16LE:
			deinterleaved_msg = dmrpacket_data_deinterleave_message((char *)fragment->bytes, fragment->bytes_stored);
			break;
		default:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF8:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF16BE:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32BE:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_UTF32LE:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_BINARY:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_BCD:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_7BIT_CHAR:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_1:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_2:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_3:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_4:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_5:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_6:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_7:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_8:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_9:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_10:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_11:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_13:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_14:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_15:
		case DMRPACKET_DATA_HEADER_DD_FORMAT_8BIT_ISO8859_16:
			break;
	}

	if (deinterleaved_msg == NULL) {
		iconv_handle = iconv_open("utf-8", dmrpacket_data_header_get_readable_dd_format(dd_format));
		if (iconv_handle == (iconv_t)-1) {
			if (errno == EINVAL)
				console_log(LOGLEVEL_DMRDATA "dmrpacket data: can't convert data from %s to utf8, charset not supported by iconv\n", dmrpacket_data_header_get_readable_dd_format(dd_format));
			else
				console_log(LOGLEVEL_DMRDATA "dmrpacket data: can't convert data from %s to utf8, iconv init error\n", dmrpacket_data_header_get_readable_dd_format(dd_format));
			return NULL;
		}


		insize = fragment->bytes_stored;
		inptr = deinterleaved_msg;
		result = iconv(iconv_handle, &inptr, &insize, &outptr, &outsize);
		iconv_close(iconv_handle);
		if (result < 0) {
			console_log(LOGLEVEL_DMRDATA "dmrpacket data warning: can't convert data from %s to utf8, iconv error\n", dmrpacket_data_header_get_readable_dd_format(dd_format));
			memcpy(outbuf, fragment->bytes, fragment->bytes_stored);
		}
	} else {
		strncpy(outbuf, deinterleaved_msg, sizeof(outbuf));
		free(deinterleaved_msg);
	}

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

dmrpacket_data_block_t *dmrpacket_data_construct_message_blocks(dmrpacket_data_fragment_t *fragment) {
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
		data_blocks[i].serialnr = i;
		data_blocks[i].data_length = 16;

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

dmrpacket_data_fragment_t *dmrpacket_data_construct_fragment(uint8_t *data, uint16_t data_size) {
	static dmrpacket_data_fragment_t fragment;
	uint8_t pad_octets;
	uint16_t i;
	loglevel_t loglevel = console_get_loglevel();

	if (data == NULL || data_size == 0)
		return NULL;

	memset((uint8_t *)&fragment, 0, sizeof(dmrpacket_data_fragment_t));
	fragment.bytes_stored = min(data_size, DMRPACKET_MAX_FRAGMENTSIZE);
	memcpy(fragment.bytes, data, fragment.bytes_stored);

	// See DMR AI spec. page. 73. - confirmed rate 3/4
	fragment.data_blocks_needed = ceil(fragment.bytes_stored / 16.0);
	// Checking if there's no space left in the last data block for the fragment CRC.
	if (fragment.data_blocks_needed*16-fragment.bytes_stored < 4)
		fragment.data_blocks_needed++;

	pad_octets = (fragment.data_blocks_needed*16-4)-fragment.bytes_stored; // -4 - fragment CRC

	for (i = 0; i < fragment.bytes_stored+pad_octets; i += 2) {
		if (i+1 < fragment.bytes_stored)
			crc_calc_crc32(&fragment.crc, fragment.bytes[i+1]);
		else
			crc_calc_crc32(&fragment.crc, 0);
		if (i < fragment.bytes_stored)
			crc_calc_crc32(&fragment.crc, fragment.bytes[i]);
		else
			crc_calc_crc32(&fragment.crc, 0);
	}
	crc_calc_crc32_finish(&fragment.crc);

	if (loglevel.flags.dmrdata && loglevel.flags.debug) {
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  message length: %u bytes, fragment crc: %.8x, needed blocks: %u, pad octets: %u\n",
			fragment.bytes_stored, fragment.crc, fragment.data_blocks_needed, pad_octets);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  message bytes: ");
		for (i = 0; i < fragment.bytes_stored; i++)
			console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "%.2x", fragment.bytes[i]);
		console_log(LOGLEVEL_DMRDATA LOGLEVEL_DEBUG " %.8x\n", fragment.crc);
	}

	return &fragment;
}

// Converts the message to the following Hytera format: the first two bytes are zeroes,
// then it places a zero after every char. The returned memory area must be freed later.
// Size of the interleaved message without the closing 0 is returned in *interleaved_msg_length.
char *dmrpacket_data_interleave_message(char *msg, uint16_t *interleaved_msg_length) {
	char *new_msg;
	uint16_t msg_len;
	uint16_t i;

	if (msg == NULL || interleaved_msg_length == NULL)
		return NULL;

	msg_len = strlen(msg);
	*interleaved_msg_length = min(2+msg_len*2+1, DMRPACKET_MAX_FRAGMENTSIZE);
	new_msg = (char *)calloc(1, *interleaved_msg_length);
	if (new_msg == NULL) {
		console_log("dmrpacket data error: can't allocate memory for interleaving message\n");
		return NULL;
	}

	for (i = 0; i < msg_len; i++)
		new_msg[2+i*2] = msg[i];

	return new_msg;
}

char *dmrpacket_data_deinterleave_message(char *msg, uint16_t msg_length) {
	char *new_msg;
	uint16_t new_msg_len;
	uint16_t i;

	if (msg == NULL || msg_length == 0)
		return NULL;

	new_msg_len = ceil((msg_length-2)/2.0)+1;
	new_msg = (char *)calloc(1, new_msg_len);
	if (new_msg == NULL) {
		console_log("dmrpacket data error: can't allocate memory for deinterleaving message\n");
		return NULL;
	}

	for (i = 0; i < new_msg_len; i++)
		new_msg[i] = msg[2+i*2];
	return new_msg;
}
