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

#include "repeaters.h"
#include "comm.h"
#include "snmp.h"
#include "ipsc.h"

#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>
#include <libs/config/config.h>
#include <libs/remotedb/remotedb.h>
#include <libs/base/dmr-handle.h>
#include <libs/base/base.h>
#include <libs/dmrpacket/dmrpacket-emb.h>
#include <libs/dmrpacket/dmrpacket-lc.h>
#include <libs/voicestreams/voicestreams-decode.h>
#include <libs/coding/crc.h>
#include <libs/base/dmr-data.h>

#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>

static repeater_t *repeaters = NULL;

static char *repeaters_get_readable_slot_state(repeater_slot_state_t state) {
	switch (state) {
		case REPEATER_SLOT_STATE_IDLE: return "idle";
		case REPEATER_SLOT_STATE_VOICE_CALL_RUNNING: return "voice call running";
		case REPEATER_SLOT_STATE_DATA_CALL_RUNNING: return "data call running";
		default: return "unknown";
	}
}

repeater_t *repeaters_get(void) {
	return repeaters;
}

char *repeaters_get_display_string_for_ip(struct in_addr *ipaddr) {
	repeater_t *foundrep;

	foundrep = repeaters_findbyip(ipaddr);
	if (foundrep && foundrep->callsign_lowercase[0] != 0)
		return foundrep->callsign_lowercase;
	if (comm_is_our_ipaddr(ipaddr))
		return "ds";

	return comm_get_ip_str(ipaddr);
}

char *repeaters_get_display_string(repeater_t *repeater) {
	if (repeater->callsign[0] == 0)
		return comm_get_ip_str(&repeater->ipaddr);
	else
		return repeater->callsign_lowercase;
}

repeater_t *repeaters_findbyip(struct in_addr *ipaddr) {
	repeater_t *repeater = repeaters;

	if (ipaddr == NULL)
		return NULL;

	while (repeater) {
		if (memcmp(&repeater->ipaddr, ipaddr, sizeof(struct in_addr)) == 0)
			return repeater;

		repeater = repeater->next;
	}
	return NULL;
}

repeater_t *repeaters_findbyhost(char *host) {
	struct in_addr ipaddr;

	if (comm_hostname_to_ip(host, &ipaddr))
		return repeaters_findbyip(&ipaddr);
	else
		return NULL;
}

repeater_t *repeaters_findbycallsign(char *callsign) {
	repeater_t *repeater = repeaters;

	if (callsign == NULL)
		return NULL;

	while (repeater) {
		if (strcasecmp(repeater->callsign, callsign) == 0)
			return repeater;

		repeater = repeater->next;
	}
	return NULL;
}

repeater_t *repeaters_get_active(dmr_id_t src_id, dmr_id_t dst_id, dmr_call_type_t call_type) {
	repeater_t *repeater = repeaters;

	while (repeater) {
		if ((repeater->slot[0].state != REPEATER_SLOT_STATE_IDLE && repeater->slot[0].src_id == src_id && repeater->slot[0].dst_id == dst_id && repeater->slot[0].call_type == call_type) ||
			(repeater->slot[1].state != REPEATER_SLOT_STATE_IDLE && repeater->slot[1].src_id == src_id && repeater->slot[1].dst_id == dst_id && repeater->slot[1].call_type == call_type))
				return repeater;

		repeater = repeater->next;
	}
	return NULL;
}

static flag_t repeaters_issnmpignoredforip(struct in_addr *ipaddr) {
	char *ignoredhosts = config_get_ignoredsnmprepeaterhosts();
	char *tok = NULL;
	struct in_addr ignoredaddr;

	tok = strtok(ignoredhosts, ",");
	if (tok) {
		do {
			if (comm_hostname_to_ip(tok, &ignoredaddr)) {
				if (memcmp(&ignoredaddr, ipaddr, sizeof(struct in_addr)) == 0) {
					free(ignoredhosts);
					return 1;
				}
			} else
				console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters: can't resolve hostname %s\n", tok);

			tok = strtok(NULL, ",");
		} while (tok != NULL);
	}
	free(ignoredhosts);
	return 0;
}

static void repeaters_remove(repeater_t *repeater) {
	ipscrawpacketbuf_t *pb_nextentry;

	if (repeater == NULL)
		return;

	console_log("repeaters [%s]: removing\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));

	vbptc_16_11_free(&repeater->slot[0].emb_sig_lc_vbptc_storage);
	vbptc_16_11_free(&repeater->slot[1].emb_sig_lc_vbptc_storage);
	vbptc_16_11_free(&repeater->slot[0].ipsc_tx_emb_sig_lc_vbptc_storage);
	vbptc_16_11_free(&repeater->slot[1].ipsc_tx_emb_sig_lc_vbptc_storage);

	repeaters_free_echo_buf(repeater, 0);
	repeaters_free_echo_buf(repeater, 1);

	// Freeing up IPSC packet buffers for both slots.
	while (repeater->slot[0].ipsc_tx_rawpacketbuf) {
		pb_nextentry = repeater->slot[0].ipsc_tx_rawpacketbuf->next;
		free(repeater->slot[0].ipsc_tx_rawpacketbuf);
		repeater->slot[0].ipsc_tx_rawpacketbuf = pb_nextentry;
	}
	while (repeater->slot[1].ipsc_tx_rawpacketbuf) {
		pb_nextentry = repeater->slot[1].ipsc_tx_rawpacketbuf->next;
		free(repeater->slot[1].ipsc_tx_rawpacketbuf);
		repeater->slot[1].ipsc_tx_rawpacketbuf = pb_nextentry;
	}

	if (repeater->prev)
		repeater->prev->next = repeater->next;
	if (repeater->next)
		repeater->next->prev = repeater->prev;

	if (repeater == repeaters)
		repeaters = repeater->next;

	free(repeater);
}

repeater_t *repeaters_add(struct in_addr *ipaddr) {
	flag_t error = 0;
	repeater_t *repeater = repeaters_findbyip(ipaddr);

	if (ipaddr == NULL)
		return NULL;

	if (repeater == NULL) {
		repeater = (repeater_t *)calloc(sizeof(repeater_t), 1);
		if (repeater == NULL) {
			console_log("repeaters [%s]: can't add new repeater, not enough memory\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			return NULL;
		}
		memcpy(&repeater->ipaddr, ipaddr, sizeof(struct in_addr));

		// Expecting 8 rows of variable length BPTC coded embedded LC data.
		// It will contain 77 data bits (without the Hamming (16,11) checksums
		// and the last row of parity bits).
		if (!vbptc_16_11_init(&repeater->slot[0].emb_sig_lc_vbptc_storage, 8))
			error = 1;
		else {
			if (!vbptc_16_11_init(&repeater->slot[1].emb_sig_lc_vbptc_storage, 8)) {
				vbptc_16_11_free(&repeater->slot[0].emb_sig_lc_vbptc_storage);
				error = 1;
			}
		}
		if (error) {
			console_log("repeaters [%s]: can't add, not enough memory for embedded signalling lc storage\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			free(repeater);
			return NULL;
		}

		if (repeaters_issnmpignoredforip(ipaddr))
			repeater->snmpignored = 1;

		repeater->slot[0].voicestream = voicestreams_get_stream_for_repeater(ipaddr, 1);
#ifdef AMBEDECODEVOICE
		voicestreams_decode_ambe_init(repeater->slot[0].voicestream);
#endif
		repeater->slot[1].voicestream = voicestreams_get_stream_for_repeater(ipaddr, 2);
#ifdef AMBEDECODEVOICE
		voicestreams_decode_ambe_init(repeater->slot[1].voicestream);
#endif
		if (repeaters != NULL) {
			repeaters->prev = repeater;
			repeater->next = repeaters;
		}
		repeaters = repeater;

		console_log("repeaters [%s]: added, snmp ignored: %u ts1 stream: %s ts2 stream: %s\n",
			repeaters_get_display_string_for_ip(&repeater->ipaddr), repeater->snmpignored,
			repeater->slot[0].voicestream != NULL ? repeater->slot[0].voicestream->name : "no stream defined",
			repeater->slot[1].voicestream != NULL ? repeater->slot[1].voicestream->name : "no stream defined");
	}
	repeater->last_active_time = time(NULL);

	return repeater;
}

void repeaters_list(void) {
	repeater_t *repeater = repeaters;
	int i = 1;
	flag_t master;

	if (repeaters == NULL) {
		console_log("no repeaters found yet\n");
		return;
	}

	console_log("repeaters:\n");
	console_log("      nr              ip     id  callsign  act  lstinf         type        fwver    dlfreq    ulfreq snmp ts1/ts2 streams\n");
	while (repeater) {
		master = comm_is_masteripaddr(&repeater->ipaddr);
		console_log("  #%4u: %15s %6u %9s %4u  %6u %12s %12s %9u %9u    %u %s / %s\n",
			i++,
			comm_get_ip_str(&repeater->ipaddr),
			repeater->id,
			master ? "master" : repeater->callsign,
			master ? 0 : time(NULL)-repeater->last_active_time,
			master ? 0 : time(NULL)-repeater->last_repeaterinfo_request_time,
			repeater->type,
			repeater->fwversion,
			repeater->dlfreq,
			repeater->ulfreq,
			!repeater->snmpignored,
			repeater->slot[0].voicestream != NULL ? repeater->slot[0].voicestream->name : "n/a",
			repeater->slot[1].voicestream != NULL ? repeater->slot[1].voicestream->name : "n/a");

		repeater = repeater->next;
	}
}

void repeaters_state_change(repeater_t *repeater, dmr_timeslot_t timeslot, repeater_slot_state_t new_state) {
	console_log(LOGLEVEL_REPEATERS "repeaters [%s]: slot %u state change from %s to %s\n",
		repeaters_get_display_string_for_ip(&repeater->ipaddr), timeslot+1, repeaters_get_readable_slot_state(repeater->slot[timeslot].state),
		repeaters_get_readable_slot_state(new_state));
	repeater->slot[timeslot].state = new_state;

	if (repeater->auto_rssi_update_enabled_at != 0 &&
		repeater->slot[0].state != REPEATER_SLOT_STATE_VOICE_CALL_RUNNING &&
		repeater->slot[1].state != REPEATER_SLOT_STATE_VOICE_CALL_RUNNING) {
			console_log(LOGLEVEL_SNMP "repeaters [%s]: stopping auto repeater status update\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			repeater->auto_rssi_update_enabled_at = 0;
	}
}

void repeaters_add_to_ipsc_packet_buffer(repeater_t *repeater, dmr_timeslot_t ts, ipscpacket_raw_t *ipscpacket_raw, flag_t nowait) {
	ipscrawpacketbuf_t *newpbentry;
	ipscrawpacketbuf_t *pbentry;

	if (repeater == NULL || ipscpacket_raw == NULL)
		return;

	console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: adding entry to ts%u ipsc packet buffer\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ts+1);

	newpbentry = (ipscrawpacketbuf_t *)calloc(1, sizeof(ipscrawpacketbuf_t));
	if (newpbentry == NULL) {
		console_log(LOGLEVEL_REPEATERS "repeaters [%s] error: couldn't allocate memory for new ipsc packet buffer entry\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
		return;
	}

	memcpy(&newpbentry->ipscpacket_raw, ipscpacket_raw, sizeof(ipscpacket_raw_t));
	newpbentry->nowait = nowait;

	pbentry = repeater->slot[ts].ipsc_tx_rawpacketbuf;
	if (pbentry == NULL)
		repeater->slot[ts].ipsc_tx_rawpacketbuf = newpbentry;
	else {
		// Searching for the last element in the packet buffer.
		while (pbentry->next)
			pbentry = pbentry->next;
		pbentry->next = newpbentry;
	}

	daemon_poll_setmaxtimeout(0);
}

// Sends given raw IPSC packet to the given repeater.
static flag_t repeaters_send_raw_ipsc_packet(repeater_t *repeater, ipscpacket_raw_t *ipscpacket_raw) {
	struct sockaddr_in sin;
	int sockfd;

	if (repeater == NULL || ipscpacket_raw == NULL)
		return 0;

	// Need to use raw socket here, because if the master software is running,
	// we can't bind to the source port to set it in our UDP packet.
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: can't create raw socket for sending an udp packet\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
		return 0;
	}

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(62006);
	memcpy(&sin.sin_addr, &repeater->ipaddr, sizeof(struct in_addr));

	errno = 0;
	if (sendto(sockfd, ipscpacket_raw->bytes, sizeof(ipscpacket_raw_t), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) != sizeof(ipscpacket_raw_t)) {
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: can't send udp packet: %s\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), strerror(errno));
		close(sockfd);
		return 0;
	}
	close(sockfd);
	return 1;
}

void repeaters_send_ipsc_sync(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid) {
	ipscpacket_payload_t *ipscpacket_payload;

	if (repeater == NULL)
		return;

	console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: sending ipsc sync\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));

	ipscpacket_payload = ipscpacket_construct_payload_ipsc_sync(ts, dstid, srcid);
	repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(0, ts, IPSCPACKET_SLOT_TYPE_IPSC_SYNC, calltype, dstid, srcid, ipscpacket_payload)), 1);
}

void repeaters_start_voice_call(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid) {
	dmrpacket_emb_signalling_lc_bits_t *emb_signalling_lc_bits;
	uint8_t i;

	if (repeater == NULL)
		return;

	repeater->slot[ts].ipsc_tx_seqnum = 0;
	repeater->slot[ts].ipsc_tx_voice_frame_num = 2;
	if (!vbptc_16_11_init(&repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage, 8)) {
		console_log("repeaters [%s] error: can't allocate memory for vbptc encoding\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
		return;
	}
	emb_signalling_lc_bits = dmrpacket_emb_signalling_lc_interleave(dmrpacket_lc_construct_emb_signalling_lc(calltype, dstid, srcid));
	vbptc_16_11_construct(&repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage, emb_signalling_lc_bits->bits, sizeof(dmrpacket_emb_signalling_lc_bits_t));

	for (i = 0; i < 3; i++)
		repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_LC_HEADER, calltype, dstid, srcid, ipscpacket_construct_payload_voice_lc_header(calltype, dstid, srcid))), 0);
}

void repeaters_play_ambe_data(dmrpacket_payload_voice_bytes_t *voice_bytes, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid) {
	dmrpacket_payload_voice_bits_t voice_bits;

	if (repeater == NULL || voice_bytes == NULL)
		return;

	base_bytestobits(voice_bytes->bytes, sizeof(dmrpacket_payload_voice_bytes_t), voice_bits.raw.bits, sizeof(dmrpacket_payload_voice_bits_t));

	switch (repeater->slot[ts].ipsc_tx_voice_frame_num) {
		case 0:
			repeaters_send_ipsc_sync(repeater, ts, calltype, dstid, srcid);
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_A, calltype, dstid, srcid,
				ipscpacket_construct_payload_voice_frame(IPSCPACKET_SLOT_TYPE_VOICE_DATA_A, &voice_bits, &repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage))), 0);
			break;
		case 1:
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_B, calltype, dstid, srcid,
				ipscpacket_construct_payload_voice_frame(IPSCPACKET_SLOT_TYPE_VOICE_DATA_B, &voice_bits, &repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage))), 0);
			break;
		case 2:
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_C, calltype, dstid, srcid,
				ipscpacket_construct_payload_voice_frame(IPSCPACKET_SLOT_TYPE_VOICE_DATA_C, &voice_bits, &repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage))), 0);
			break;
		case 3:
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_D, calltype, dstid, srcid,
				ipscpacket_construct_payload_voice_frame(IPSCPACKET_SLOT_TYPE_VOICE_DATA_D, &voice_bits, &repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage))), 0);
			break;
		case 4:
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_E, calltype, dstid, srcid,
				ipscpacket_construct_payload_voice_frame(IPSCPACKET_SLOT_TYPE_VOICE_DATA_E, &voice_bits, &repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage))), 0);
			break;
		case 5:
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_F, calltype, dstid, srcid,
				ipscpacket_construct_payload_voice_frame(IPSCPACKET_SLOT_TYPE_VOICE_DATA_F, &voice_bits, &repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage))), 0);
			break;
		default:
			break;
	}
	repeater->slot[ts].ipsc_tx_voice_frame_num++;
	if (repeater->slot[ts].ipsc_tx_voice_frame_num > 5)
		repeater->slot[ts].ipsc_tx_voice_frame_num = 0;
}

void repeaters_end_voice_call(repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid) {
	if (repeater == NULL)
		return;

	repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_TERMINATOR_WITH_LC, calltype, dstid, srcid, ipscpacket_construct_payload_terminator_with_lc(calltype, dstid, srcid))), 0);
	vbptc_16_11_free(&repeater->slot[ts].ipsc_tx_emb_sig_lc_vbptc_storage);
}

void repeaters_play_ambe_file(char *ambe_file_name, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid) {
	FILE *f;
	dmrpacket_payload_voice_bytes_t voice_bytes;

	if (ambe_file_name == NULL || repeater == NULL)
		return;

	f = fopen(ambe_file_name, "r");
	if (!f) {
		console_log("repeaters [%s] error: can't open %s for playing\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ambe_file_name);
		return;
	}

	console_log("repeaters [%s]: playing %s\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ambe_file_name);

	repeaters_start_voice_call(repeater, ts, calltype, dstid, srcid);
	while (!feof(f)) {
		if (fread(voice_bytes.bytes, 1, sizeof(dmrpacket_payload_voice_bytes_t), f) == sizeof(dmrpacket_payload_voice_bytes_t))
			repeaters_play_ambe_data(&voice_bytes, repeater, ts, calltype, dstid, srcid);
	}
	repeaters_end_voice_call(repeater, ts, calltype, dstid, srcid);
	fclose(f);

}

void repeaters_free_echo_buf(repeater_t *repeater, dmr_timeslot_t ts) {
	repeater_echo_buf_t *next_echo_buf_entry;

	while (repeater->slot[ts].echo_buf_first_entry != NULL) {
		next_echo_buf_entry = repeater->slot[ts].echo_buf_first_entry->next;
		free(repeater->slot[ts].echo_buf_first_entry);
		repeater->slot[ts].echo_buf_first_entry = next_echo_buf_entry;
	}
	repeater->slot[ts].echo_buf_last_entry = NULL;
}

void repeaters_play_and_free_echo_buf(repeater_t *repeater, dmr_timeslot_t ts) {
	repeater_echo_buf_t *echo_buf;
	repeater_echo_buf_t *next_echo_buf;

	if (repeater == NULL || repeater->slot[ts].echo_buf_first_entry == NULL)
		return;

	// We need to use local variables here as processing outgoing IPSC packets could overwrite them.
	echo_buf = repeater->slot[ts].echo_buf_first_entry;
	repeater->slot[ts].echo_buf_first_entry = NULL;
	repeater->slot[ts].echo_buf_last_entry = NULL;

	repeaters_start_voice_call(repeater, ts, DMR_CALL_TYPE_GROUP, DMRSHARK_DEFAULT_DMR_ID, DMRSHARK_DEFAULT_DMR_ID);
	while (echo_buf != NULL) {
		repeaters_play_ambe_data(&echo_buf->voice_bytes, repeater, ts, DMR_CALL_TYPE_GROUP, DMRSHARK_DEFAULT_DMR_ID, DMRSHARK_DEFAULT_DMR_ID);

		next_echo_buf = echo_buf->next;
		free(echo_buf);
		echo_buf = next_echo_buf;
	}
	repeaters_end_voice_call(repeater, ts, DMR_CALL_TYPE_GROUP, DMRSHARK_DEFAULT_DMR_ID, DMRSHARK_DEFAULT_DMR_ID);
}

void repeaters_store_voice_frame_to_echo_buf(repeater_t *repeater, ipscpacket_t *ipscpacket) {
	repeater_echo_buf_t *new_echo_buf_entry;
	dmrpacket_payload_voice_bits_t *voice_bits;

	if (repeater == NULL || ipscpacket == NULL)
		return;

	new_echo_buf_entry = (repeater_echo_buf_t *)malloc(sizeof(repeater_echo_buf_t));
	if (new_echo_buf_entry == NULL) {
		console_log("  error: can't allocate memory for new echo buffer entry\n");
		return;
	}

	console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: storing ts%u voice frame to echo buf\n", repeaters_get_display_string_for_ip(&repeater->ipaddr),
		ipscpacket->timeslot);

	voice_bits = dmrpacket_extract_voice_bits(&ipscpacket->payload_bits);
	base_bitstobytes(voice_bits->raw.bits, sizeof(dmrpacket_payload_voice_bits_t), new_echo_buf_entry->voice_bytes.bytes, sizeof(dmrpacket_payload_voice_bits_t)/8);
	new_echo_buf_entry->next = NULL;

	if (repeater->slot[ipscpacket->timeslot-1].echo_buf_last_entry == NULL) {
		repeater->slot[ipscpacket->timeslot-1].echo_buf_last_entry = repeater->slot[ipscpacket->timeslot-1].echo_buf_first_entry = new_echo_buf_entry;
	} else {
		// Putting the new entry to the end of the linked list.
		repeater->slot[ipscpacket->timeslot-1].echo_buf_last_entry->next = new_echo_buf_entry;
		repeater->slot[ipscpacket->timeslot-1].echo_buf_last_entry = new_echo_buf_entry;
	}
}

void repeaters_send_data_packet(repeater_t *repeater, dmr_timeslot_t ts, flag_t *selective_blocks, uint8_t selective_blocks_size, dmrpacket_data_packet_t *data_packet) {
	uint16_t i;
	dmrpacket_csbk_t csbk;
	ipscpacket_payload_t *ipscpacket_payload;
	dmrpacket_data_block_t *data_blocks;
	uint8_t data_blocks_needed = 0;

	if (repeater == NULL || data_packet == NULL)
		return;

	repeater->slot[ts].ipsc_tx_seqnum = 0;

	console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA "repeaters [%s]: sending %s sap: %s dpf: %s to %u on ts%u\n", repeaters_get_display_string_for_ip(&repeater->ipaddr),
		dmr_get_readable_call_type(data_packet->header.common.dst_is_a_group ? DMR_CALL_TYPE_GROUP : DMR_CALL_TYPE_PRIVATE),
		dmrpacket_data_header_get_readable_sap(data_packet->header.common.service_access_point),
		dmrpacket_data_header_get_readable_dpf(data_packet->header.common.data_packet_format),
		data_packet->header.common.dst_llid, ts+1);

	// If which blocks to send is set. Used for selective ACK reply.
	if (selective_blocks != NULL && selective_blocks_size > 0) {
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA "  sending only selective blocks: ");
		for (i = 0; i < selective_blocks_size; i++) {
			if (selective_blocks[i]) {
				console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA "%u ", i);
				data_blocks_needed++;
			}
		}
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA "\n");
	} else {
		data_blocks_needed = data_packet->fragment.data_blocks_needed;
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA "  sending full message (all %u blocks)\n", data_blocks_needed);
	}

	data_blocks = dmrpacket_data_construct_data_blocks(&data_packet->fragment, data_packet->data_type, data_packet->header.common.response_requested);
	if (data_blocks == NULL)
		return;

	// Filling up missing fields from the header.
	switch (data_packet->header.common.data_packet_format) {
		case DMRPACKET_DATA_HEADER_DPF_UDT:
			data_packet->header.udt.appended_blocks = data_blocks_needed;
			break;
		case DMRPACKET_DATA_HEADER_DPF_RESPONSE:
			data_packet->header.response.blocks_to_follow = data_blocks_needed;
			break;
		case DMRPACKET_DATA_HEADER_DPF_UNCONFIRMED_DATA:
			data_packet->header.unconfirmed_data.pad_octet_count = data_blocks_needed*dmrpacket_data_get_block_size(data_packet->data_type, data_packet->header.common.response_requested)-data_packet->fragment.bytes_stored-4;
			data_packet->header.unconfirmed_data.blocks_to_follow = data_blocks_needed;
			data_packet->header.unconfirmed_data.full_message = (selective_blocks == NULL && selective_blocks_size == 0);
			break;
		case DMRPACKET_DATA_HEADER_DPF_CONFIRMED_DATA:
			data_packet->header.confirmed_data.pad_octet_count = data_blocks_needed*dmrpacket_data_get_block_size(data_packet->data_type, data_packet->header.common.response_requested)-data_packet->fragment.bytes_stored-4;
			data_packet->header.confirmed_data.blocks_to_follow = data_blocks_needed;
			data_packet->header.confirmed_data.full_message = (selective_blocks == NULL && selective_blocks_size == 0);
			break;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_DEFINED:
			data_packet->header.short_data_defined.appended_blocks = data_blocks_needed;
			data_packet->header.short_data_defined.full_message = (selective_blocks == NULL && selective_blocks_size == 0);
			break;
		case DMRPACKET_DATA_HEADER_DPF_SHORT_DATA_RAW:
			data_packet->header.short_data_raw.appended_blocks = data_blocks_needed;
			data_packet->header.short_data_raw.full_message = (selective_blocks == NULL && selective_blocks_size == 0);
			break;
		default:
			break;
	}

	// Constructing the CSBK preamble.
	csbk.last_block = 1;
	csbk.csbko = DMRPACKET_CSBKO_PREAMBLE;
	csbk.data.preamble.data_follows = 1;
	csbk.data.preamble.dst_is_group = data_packet->header.common.dst_is_a_group;
	csbk.data.preamble.csbk_blocks_to_follow = data_packet->number_of_csbk_preambles_to_send+data_blocks_needed+1; // +1 - header
	csbk.dst_id = data_packet->header.common.dst_llid;
	csbk.src_id = data_packet->header.common.src_llid;

	// Sending CSBK preambles.
	for (i = 0; i < data_packet->number_of_csbk_preambles_to_send; i++) {
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  sending csbk #%u/%u\n", i, data_packet->number_of_csbk_preambles_to_send);
		csbk.data.preamble.csbk_blocks_to_follow--;
		ipscpacket_payload = ipscpacket_construct_payload_csbk(&csbk);
		repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_CSBK,
			(data_packet->header.common.dst_is_a_group ? DMR_CALL_TYPE_GROUP : DMR_CALL_TYPE_PRIVATE), data_packet->header.common.dst_llid, data_packet->header.common.src_llid, ipscpacket_payload)), 0);
	}

	repeaters_send_ipsc_sync(repeater, ts, (data_packet->header.common.dst_is_a_group ? DMR_CALL_TYPE_GROUP : DMR_CALL_TYPE_PRIVATE), data_packet->header.common.dst_llid, data_packet->header.common.src_llid);

	// Sending data header.
	console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  sending data header\n");
	ipscpacket_payload = ipscpacket_construct_payload_data_header(&data_packet->header);
	repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts, IPSCPACKET_SLOT_TYPE_DATA_HEADER,
		(data_packet->header.common.dst_is_a_group ? DMR_CALL_TYPE_GROUP : DMR_CALL_TYPE_PRIVATE), data_packet->header.common.dst_llid, data_packet->header.common.src_llid, ipscpacket_payload)), 0);

	// Sending data blocks.
	for (i = 0; i < data_packet->fragment.data_blocks_needed; i++) { // Note: iterating through all blocks.
		// Sending this block if no selective blocks given, or they are given and this block is in the list
		// of blocks need to be sent.
		if (selective_blocks == NULL || (selective_blocks != NULL && i < selective_blocks_size && selective_blocks[i])) {
			console_log(LOGLEVEL_REPEATERS LOGLEVEL_DMRDATA LOGLEVEL_DEBUG "  sending block #%u\n", i);
			switch (data_packet->data_type) {
				default:
				case DMRPACKET_DATA_TYPE_RATE_34_DATA: ipscpacket_payload = ipscpacket_construct_payload_data_block_rate_34(&data_blocks[i]); break;
				case DMRPACKET_DATA_TYPE_RATE_12_DATA: ipscpacket_payload = ipscpacket_construct_payload_data_block_rate_12(&data_blocks[i]); break;
			}
			repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(repeater->slot[ts].ipsc_tx_seqnum++, ts,
				ipscpacket_get_slot_type_for_data_type(data_packet->data_type), (data_packet->header.common.dst_is_a_group ? DMR_CALL_TYPE_GROUP : DMR_CALL_TYPE_PRIVATE), data_packet->header.common.dst_llid, data_packet->header.common.src_llid,
				ipscpacket_payload)), 0);
		}
	}

	free(data_blocks);
	daemon_poll_setmaxtimeout(0);
}

void repeaters_send_broadcast_data_packet(dmrpacket_data_packet_t *data_packet) {
	repeater_t *repeater = repeaters;

	while (repeater) {
		repeaters_send_data_packet(repeater, 0, NULL, 0, data_packet);
		repeaters_send_data_packet(repeater, 1, NULL, 0, data_packet);

		repeater = repeater->next;
	}
}

flag_t repeaters_is_there_a_call_not_for_us_or_by_us(repeater_t *repeater, dmr_timeslot_t ts) {
	if (repeater == NULL)
		return 0;

	if (repeater->slot[ts].state != REPEATER_SLOT_STATE_IDLE && repeater->slot[ts].dst_id != DMRSHARK_DEFAULT_DMR_ID &&
		repeater->slot[ts].src_id != DMRSHARK_DEFAULT_DMR_ID)
			return 1;
	return 0;
}

flag_t repeaters_is_call_running_on_other_repeater(repeater_t *current_repeater, dmr_timeslot_t ts, dmr_id_t srcid) {
	repeater_t *repeater = repeaters;

	while (repeater) {
		if (repeater != current_repeater && repeater->slot[ts].state != REPEATER_SLOT_STATE_IDLE && repeater->slot[ts].src_id == srcid)
				return 1;

		repeater = repeater->next;
	}
	return 0;
}

static void repeaters_process_ipsc_tx_rawpacketbuf(repeater_t *repeater) {
	struct timeval currtime = {0,};
	struct timeval difftime = {0,};
	ipscrawpacketbuf_t *ipsc_tx_rawpacketbuf_entry_to_send;
	dmr_timeslot_t ts;
	flag_t nowait = 0;

	if (repeater == NULL)
		return;

	if (repeater->slot[0].ipsc_tx_rawpacketbuf != NULL || repeater->slot[1].ipsc_tx_rawpacketbuf != NULL)
		daemon_poll_setmaxtimeout(0);

	if (repeater->last_ipsc_packet_sent_from_slot == 1)
		ts = 0;
	else
		ts = 1;

	gettimeofday(&currtime, NULL);
	timersub(&currtime, &repeater->last_ipsc_packet_sent_time, &difftime);
	if (difftime.tv_sec*1000+difftime.tv_usec/1000 < IPSC_PACKET_SEND_INTERVAL_IN_MS)
		return;

	if (repeater->slot[ts].ipsc_tx_rawpacketbuf != NULL && repeater->slot[ts].ipsc_tx_rawpacketbuf->nowait)
		nowait = 1;

	if (nowait == 0)
		repeater->last_ipsc_packet_sent_from_slot = ts;

	if (repeater->slot[ts].ipsc_tx_rawpacketbuf == NULL) {
		gettimeofday(&repeater->last_ipsc_packet_sent_time, NULL);
		return;
	}

	if (repeaters_is_there_a_call_not_for_us_or_by_us(repeater, ts))
		return;

	ipsc_tx_rawpacketbuf_entry_to_send = repeater->slot[ts].ipsc_tx_rawpacketbuf;

	console_log(LOGLEVEL_REPEATERS "repeaters [%s]: sending ipsc packet from tx buffer\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
	if (repeaters_send_raw_ipsc_packet(repeater, &ipsc_tx_rawpacketbuf_entry_to_send->ipscpacket_raw)) {
		// Sending the packet to our IPSC processing loop too.
		//ipsc_processpacket(&ipsc_tx_rawpacketbuf_entry_to_send->ipscpacket_raw, sizeof(ipscpacket_raw_t));

		// Shifting the buffer.
		repeater->slot[ts].ipsc_tx_rawpacketbuf = repeater->slot[ts].ipsc_tx_rawpacketbuf->next;
		free(ipsc_tx_rawpacketbuf_entry_to_send);
	}
	if (nowait == 0)
		gettimeofday(&repeater->last_ipsc_packet_sent_time, NULL);
	if (repeater->slot[ts].ipsc_tx_rawpacketbuf == NULL)
		console_log(LOGLEVEL_REPEATERS "repeaters [%s]: tx packet buffer got empty\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
}

void repeaters_process(void) {
	repeater_t *repeater = repeaters;
	repeater_t *repeater_to_remove;
	struct timeval currtime = {0,};
	struct timeval difftime = {0,};

	while (repeater) {
		if (repeater->slot[0].state != REPEATER_SLOT_STATE_IDLE || repeater->slot[1].state != REPEATER_SLOT_STATE_IDLE)
			daemon_poll_setmaxtimeout(IPSC_PACKET_SEND_INTERVAL_IN_MS);

		repeaters_process_ipsc_tx_rawpacketbuf(repeater);

		if (!comm_is_masteripaddr(&repeater->ipaddr) && time(NULL)-repeater->last_active_time > config_get_repeaterinactivetimeoutinsec()) {
			console_log(LOGLEVEL_REPEATERS "repeaters [%s]: timed out\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			repeater_to_remove = repeater;
			repeater = repeater->next;
			repeaters_remove(repeater_to_remove);
			continue;
		}

		if (!repeater->snmpignored && config_get_repeaterinfoupdateinsec() > 0 && time(NULL)-repeater->last_repeaterinfo_request_time > config_get_repeaterinfoupdateinsec()) {
			console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: sending snmp info update request\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			snmp_start_read_repeaterinfo(comm_get_ip_str(&repeater->ipaddr));
			repeater->last_repeaterinfo_request_time = time(NULL);
		}

		if (repeater->slot[0].state == REPEATER_SLOT_STATE_VOICE_CALL_RUNNING && time(NULL)-repeater->slot[0].last_call_or_data_packet_received_at > config_get_calltimeoutinsec())
			dmr_handle_voice_call_timeout(repeater, 0);

		if (repeater->slot[1].state == REPEATER_SLOT_STATE_VOICE_CALL_RUNNING && time(NULL)-repeater->slot[1].last_call_or_data_packet_received_at > config_get_calltimeoutinsec())
			dmr_handle_voice_call_timeout(repeater, 1);

		if (repeater->auto_rssi_update_enabled_at > 0 && repeater->auto_rssi_update_enabled_at <= time(NULL)) {
			if (config_get_rssiupdateduringcallinmsec() > 0) {
				gettimeofday(&currtime, NULL);
				timersub(&currtime, &repeater->last_rssi_request_time, &difftime);
				if (difftime.tv_sec*1000+difftime.tv_usec/1000 > config_get_rssiupdateduringcallinmsec()) {
					snmp_start_read_repeaterstatus(comm_get_ip_str(&repeater->ipaddr));
					repeater->last_rssi_request_time = currtime;
				}
			}
		}

		if (repeater->slot[0].state == REPEATER_SLOT_STATE_DATA_CALL_RUNNING && time(NULL)-repeater->slot[0].last_call_or_data_packet_received_at > config_get_datatimeoutinsec())
			dmr_handle_data_call_timeout(repeater, 0);

		if (repeater->slot[1].state == REPEATER_SLOT_STATE_DATA_CALL_RUNNING && time(NULL)-repeater->slot[1].last_call_or_data_packet_received_at > config_get_datatimeoutinsec())
			dmr_handle_data_call_timeout(repeater, 1);

		repeater = repeater->next;
	}
}

void repeaters_deinit(void) {
	console_log("repeaters: deinit\n");

	while (repeaters != NULL)
		repeaters_remove(repeaters);
}
