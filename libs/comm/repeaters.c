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

#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>

static repeater_t *repeaters = NULL;

static char *repeaters_get_readable_slot_state(repeater_slot_state_t state) {
	switch (state) {
		case REPEATER_SLOT_STATE_IDLE: return "idle";
		case REPEATER_SLOT_STATE_CALL_RUNNING: return "call running";
		case REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING: return "data receive running";
		default: return "unknown";
	}
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

	// Freeing up IPSC packet buffers for both slots.
	while (repeater->slot[0].ipscrawpacketbuf) {
		pb_nextentry = repeater->slot[0].ipscrawpacketbuf->next;
		free(repeater->slot[0].ipscrawpacketbuf);
		repeater->slot[0].ipscrawpacketbuf = pb_nextentry;
	}
	while (repeater->slot[1].ipscrawpacketbuf) {
		pb_nextentry = repeater->slot[1].ipscrawpacketbuf->next;
		free(repeater->slot[1].ipscrawpacketbuf);
		repeater->slot[1].ipscrawpacketbuf = pb_nextentry;
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

	if (repeaters == NULL) {
		console_log("no repeaters found yet\n");
		return;
	}

	console_log("repeaters:\n");
	console_log("      nr              ip     id  callsign  act  lstinf         type        fwver    dlfreq    ulfreq snmp ts1/ts2 streams\n");
	while (repeater) {
		console_log("  #%4u: %15s %6u %9s %4u  %6u %12s %12s %9u %9u    %u %s / %s\n",
			i++,
			comm_get_ip_str(&repeater->ipaddr),
			repeater->id,
			repeater->callsign,
			time(NULL)-repeater->last_active_time,
			time(NULL)-repeater->last_repeaterinfo_request_time,
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
		repeater->slot[0].state != REPEATER_SLOT_STATE_CALL_RUNNING &&
		repeater->slot[1].state != REPEATER_SLOT_STATE_CALL_RUNNING) {
			console_log(LOGLEVEL_REPEATERS "repeaters [%s]: stopping auto repeater status update\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
			repeater->auto_rssi_update_enabled_at = 0;
	}
}

static void repeaters_add_to_ipsc_packet_buffer(repeater_t *repeater, dmr_timeslot_t ts, ipscpacket_raw_t *ipscpacket_raw) {
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

	pbentry = repeater->slot[ts].ipscrawpacketbuf;
	if (pbentry == NULL)
		repeater->slot[ts].ipscrawpacketbuf = newpbentry;
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
	if (sendto(sockfd, (uint8_t *)ipscpacket_raw, sizeof(ipscpacket_raw_t), MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) != sizeof(ipscpacket_raw_t)) {
		console_log(LOGLEVEL_REPEATERS LOGLEVEL_DEBUG "repeaters [%s]: can't send udp packet: %s\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), strerror(errno));
		close(sockfd);
		return 0;
	}
	close(sockfd);
	return 1;
}

void repeaters_play_ambe_file(char *ambe_file_name, repeater_t *repeater, dmr_timeslot_t ts, dmr_call_type_t calltype, dmr_id_t dstid, dmr_id_t srcid) {
	FILE *f;
	uint8_t voice_bytes[sizeof(dmrpacket_payload_voice_bits_t)/8];
	dmrpacket_payload_voice_bits_t voice_bits;
	uint8_t i;
	uint8_t seqnum = 0;
	uint8_t voice_frame_num = 2;
	size_t bytes_read;
	dmrpacket_emb_signalling_lc_bits_t *emb_signalling_lc_bits;
	vbptc_16_11_t emb_sig_lc_vbptc_storage;

	if (ambe_file_name == NULL || repeater == NULL)
		return;

	if (!vbptc_16_11_init(&emb_sig_lc_vbptc_storage, 8)) {
		console_log("repeaters [%s] error: can't allocate memory for vbptc encoding\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
		return;
	}

	f = fopen(ambe_file_name, "r");
	if (!f) {
		console_log("repeaters [%s] error: can't open %s for playing\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ambe_file_name);
		return;
	}

	console_log("repeaters [%s]: playing %s\n", repeaters_get_display_string_for_ip(&repeater->ipaddr), ambe_file_name);

	emb_signalling_lc_bits = dmrpacket_emb_signalling_lc_interleave(dmrpacket_lc_construct_emb_signalling_lc(calltype, dstid, srcid));
	vbptc_16_11_construct(&emb_sig_lc_vbptc_storage, emb_signalling_lc_bits->bits, sizeof(dmrpacket_emb_signalling_lc_bits_t));

	for (i = 0; i < 4; i++)
		repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_LC_HEADER, calltype, dstid, srcid, ipscpacket_construct_payload_voice_lc_header(calltype, dstid, srcid))));

	while (!feof(f)) {
		bytes_read = fread(voice_bytes, 1, sizeof(voice_bytes), f);
		base_bytestobits(voice_bytes, bytes_read, voice_bits.raw.bits, min(bytes_read*8, sizeof(dmrpacket_payload_voice_bits_t)));

		switch (voice_frame_num) {
			case 0:
				repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_A, calltype, dstid, srcid,
					ipscpacket_construct_payload_voice_frame(calltype, dstid, srcid, IPSCPACKET_SLOT_TYPE_VOICE_DATA_A, &voice_bits, &emb_sig_lc_vbptc_storage))));
				break;
			case 1:
				repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_B, calltype, dstid, srcid,
					ipscpacket_construct_payload_voice_frame(calltype, dstid, srcid, IPSCPACKET_SLOT_TYPE_VOICE_DATA_B, &voice_bits, &emb_sig_lc_vbptc_storage))));
				break;
			case 2:
				repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_C, calltype, dstid, srcid,
					ipscpacket_construct_payload_voice_frame(calltype, dstid, srcid, IPSCPACKET_SLOT_TYPE_VOICE_DATA_C, &voice_bits, &emb_sig_lc_vbptc_storage))));
				break;
			case 3:
				repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_D, calltype, dstid, srcid,
					ipscpacket_construct_payload_voice_frame(calltype, dstid, srcid, IPSCPACKET_SLOT_TYPE_VOICE_DATA_D, &voice_bits, &emb_sig_lc_vbptc_storage))));
				break;
			case 4:
				repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_E, calltype, dstid, srcid,
					ipscpacket_construct_payload_voice_frame(calltype, dstid, srcid, IPSCPACKET_SLOT_TYPE_VOICE_DATA_E, &voice_bits, &emb_sig_lc_vbptc_storage))));
				break;
			case 5:
				repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_VOICE_DATA_F, calltype, dstid, srcid,
					ipscpacket_construct_payload_voice_frame(calltype, dstid, srcid, IPSCPACKET_SLOT_TYPE_VOICE_DATA_F, &voice_bits, &emb_sig_lc_vbptc_storage))));
				break;
			default:
				break;
		}
		voice_frame_num++;
		if (voice_frame_num > 5)
			voice_frame_num = 0;
	}
	repeaters_add_to_ipsc_packet_buffer(repeater, ts, ipscpacket_construct_raw_packet(&repeater->ipaddr, ipscpacket_construct_raw_payload(seqnum++, ts, IPSCPACKET_SLOT_TYPE_TERMINATOR_WITH_LC, calltype, dstid, srcid, ipscpacket_construct_payload_terminator_with_lc(calltype, dstid, srcid))));
	fclose(f);
	vbptc_16_11_free(&emb_sig_lc_vbptc_storage);
}

static void repeaters_process_ipscrawpacketbuf(repeater_t *repeater, dmr_timeslot_t ts) {
	struct timeval currtime = {0,};
	struct timeval difftime = {0,};
	ipscrawpacketbuf_t *ipscrawpacketbuf_entry_to_send;

	if (repeater == NULL || ts < 0 || ts > 1 || repeater->slot[ts].ipscrawpacketbuf == NULL)
		return;

	gettimeofday(&currtime, NULL);
	timersub(&currtime, &repeater->slot[ts].last_ipsc_packet_sent_time, &difftime);
	if (difftime.tv_sec*1000+difftime.tv_usec/1000 >= 50) { // Sending a frame every x ms.
		console_log(LOGLEVEL_REPEATERS "repeaters [%s]: sending ipsc packet from tx buffer\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
		ipscrawpacketbuf_entry_to_send = repeater->slot[ts].ipscrawpacketbuf;
		if (repeaters_send_raw_ipsc_packet(repeater, &ipscrawpacketbuf_entry_to_send->ipscpacket_raw)) {
			// Sending the packet to our IPSC processing loop too.
			//ipsc_processpacket(&ipscrawpacketbuf_entry_to_send->ipscpacket_raw, sizeof(ipscpacket_raw_t));

			// Shifting the buffer.
			repeater->slot[ts].ipscrawpacketbuf = repeater->slot[ts].ipscrawpacketbuf->next;
			free(ipscrawpacketbuf_entry_to_send);
			gettimeofday(&repeater->slot[ts].last_ipsc_packet_sent_time, NULL);
		}
		if (repeater->slot[ts].ipscrawpacketbuf == NULL)
			console_log(LOGLEVEL_REPEATERS "repeaters [%s]: tx packet buffer got empty\n", repeaters_get_display_string_for_ip(&repeater->ipaddr));
	}
	if (repeater->slot[ts].ipscrawpacketbuf != NULL)
		daemon_poll_setmaxtimeout(0);
}

void repeaters_process(void) {
	repeater_t *repeater = repeaters;
	repeater_t *repeater_to_remove;
	struct timeval currtime = {0,};
	struct timeval difftime = {0,};

	while (repeater) {
		repeaters_process_ipscrawpacketbuf(repeater, 0);
		repeaters_process_ipscrawpacketbuf(repeater, 1);

		if (time(NULL)-repeater->last_active_time > config_get_repeaterinactivetimeoutinsec()) {
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

		if (repeater->slot[0].state == REPEATER_SLOT_STATE_CALL_RUNNING && time(NULL)-repeater->slot[0].last_packet_received_at > config_get_calltimeoutinsec())
			dmr_handle_voicecall_timeout(repeater, 0);

		if (repeater->slot[1].state == REPEATER_SLOT_STATE_CALL_RUNNING && time(NULL)-repeater->slot[1].last_packet_received_at > config_get_calltimeoutinsec())
			dmr_handle_voicecall_timeout(repeater, 1);

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

		if (repeater->slot[0].state == REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING && time(NULL)-repeater->slot[0].data_header_received_at > config_get_datatimeoutinsec())
			dmr_handle_data_timeout(repeater, 0);

		if (repeater->slot[1].state == REPEATER_SLOT_STATE_DATA_RECEIVE_RUNNING && time(NULL)-repeater->slot[1].data_header_received_at > config_get_datatimeoutinsec())
			dmr_handle_data_timeout(repeater, 1);

		repeater = repeater->next;
	}
}

void repeaters_deinit(void) {
	console_log("repeaters: deinit\n");

	while (repeaters != NULL)
		repeaters_remove(repeaters);
}
