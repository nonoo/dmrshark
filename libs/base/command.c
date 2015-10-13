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

#include "command.h"
#include "log.h"
#include "types.h"
#include "base.h"
#include "smstxbuf.h"
#include "smsrtbuf.h"
#include "dmr-data.h"
#include "data-packet-txbuf.h"

#include <libs/daemon/console.h>
#include <libs/config/config.h>
#include <libs/comm/snmp.h>
#include <libs/comm/repeaters.h>
#include <libs/remotedb/remotedb.h>
#include <libs/comm/comm.h>
#include <libs/voicestreams/voicestreams.h>
#include <libs/comm/httpserver.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

void command_process(char *input_buffer) {
	extern base_flags_t base_flags;
	loglevel_t loglevel;
	union {
		struct {
			voicestream_t *voicestream;
		} stream;
		struct {
			char *filename;
			char *host;
			repeater_t *repeater;
			dmr_timeslot_t ts;
			dmr_call_type_t calltype;
			dmr_id_t dstid;
		} play;
		struct {
			char *host;
			repeater_t *repeater;
			dmr_timeslot_t ts;
			dmr_call_type_t calltype;
			dmr_id_t dstid;
		} smsr;
		struct {
			dmr_timeslot_t ts;
			dmr_call_type_t calltype;
			dmr_id_t dstid;
		} sms;
	} d;
	char *endptr = NULL;
	char *tok = strtok(input_buffer, " ");

	if (tok == NULL)
		return;

	if (strcmp(tok, "help") == 0 || strcmp(tok, "h") == 0) {
		console_log("  ver                                                            - version\n");
		console_log("  log (loglevel)                                                 - get/set loglevel\n");
		console_log("  exit                                                           - exits the application\n");
		console_log("  repstat [host]                                                 - reads repeater status from host using snmp\n");
		console_log("  repinfo [host]                                                 - reads repeater info from host using snmp\n");
		console_log("  replist                                                        - list repeaters\n");
		console_log("  streamlist                                                     - list voice streams\n");
		console_log("  remotedbmaintain                                               - start db maintenance\n");
		console_log("  remotedbreplistmaintain                                        - start repeater list db maintenance\n");
		console_log("  loadpcap [pcapfile]                                            - reads and processes packets from pcap file\n");
		console_log("  httplist                                                       - list http clients\n");
		console_log("  streamenable [name]                                            - enable stream\n");
		console_log("  streamdisable [name]                                           - disable stream\n");
		console_log("  streamrecstart [name]                                          - enable saving raw AMBE data to file\n");
		console_log("  streamrecstop [name]                                           - disable saving raw AMBE data to file\n");
		console_log("  streamdecrecstart [name]                                       - enable saving raw decoded data to file\n");
		console_log("  streamdecrecstop [name]                                        - disable saving raw decoded data to file\n");
		console_log("  streammp3recstart [name]                                       - enable saving mp3 data to file\n");
		console_log("  streammp3recstop [name]                                        - disable saving mp3 data to file\n");
		console_log("  play [file] [host/rptr callsign] [ts] [calltype (p/g)] [dstid] - play raw AMBE file to given repeater host\n");
		console_log("  smslist                                                        - print the contents of the sms tx buffer\n");
		console_log("  smsrtlist                                                      - print the contents of the sms retransmit buffer\n");
		console_log("  dptlist                                                        - print the contents of the data packet tx buffer\n");
		console_log("  smsr [host/rptr callsign] [ts] [calltype (p/g)] [dstid] [msg]  - send sms to given repeater host\n");
		console_log("  smsm [host/rptr callsign] [ts] [calltype (p/g)] [dstid] [msg]  - send motorola format sms to given repeater host\n");
		console_log("  sms [calltype (p/g)] [dstid] [msg]                             - send sms\n");
		return;
	}

	if (strcmp(tok, "ver") == 0) {
		log_ver();
		return;
	}

	if (strcmp(tok, "log") == 0) {
		loglevel = console_get_loglevel();
		tok = strtok(NULL, " ");
		if (tok != NULL) {
			if (strcmp(tok, "off") == 0 || tok[0] == '0') {
				if (loglevel.raw == 0)
					memset((void *)&loglevel.raw, 0xff, sizeof(loglevel.raw));
				else
					loglevel.raw = 0;
			} else if (strcmp(tok, "debug") == 0)
				loglevel.flags.debug = !loglevel.flags.debug;
			else if (strcmp(tok, "ipsc") == 0)
				loglevel.flags.ipsc = !loglevel.flags.ipsc;
			else if (strcmp(tok, "comm-ip") == 0)
				loglevel.flags.comm_ip = !loglevel.flags.comm_ip;
			else if (strcmp(tok, "dmr") == 0)
				loglevel.flags.dmr = !loglevel.flags.dmr;
			else if (strcmp(tok, "dmrlc") == 0)
				loglevel.flags.dmrlc = !loglevel.flags.dmrlc;
			else if (strcmp(tok, "dmrdata") == 0)
				loglevel.flags.dmrdata = !loglevel.flags.dmrdata;
			else if (strcmp(tok, "snmp") == 0)
				loglevel.flags.snmp = !loglevel.flags.snmp;
			else if (strcmp(tok, "repeaters") == 0)
				loglevel.flags.repeaters = !loglevel.flags.repeaters;
			else if (strcmp(tok, "heartbeat") == 0)
				loglevel.flags.heartbeat = !loglevel.flags.heartbeat;
			else if (strcmp(tok, "remotedb") == 0)
				loglevel.flags.remotedb = !loglevel.flags.remotedb;
			else if (strcmp(tok, "voicestreams") == 0)
				loglevel.flags.voicestreams = !loglevel.flags.voicestreams;
			else if (strcmp(tok, "coding") == 0)
				loglevel.flags.coding = !loglevel.flags.coding;
			else if (strcmp(tok, "httpserver") == 0)
				loglevel.flags.httpserver = !loglevel.flags.httpserver;

			config_set_loglevel(&loglevel);
			console_set_loglevel(&loglevel);
		}
		log_loglevel(&loglevel);
		return;
	}

	if (strcmp(tok, "exit") == 0) {
		base_flags.sigexit = 1;
		return;
	}

	if (strcmp(tok, "repstat") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		console_log("starting repeater status read request to %s...\n", tok);
		snmp_start_read_repeaterstatus(tok);
		return;
	}

	if (strcmp(tok, "repinfo") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		console_log("starting info read request to %s...\n", tok);
		snmp_start_read_repeaterinfo(tok);
		return;
	}

	if (strcmp(tok, "replist") == 0) {
		repeaters_list();
		return;
	}

	if (strcmp(tok, "streamlist") == 0) {
		voicestreams_printlist();
		return;
	}

	if (strcmp(tok, "remotedbmaintain") == 0) {
		remotedb_maintain();
		return;
	}

	if (strcmp(tok, "remotedbreplistmaintain") == 0) {
		remotedb_maintain_repeaterlist();
		return;
	}

	if (strcmp(tok, "loadpcap") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		comm_pcapfile_open(tok);
		return;
	}

	if (strcmp(tok, "httplist") == 0) {
		httpserver_print_client_list();
		return;
	}

	if (strcmp(tok, "streamenable") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->enabled = 1;
		console_log("voicestream [%s]: enabled\n", tok);
		return;
	}

	if (strcmp(tok, "streamdisable") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->enabled = 0;
		console_log("voicestream [%s]: disabled\n", tok);
		return;
	}

	if (strcmp(tok, "streamrecstart") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->savetorawambefile = 1;
		console_log("voicestream [%s]: saving to raw ambe file enabled\n", tok);
		return;
	}

	if (strcmp(tok, "streamrecstop") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->savetorawambefile = 0;
		console_log("voicestream [%s]: saving to raw file disabled\n", tok);
		return;
	}

	if (strcmp(tok, "streamdecrecstart") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->savedecodedtorawfile = 1;
		console_log("voicestream [%s]: saving decoded data to raw file enabled\n", tok);
		return;
	}

	if (strcmp(tok, "streamdecrecstop") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->savedecodedtorawfile = 0;
		console_log("voicestream [%s]: saving decoded data to raw file disabled\n", tok);
		return;
	}

	if (strcmp(tok, "streammp3recstart") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->savedecodedtomp3file = 1;
		console_log("voicestream [%s]: saving decoded data to mp3 file enabled\n", tok);
		return;
	}

	if (strcmp(tok, "streammp3recstop") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.stream.voicestream = voicestreams_get_stream_by_name(tok);
		if (d.stream.voicestream == NULL) {
			console_log("voicestream %s not found\n", tok);
			return;
		}
		d.stream.voicestream->savedecodedtomp3file = 0;
		console_log("voicestream [%s]: saving decoded data to mp3 file disabled\n", tok);
		return;
	}

	if (strcmp(tok, "play") == 0) {
		d.play.filename = strtok(NULL, " ");
		if (d.play.filename == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.play.host = strtok(NULL, " ");
		if (d.play.host == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.play.repeater = repeaters_findbyhost(d.play.host);
		if (d.play.repeater == NULL)
			d.play.repeater = repeaters_findbycallsign(d.play.host);
		if (d.play.repeater == NULL) {
			console_log(LOGLEVEL_IPSC "error: couldn't find repeater with host %s\n", d.play.host);
			return;
		}
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.play.ts = strtol(tok, &endptr, 10)-1;
		if (*endptr != 0 || errno != 0 || d.play.ts < 0 || d.play.ts > 1) {
			log_cmdinvalidparam();
			return;
		}
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.play.calltype = DMR_CALL_TYPE_PRIVATE;
		if (*tok == 'g')
			d.play.calltype = DMR_CALL_TYPE_GROUP;
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.play.dstid = strtol(tok, &endptr, 10);
		if (*endptr != 0 || errno != 0) {
			log_cmdinvalidparam();
			return;
		}

		console_log("playing %s to %s ts %u calltype %u dstid %u\n", d.play.filename, d.play.host, d.play.ts+1, dmr_get_readable_call_type(d.play.calltype), d.play.dstid);
		repeaters_play_ambe_file(d.play.filename, d.play.repeater, d.play.ts, d.play.calltype, d.play.dstid, DMRSHARK_DEFAULT_DMR_ID);
		return;
	}

	if (strcmp(tok, "smslist") == 0) {
		smstxbuf_print();
		return;
	}

	if (strcmp(tok, "smsrtlist") == 0) {
		smsrtbuf_print();
		return;
	}

	if (strcmp(tok, "dptlist") == 0) {
		data_packet_txbuf_print();
		return;
	}

	if (strcmp(tok, "smsr") == 0) {
		d.smsr.host = strtok(NULL, " ");
		if (d.smsr.host == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.smsr.repeater = repeaters_findbyhost(d.smsr.host);
		if (d.smsr.repeater == NULL)
			d.smsr.repeater = repeaters_findbycallsign(d.smsr.host);
		if (d.smsr.repeater == NULL) {
			console_log(LOGLEVEL_IPSC "error: couldn't find repeater with host %s\n", d.smsr.host);
			return;
		}
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.smsr.ts = strtol(tok, &endptr, 10)-1;
		if (*endptr != 0 || errno != 0 || d.smsr.ts < 0 || d.smsr.ts > 1) {
			log_cmdinvalidparam();
			return;
		}
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.smsr.calltype = DMR_CALL_TYPE_PRIVATE;
		if (*tok == 'g')
			d.smsr.calltype = DMR_CALL_TYPE_GROUP;
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.smsr.dstid = strtol(tok, &endptr, 10);
		if (*endptr != 0 || errno != 0) {
			log_cmdinvalidparam();
			return;
		}
		tok = strtok(NULL, "\n");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}

		dmr_data_send_sms(0, d.smsr.repeater, d.smsr.ts, d.smsr.calltype, d.smsr.dstid, DMRSHARK_DEFAULT_DMR_ID, tok);
		return;
	}

	if (strcmp(tok, "smsm") == 0) {
		d.smsr.host = strtok(NULL, " ");
		if (d.smsr.host == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.smsr.repeater = repeaters_findbyhost(d.smsr.host);
		if (d.smsr.repeater == NULL)
			d.smsr.repeater = repeaters_findbycallsign(d.smsr.host);
		if (d.smsr.repeater == NULL) {
			console_log(LOGLEVEL_IPSC "error: couldn't find repeater with host %s\n", d.smsr.host);
			return;
		}
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.smsr.ts = strtol(tok, &endptr, 10)-1;
		if (*endptr != 0 || errno != 0 || d.smsr.ts < 0 || d.smsr.ts > 1) {
			log_cmdinvalidparam();
			return;
		}
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.smsr.calltype = DMR_CALL_TYPE_PRIVATE;
		if (*tok == 'g')
			d.smsr.calltype = DMR_CALL_TYPE_GROUP;
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.smsr.dstid = strtol(tok, &endptr, 10);
		if (*endptr != 0 || errno != 0) {
			log_cmdinvalidparam();
			return;
		}
		tok = strtok(NULL, "\n");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}

		dmr_data_send_motorola_tms_sms(0, d.smsr.repeater, d.smsr.ts, d.smsr.calltype, d.smsr.dstid, DMRSHARK_DEFAULT_DMR_ID, tok);
		return;
	}

	if (strcmp(tok, "sms") == 0) {
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		d.sms.calltype = DMR_CALL_TYPE_PRIVATE;
		if (*tok == 'g')
			d.sms.calltype = DMR_CALL_TYPE_GROUP;
		tok = strtok(NULL, " ");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}
		errno = 0;
		d.sms.dstid = strtol(tok, &endptr, 10);
		if (*endptr != 0 || errno != 0) {
			log_cmdinvalidparam();
			return;
		}
		tok = strtok(NULL, "\n");
		if (tok == NULL) {
			log_cmdmissingparam();
			return;
		}

		smstxbuf_add(NULL, 0, d.sms.calltype, d.sms.dstid, DMRSHARK_DEFAULT_DMR_ID, 0, tok);
		smstxbuf_add(NULL, 0, d.sms.calltype, d.sms.dstid, DMRSHARK_DEFAULT_DMR_ID, 1, tok);
		return;
	}

	console_log("error: unknown command, see help, or go get a beer.\n");
}
