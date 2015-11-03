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

#include "aprs.h"

#include <libs/config/config.h>
#include <libs/config/config-aprsobjs.h>
#include <libs/remotedb/userdb.h>
#include <libs/base/smstxbuf.h>

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <sys/poll.h>
#include <stdio.h>

static pthread_t aprs_thread;

static pthread_mutex_t aprs_mutex_thread_should_stop = PTHREAD_MUTEX_INITIALIZER;
static flag_t aprs_thread_should_stop = 0;

static pthread_mutex_t aprs_mutex_wakeup = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t aprs_cond_wakeup;

static flag_t aprs_enabled = 0;
static flag_t aprs_loggedin = 0;
static int aprs_sockfd = -1;

typedef struct aprs_obj_st {
	char *callsign;
	double latitude;
	char latitude_ch;
	double longitude;
	char longitude_ch;
	char *description;
	char table_ch;
	char symbol_ch;

	struct aprs_obj_st *next;
} aprs_obj_t;

static aprs_obj_t *aprs_objs_first_entry = NULL;

#define APRS_QUEUE_ENTRY_TYPE_UNKNOWN	0
#define APRS_QUEUE_ENTRY_TYPE_GPSPOS	1
#define APRS_QUEUE_ENTRY_TYPE_MSG		2
typedef uint8_t aprs_queue_entry_type_t;

typedef struct aprs_queue_st {
	aprs_queue_entry_type_t type;
	char repeater_callsign[10];
	union {
		struct {
			char callsign[10];
			char icon_char;
			dmr_data_gpspos_t gpspos;
			time_t added_at;
		} gpspos;
		aprs_msg_t msg;
	} u;

	struct aprs_queue_st *next;
} aprs_queue_t;

static pthread_mutex_t aprs_mutex_queue = PTHREAD_MUTEX_INITIALIZER;
static aprs_queue_t *aprs_queue_first_entry = NULL;
static aprs_queue_t *aprs_queue_last_entry = NULL;

static void aprs_add_entry_to_queue(aprs_queue_t *new_entry) {
	pthread_mutex_lock(&aprs_mutex_queue);
	if (aprs_queue_first_entry == NULL)
		aprs_queue_first_entry = aprs_queue_last_entry = new_entry;
	else {
		aprs_queue_last_entry->next = new_entry;
		aprs_queue_last_entry = new_entry;
	}
	pthread_mutex_unlock(&aprs_mutex_queue);

	// Waking up the thread if it's sleeping.
	pthread_mutex_lock(&aprs_mutex_wakeup);
	pthread_cond_signal(&aprs_cond_wakeup);
	pthread_mutex_unlock(&aprs_mutex_wakeup);
}

void aprs_add_to_queue_msg(char *dst_callsign, char *src_callsign, char *msg, char *repeater_callsign) {
	aprs_queue_t *new_entry;
	uint8_t i;
	uint8_t len;

	if (dst_callsign == NULL || src_callsign == NULL || msg == NULL || repeater_callsign == NULL || repeater_callsign[0] == 0)
		return;

	new_entry = (aprs_queue_t *)calloc(1, sizeof(aprs_queue_t));
	if (new_entry == NULL) {
		console_log("aprs error: can't allocate memory for new msg entry in the queue\n");
		return;
	}
	new_entry->type = APRS_QUEUE_ENTRY_TYPE_MSG;
	strncpy(new_entry->repeater_callsign, repeater_callsign, sizeof(new_entry->repeater_callsign));
	len = min(strlen(dst_callsign), sizeof(new_entry->u.msg.dst_callsign)-1);
	for (i = 0; i < len; i++)
		new_entry->u.msg.dst_callsign[i] = toupper(dst_callsign[i]);
	len = min(strlen(src_callsign), sizeof(new_entry->u.msg.src_callsign)-1);
	for (i = 0; i < len; i++)
		new_entry->u.msg.src_callsign[i] = toupper(src_callsign[i]);
	strncpy(new_entry->u.msg.msg, msg, sizeof(new_entry->u.msg.msg));

	aprs_add_entry_to_queue(new_entry);

	console_log(LOGLEVEL_APRS "aprs queue: added entry: repeater: %s dst: %s src: %s msg: %s\n", new_entry->repeater_callsign,
		new_entry->u.msg.dst_callsign, new_entry->u.msg.src_callsign, new_entry->u.msg.msg);
}

void aprs_add_to_queue_gpspos(dmr_data_gpspos_t *gpspos, char *callsign, uint8_t ssid, char *repeater_callsign) {
	aprs_queue_t *new_entry;

	if (!aprs_enabled || gpspos == NULL || callsign == NULL)
		return;

	if (repeater_callsign == NULL || repeater_callsign[0] == 0) {
		console_log(LOGLEVEL_APRS LOGLEVEL_DEBUG "aprs error: not adding gps position to queue as repeater callsign is empty\n");
		return;
	}

	if (ssid > 9)
		ssid = 9;

	new_entry = (aprs_queue_t *)calloc(1, sizeof(aprs_queue_t));
	if (new_entry == NULL) {
		console_log("aprs error: can't allocate memory for new gps position entry in the queue\n");
		return;
	}
	new_entry->type = APRS_QUEUE_ENTRY_TYPE_GPSPOS;
	memcpy(&new_entry->u.gpspos.gpspos, gpspos, sizeof(dmr_data_gpspos_t));
	snprintf(new_entry->u.gpspos.callsign, sizeof(new_entry->u.gpspos.callsign), "%s-%u", callsign, ssid);
	strncpy(new_entry->repeater_callsign, repeater_callsign, sizeof(new_entry->repeater_callsign));
	new_entry->u.gpspos.added_at = time(NULL);
	switch (ssid) {
		case 0:	new_entry->u.gpspos.icon_char = '-'; break;
		case 1:	new_entry->u.gpspos.icon_char = '='; break;
		case 2:	new_entry->u.gpspos.icon_char = 'F'; break;
		case 3:	new_entry->u.gpspos.icon_char = 'k'; break;
		case 4:	new_entry->u.gpspos.icon_char = 'v'; break;
		case 5:	new_entry->u.gpspos.icon_char = '$'; break;
		case 6:	new_entry->u.gpspos.icon_char = ';'; break;
		default:
		case 7:	new_entry->u.gpspos.icon_char = '['; break;
		case 8:	new_entry->u.gpspos.icon_char = '<'; break;
		case 9:	new_entry->u.gpspos.icon_char = '>'; break;
	}

	aprs_add_entry_to_queue(new_entry);

	console_log(LOGLEVEL_APRS "aprs queue: added entry: repeater: %s callsign: %s pos: %s\n", new_entry->repeater_callsign,
		new_entry->u.gpspos.callsign, dmr_data_get_gps_string(gpspos));
}

static flag_t aprs_thread_sendmsg(const char *format, ...) {
	va_list argptr;
	char buf[1024];
	flag_t result = 1;
	int bytes_sent;

    va_start(argptr, format);

	vsnprintf(buf, sizeof(buf), format, argptr);
	console_log(LOGLEVEL_APRS LOGLEVEL_DEBUG "aprs: sending message: %s", buf);
	errno = 0;
	bytes_sent = write(aprs_sockfd, buf, strlen(buf));
	if (bytes_sent < 0 || (errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		console_log(LOGLEVEL_APRS "aprs error: disconnected\n");
		aprs_loggedin = 0;
		close(aprs_sockfd);
		aprs_sockfd = -1;
		result = 0;
	}

    va_end(argptr);
    return result;
}

static void aprs_thread_connect(void) {
	struct addrinfo hints, *servinfo, *p;
	int res;
	char port_s[6];
	char *host = config_get_aprsserverhost();
	uint16_t port = config_get_aprsserverport();
	char *callsign = config_get_aprsservercallsign();
	uint16_t passcode = config_get_aprsserverpasscode();
	int flag;
	time_t connectstartedat;
	char buf[50] = {0,};
	int bytes_read;
	char expected_login_reply[50];
	struct timespec ts;

	aprs_loggedin = 0;

	if (strlen(host) == 0 || port == 0 || strlen(callsign) == 0) {
		free(host);
		free(callsign);
		return;
	}

	console_log(LOGLEVEL_APRS "aprs: trying to connect to aprs-is server %s:%u...\n", host, port);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_s, sizeof(port_s), "%u", port);
	if ((res = getaddrinfo(host, port_s, &hints, &servinfo)) != 0) {
		console_log("aprs error: failed to resolve hostname (%s)\n", gai_strerror(res));
		goto aprs_thread_connect_end;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		aprs_sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol);
		if (aprs_sockfd < 0)
			continue;

		if (connect(aprs_sockfd, p->ai_addr, p->ai_addrlen) < 0) {
			close(aprs_sockfd);
			aprs_sockfd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(servinfo);
	if (p == NULL) {
		console_log("aprs error: failed to init socket\n");
		goto aprs_thread_connect_end;
	}

	flag = 1;
	setsockopt(aprs_sockfd, IPPROTO_TCP, SO_KEEPALIVE, &flag, sizeof(int));

	console_log(LOGLEVEL_APRS "aprs: logging in\n");
	if (aprs_thread_sendmsg("user %s pass %u vers %s %u.%u.%u\n", callsign, passcode, APPNAME, VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH)) {
		snprintf(expected_login_reply, sizeof(expected_login_reply), "# logresp %s verified", callsign);
		connectstartedat = time(NULL);
		while (1) {
			errno = 0;
			bytes_read = read(aprs_sockfd, buf, sizeof(buf)-1);
			if (bytes_read < 0 || (errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
				console_log(LOGLEVEL_APRS "aprs: error during login\n");
				close(aprs_sockfd);
				aprs_sockfd = -1;
				break;
			}

			if (bytes_read > 0 && isprint(buf[0])) {
				buf[bytes_read] = 0;
				console_log(LOGLEVEL_APRS LOGLEVEL_DEBUG "aprs login read: %s", buf);
			}

			if (strncmp(buf, expected_login_reply, bytes_read) > 0) {
				aprs_loggedin = 1;
				console_log(LOGLEVEL_APRS "aprs: connected\n");
				break;
			}

			if (time(NULL)-connectstartedat > 10) {
				console_log(LOGLEVEL_APRS "aprs: login timeout\n");
				close(aprs_sockfd);
				aprs_sockfd = -1;
				break;
			}

			pthread_mutex_lock(&aprs_mutex_thread_should_stop);
			if (aprs_thread_should_stop) {
				pthread_mutex_unlock(&aprs_mutex_thread_should_stop);
				break;
			}
			pthread_mutex_unlock(&aprs_mutex_thread_should_stop);

			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_nsec += 1000;

			pthread_mutex_lock(&aprs_mutex_wakeup);
			pthread_cond_timedwait(&aprs_cond_wakeup, &aprs_mutex_wakeup, &ts);
			pthread_mutex_unlock(&aprs_mutex_wakeup);
		}
	}

aprs_thread_connect_end:
	free(host);
	free(callsign);
}

static void aprs_processreceivedline(char *line, uint16_t line_length) {
	aprs_msg_t msg;
	char dmr_sms[DMRPACKET_MAX_FRAGMENTSIZE] = {0,};
	userdb_t *dst_userdb_entry;
	uint16_t i, j;

	memset(&msg, 0, sizeof(aprs_msg_t));

	i = 0;
	while (line[i] != '>' && i < line_length)
		i++;
	strncpy(msg.src_callsign, line, min(sizeof(msg.src_callsign), i));

	// Searching for the first ":" from "::"
	while (line[i] != ':' && i < line_length)
		i++;
	if (i+1 < line_length && line[i+1] == ':') { // If the second ":" found from "::"
		i += 2;

		// Searching for the next ":"
		j = 0;
		while (line[i+j] != ':' && line[i+j] != ' ' && line[i+j] != '-' && i+j < line_length) // Halt on " " and "-".
			j++;
		strncpy(msg.dst_callsign, line+i, min(sizeof(msg.dst_callsign), j));

		// Searching for the next ":" (this is needed because we may have halted before ":").
		while (line[i] != ':' && i < line_length)
			i++;
		i++;

		j = 0;
		while (line[i+j] != '\n' && line[i+j] != 0 && line[i+j] != '{' && i+j < line_length)
			j++;
		strncpy(msg.msg, line+i, min(sizeof(msg.msg), j));
		i += j;

		j = 0;
		while (line[i+j] != '\n' && line[i+j] != 0 && line[i+j] != '}' && i+j < line_length)
			j++;
		strncpy(msg.ackpart, line+i+1, min(sizeof(msg.ackpart), j-1));

		if (msg.src_callsign[0] != 0 && msg.dst_callsign[0] != 0 && msg.msg[0] != 0) {
			console_log("aprs: message from %s to %s: %s\n", msg.src_callsign, msg.dst_callsign, msg.msg);
			if (msg.ackpart[0])
				console_log(LOGLEVEL_APRS "  ack part: %s\n", msg.ackpart);

			dst_userdb_entry = userdb_get_entry_for_callsign(msg.dst_callsign);
			if (dst_userdb_entry == NULL)
				console_log("  ignoring, can't get dmr id for dst callsign %s\n", msg.dst_callsign);
			else {
				if (strstr(msg.msg, "ack01}") == msg.msg && msg.ackpart[0] == 0)
					snprintf(dmr_sms, sizeof(dmr_sms), "APRS/%s: msg acked", msg.dst_callsign);
				else
					snprintf(dmr_sms, sizeof(dmr_sms), "APRS/%s: %s", msg.src_callsign, msg.msg);
				smstxbuf_add(0, NULL, 0, DMR_CALL_TYPE_PRIVATE, dst_userdb_entry->id, DMR_DATA_TYPE_NORMAL_SMS, dmr_sms, 0, &msg);
				smstxbuf_add(0, NULL, 0, DMR_CALL_TYPE_PRIVATE, dst_userdb_entry->id, DMR_DATA_TYPE_MOTOROLA_TMS_SMS, dmr_sms, 0, &msg);
				free(dst_userdb_entry);
			}
		}
	}
}

static void aprs_thread_process(void) {
	static time_t last_obj_send_at = 0;
	aprs_obj_t *obj;
	aprs_queue_t *next_entry;
	char timestamp[7];
	char latitude[8];
	char longitude[9];
	char speedcourse[8];
	time_t now;
	char *aprs_callsign;
	char *aprs_posdescription;
	int bytes_read;
	char buf[1024] = {0,};
	struct pollfd pollfd;
	char *tok;

	if (aprs_sockfd < 0 || !aprs_loggedin)
		return;

	aprs_posdescription = config_get_aprsposdescription();
	aprs_callsign = config_get_aprsservercallsign();

	// Processing the position queue.
	pthread_mutex_lock(&aprs_mutex_queue);
	while (aprs_queue_first_entry) {
		switch (aprs_queue_first_entry->type) {
			case APRS_QUEUE_ENTRY_TYPE_GPSPOS:
				console_log(LOGLEVEL_APRS "aprs queue: sending entry: repeater: %s callsign: %s %s\n", aprs_queue_first_entry->repeater_callsign,
					aprs_queue_first_entry->u.gpspos.callsign, dmr_data_get_gps_string(&aprs_queue_first_entry->u.gpspos.gpspos));

				strftime(timestamp, sizeof(timestamp), "%d%H%M", gmtime(&aprs_queue_first_entry->u.gpspos.added_at));
				snprintf(latitude, sizeof(latitude), "%s", dmr_data_get_gps_string_latitude(aprs_queue_first_entry->u.gpspos.gpspos.latitude));
				snprintf(longitude, sizeof(longitude), "%s", dmr_data_get_gps_string_longitude(aprs_queue_first_entry->u.gpspos.gpspos.longitude));
				if (aprs_queue_first_entry->u.gpspos.gpspos.heading_valid || aprs_queue_first_entry->u.gpspos.gpspos.speed_valid) {
					snprintf(speedcourse, sizeof(speedcourse), "%03u/%03u", aprs_queue_first_entry->u.gpspos.gpspos.heading_valid ? aprs_queue_first_entry->u.gpspos.gpspos.heading : 0,
						aprs_queue_first_entry->u.gpspos.gpspos.speed_valid ? aprs_queue_first_entry->u.gpspos.gpspos.speed : 0);
				} else
					speedcourse[0] = 0;
				aprs_thread_sendmsg("%s>APRS,%s*,qAR,%s:@%sz%s%c/%s%c%c%s%s\n",
					aprs_queue_first_entry->u.gpspos.callsign, aprs_queue_first_entry->repeater_callsign, aprs_queue_first_entry->repeater_callsign, timestamp,
					latitude, aprs_queue_first_entry->u.gpspos.gpspos.latitude_ch, longitude, aprs_queue_first_entry->u.gpspos.gpspos.longitude_ch,
					aprs_queue_first_entry->u.gpspos.icon_char, speedcourse, aprs_posdescription);
				break;
			case APRS_QUEUE_ENTRY_TYPE_MSG:
				console_log(LOGLEVEL_APRS "aprs queue: sending entry: repeater: %s dst: %s src: %s msg: %s\n", aprs_queue_first_entry->repeater_callsign,
					aprs_queue_first_entry->u.msg.dst_callsign, aprs_queue_first_entry->u.msg.src_callsign, aprs_queue_first_entry->u.msg.msg);

				aprs_thread_sendmsg("%s>APRS,%s*,qAR,%s::%-9s:%s\n", aprs_queue_first_entry->u.msg.src_callsign, aprs_queue_first_entry->repeater_callsign,
					aprs_queue_first_entry->repeater_callsign, aprs_queue_first_entry->u.msg.dst_callsign, aprs_queue_first_entry->u.msg.msg);
				break;
			default:
				console_log(LOGLEVEL_APRS "aprs queue: ignoring invalid entry\n");
				break;
		}
		next_entry = aprs_queue_first_entry->next;
		free(aprs_queue_first_entry);
		aprs_queue_first_entry = next_entry;
	}
	if (aprs_queue_first_entry == NULL)
		aprs_queue_last_entry = NULL;
	pthread_mutex_unlock(&aprs_mutex_queue);

	// Sending objects if needed.
	if (time(NULL)-last_obj_send_at > 1800) {
		obj = aprs_objs_first_entry;
		if (obj != NULL) {
			console_log(LOGLEVEL_APRS "aprs: sending objects\n");
			now = time(NULL);
			while (obj) {
				strftime(timestamp, sizeof(timestamp), "%d%H%M", gmtime(&now));
				snprintf(latitude, sizeof(latitude), "%s", dmr_data_get_gps_string_latitude(obj->latitude));
				snprintf(longitude, sizeof(longitude), "%s", dmr_data_get_gps_string_longitude(obj->longitude));
				aprs_thread_sendmsg("%s>APRS,TCPIP*,DMRSHARK:;%-9s*%sz%s%c%c%s%c%c%s\n", aprs_callsign, obj->callsign, timestamp,
					latitude, obj->latitude_ch, obj->table_ch, longitude, obj->longitude_ch, obj->symbol_ch, obj->description);

				obj = obj->next;
			}
		}
		last_obj_send_at = time(NULL);
	}

	// Receiving messages.
	pollfd.fd = aprs_sockfd;
	pollfd.events = POLLIN;
	do {
		pollfd.revents = 0;
		poll(&pollfd, 1, 0);
		if (pollfd.revents & POLLIN) { // Socket readable?
			errno = 0;
			bytes_read = read(aprs_sockfd, buf, sizeof(buf)-1);
			if (bytes_read < 0 || (errno != 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
				console_log(LOGLEVEL_APRS "aprs: disconnected\n");
				aprs_loggedin = 0;
				close(aprs_sockfd);
				aprs_sockfd = -1;
			}
			if (bytes_read > 0) {
				console_log(LOGLEVEL_APRS "aprs: read %u bytes: %s", bytes_read, buf);

				buf[bytes_read] = 0;
				tok = strtok(buf, "\n");
				while (tok != NULL) {
					aprs_processreceivedline(tok, strlen(tok));
					tok = strtok(NULL, "\n");
				}
			}
		}
	} while (pollfd.revents & POLLIN);

	free(aprs_posdescription);
	free(aprs_callsign);
}

static void *aprs_thread_init(void *arg) {
	struct timespec ts;
	aprs_queue_t *next_entry;
	time_t lastconnecttryat = 0;

	aprs_thread_should_stop = !aprs_enabled;
	pthread_cond_init(&aprs_cond_wakeup, NULL);

	while (1) {
		if (aprs_sockfd < 0 && time(NULL)-lastconnecttryat >= 10) {
			aprs_thread_connect();
			lastconnecttryat = time(NULL);
		}

		pthread_mutex_lock(&aprs_mutex_thread_should_stop);
		if (aprs_thread_should_stop) {
			pthread_mutex_unlock(&aprs_mutex_thread_should_stop);
			break;
		}
		pthread_mutex_unlock(&aprs_mutex_thread_should_stop);

		aprs_thread_process();

		pthread_mutex_lock(&aprs_mutex_queue);
		if (aprs_queue_first_entry == NULL) {
			pthread_mutex_unlock(&aprs_mutex_queue);

			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 1;

			pthread_mutex_lock(&aprs_mutex_wakeup);
			pthread_cond_timedwait(&aprs_cond_wakeup, &aprs_mutex_wakeup, &ts);
			pthread_mutex_unlock(&aprs_mutex_wakeup);
		} else
			pthread_mutex_unlock(&aprs_mutex_queue);
	}

	pthread_mutex_lock(&aprs_mutex_queue);
	while (aprs_queue_first_entry) {
		next_entry = aprs_queue_first_entry->next;
		free(aprs_queue_first_entry);
		aprs_queue_first_entry = next_entry;
	}
	aprs_queue_last_entry = NULL;
	pthread_mutex_unlock(&aprs_mutex_queue);

	pthread_mutex_destroy(&aprs_mutex_thread_should_stop);
	pthread_mutex_destroy(&aprs_mutex_queue);
	pthread_mutex_destroy(&aprs_mutex_wakeup);
	pthread_cond_destroy(&aprs_cond_wakeup);

	pthread_exit((void*) 0);
}

void aprs_init(void) {
	char **objnames = config_aprsobjs_get_objnames();
	char **objnames_i = objnames;
	pthread_attr_t attr;
	char *host = NULL;
	aprs_obj_t *newobj;
	uint8_t i;
	uint8_t length;

	console_log("aprs: init\n");

	host = config_get_aprsserverhost();
	if (strlen(host) != 0) {
		aprs_enabled = 1;

		while (*objnames_i != NULL) {
			if (config_aprsobjs_get_enabled(*objnames_i)) {
				console_log("  initializing %s...\n", *objnames_i);

				newobj = (aprs_obj_t *)calloc(1, sizeof(aprs_obj_t));

				newobj->callsign = strdup(*(objnames_i)+8); // +8 - cutting out string "aprsobj-"
				length = strlen(newobj->callsign);
				for (i = 0; i < length; i++)
					newobj->callsign[i] = toupper(newobj->callsign[i]);
				newobj->latitude = config_aprsobjs_get_latitude(*objnames_i);
				newobj->latitude_ch = config_aprsobjs_get_latitude_ch(*objnames_i);
				newobj->longitude = config_aprsobjs_get_longitude(*objnames_i);
				newobj->longitude_ch = config_aprsobjs_get_longitude_ch(*objnames_i);
				newobj->description = config_aprsobjs_get_description(*objnames_i);
				newobj->table_ch = config_aprsobjs_get_table_ch(*objnames_i);
				newobj->symbol_ch = config_aprsobjs_get_symbol_ch(*objnames_i);

				if (aprs_objs_first_entry == NULL)
					aprs_objs_first_entry = newobj;
				else {
					newobj->next = aprs_objs_first_entry;
					aprs_objs_first_entry = newobj;
				}
			}

			objnames_i++;
		}
		config_aprsobjs_free_objnames(objnames);

		console_log("aprs: starting thread for aprs\n");

		// Explicitly creating the thread as joinable to be compatible with other systems.
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		pthread_create(&aprs_thread, &attr, aprs_thread_init, NULL);
	} else
		console_log("aprs: no server configured\n");
	free(host);
}

void aprs_deinit(void) {
	void *status = NULL;
	aprs_obj_t *next_obj;

	console_log("aprs: deinit\n");
	aprs_enabled = 0;

	// Waking up the thread if it's sleeping.
	pthread_mutex_lock(&aprs_mutex_wakeup);
	pthread_cond_signal(&aprs_cond_wakeup);
	pthread_mutex_unlock(&aprs_mutex_wakeup);

	pthread_mutex_lock(&aprs_mutex_thread_should_stop);
	aprs_thread_should_stop = 1;
	pthread_mutex_unlock(&aprs_mutex_thread_should_stop);
	console_log("aprs: waiting for aprs thread to exit\n");
	pthread_join(aprs_thread, &status);

	while (aprs_objs_first_entry) {
		next_obj = aprs_objs_first_entry->next;
		free(aprs_objs_first_entry->callsign);
		free(aprs_objs_first_entry->description);
		free(aprs_objs_first_entry);
		aprs_objs_first_entry = next_obj;
	}

	pthread_mutex_destroy(&aprs_mutex_thread_should_stop);
	pthread_mutex_destroy(&aprs_mutex_wakeup);
	pthread_mutex_destroy(&aprs_mutex_queue);
}
