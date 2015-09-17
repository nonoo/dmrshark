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

#include "httpserver.h"

#include <libs/config/config.h>
#include <libs/daemon/console.h>
#include <libs/daemon/daemon-poll.h>

#include <libwebsockets.h>

#define HTTPSERVER_LWS_TXBUFFER_SIZE 65000

static struct libwebsocket_context *httpserver_lws_context = NULL;

typedef struct httpserver_client_st {
	struct libwebsocket *wsi;
	char host[100];
	voicestream_t *voicestream;
	uint8_t buf[HTTPSERVER_LWS_TXBUFFER_SIZE];
	uint16_t bytesinbuf;
	flag_t close_on_buf_empty;

	struct httpserver_client_st *next;
	struct httpserver_client_st *prev;
} httpserver_client_t;

static httpserver_client_t *httpserver_clients = NULL;

static httpserver_client_t *httpserver_get_client_by_wsi(struct libwebsocket *wsi) {
	httpserver_client_t *client = httpserver_clients;

	if (wsi == NULL)
		return NULL;

	while (client) {
		if (client->wsi == wsi)
			return client;
		client = client->next;
	}
	return NULL;
}

// Adds given bytestosend bytes to the client's tx buffer.
// If there's not enough space, it will fill the buffer up and discards remaining bytes.
// Returns the number of bytes put into the buffer.
static uint16_t httpserver_sendtoclient(httpserver_client_t *client, uint8_t *buf, uint16_t bytestosend) {
	uint16_t bytesfreeinbuf;
	uint16_t bytestowritetobuf;

	if (client == NULL || buf == NULL || bytestosend == 0)
		return 0;

	bytesfreeinbuf = sizeof(client->buf)-client->bytesinbuf;
	bytestowritetobuf = min(bytestosend, bytesfreeinbuf);
	if (bytestowritetobuf) {
		memcpy(client->buf+client->bytesinbuf, buf, bytestowritetobuf);
		client->bytesinbuf += bytestowritetobuf;
	}
	return bytestowritetobuf;
}

static char *httpserver_get_client_host_or_ip(struct libwebsocket_context *context, struct libwebsocket *wsi) {
	static char clienthost[100];
	static char clientip[INET6_ADDRSTRLEN];
	int fd;

	fd = libwebsocket_get_socket_fd(wsi);
	if (fd >= 0)
		libwebsockets_get_peer_addresses(context, wsi, fd, clienthost, sizeof(clienthost), clientip, sizeof(clientip));
	if (clienthost[0] == 0) {
		if (clientip[0] == 0)
			snprintf(clientip, sizeof(clientip), "n/a");
		return clientip;
	}
	return clienthost;
}

static uint16_t httpserver_calc_datatosendsize(struct libwebsocket *wsi, httpserver_client_t *httpserver_client) {
	uint16_t datatosendsize;
	int peerallowance;

	datatosendsize = min(httpserver_client->bytesinbuf, HTTPSERVER_LWS_TXBUFFER_SIZE);
	peerallowance = lws_get_peer_write_allowance(wsi);
	if (peerallowance >= 0)
		datatosendsize = min(datatosendsize, peerallowance);

	return datatosendsize;
}

static int httpserver_http_callback(struct libwebsocket_context *context, struct libwebsocket *wsi,
	enum libwebsocket_callback_reasons reason, void *user, void *in, size_t len)
{
	struct libwebsocket_pollargs *pa = (struct libwebsocket_pollargs *)in;
	uint8_t txbuf[HTTPSERVER_LWS_TXBUFFER_SIZE];
	char *requrl = (char *)in;
	flag_t pagefound = 0;
	httpserver_client_t *httpserver_client = NULL;
	uint16_t datatosendsize;
	int bytes_sent;
	char *tok;

	if (context == NULL || wsi == NULL)
		return -1;

	switch (reason) {
		case LWS_CALLBACK_HTTP: // Got a plain HTTP request.
			if (len < 1) {
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_BAD_REQUEST, NULL);
				return -1;
			}

			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;
			strncpy(httpserver_client->host, httpserver_get_client_host_or_ip(context, wsi), sizeof(httpserver_client->host));

			console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "httpserver [%s]: got request: %s ", httpserver_client->host, requrl);

			// HTTP POST not allowed.
			if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
				console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "(post request, not allowed, closing connection)\n");
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
				return -1;
			}

			tok = strtok(requrl, "/");
			if (tok == NULL) {
				console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "(status page request)\n");
				pagefound = 1;

				// TODO: status page
				snprintf((char *)txbuf, sizeof(txbuf),
					"HTTP/1.0 200 OK\r\n"
					"\r\n"
					"Hello World!\r\n");
				httpserver_client->close_on_buf_empty = 1;
				httpserver_sendtoclient(httpserver_client, txbuf, strlen((char *)txbuf));
			} else{
				httpserver_client->voicestream = voicestreams_get_stream_by_name(tok);
				if (httpserver_client->voicestream != NULL) { // Request is for an existing voicestream?
					console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "(request for %s)\n", tok);
					pagefound = 1;
					snprintf((char *)txbuf, sizeof(txbuf),
						"HTTP/1.1 200 OK\r\n"
						"Server: dmrshark v%u.%u.%u\r\n"
						"icy-name: dmrshark v%u.%u.%u - playing %s\r\n"
						"ice-audio-info: ice-samplerate=8000;ice-channels=1\r\n"
						"icy-description: dmrshark by ha2non - https://github.com/nonoo/dmrshark/\r\n"
						"icy-genre: Speech\r\n"
						"icy-private: 0\r\n"
						"icy-pub: 1\r\n"
						"icy-url: http://nonoo.hu/\r\n"
						"Content-Type: audio/mpeg\r\n"
						"Content-Length: -1\r\n"
						"Accept-Ranges: bytes\r\n"
						"Cache-Control: no-cache, no-store\r\n"
						"Pragma: no-cache\r\n"
						"Expires: Mon, 26 Jul 1997 05:00:00 GMT\r\n"
						"Connection: close\r\n"
						"\r\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH,
						VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, tok);
					httpserver_sendtoclient(httpserver_client, txbuf, strlen((char *)txbuf));
				}
			}

			if (!pagefound) {
				console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "(404)\n");
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}

			// Schedule a callback for async tx.
			libwebsocket_callback_on_writable(context, wsi);
			break;

		case LWS_CALLBACK_HTTP_WRITEABLE: // One of the HTTP clients got writable.
			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;

			while (httpserver_client->bytesinbuf > 0) {
				datatosendsize = httpserver_calc_datatosendsize(wsi, httpserver_client);
				memcpy(txbuf, httpserver_client->buf, datatosendsize);
				bytes_sent = libwebsocket_write(wsi, txbuf, datatosendsize, LWS_WRITE_HTTP);
				if (bytes_sent < 0)
					return -1;

				// Shifting the buffer, so we can continue sending the data next time.
				memmove(httpserver_client->buf, httpserver_client->buf+bytes_sent, sizeof(httpserver_client->buf)-bytes_sent);
				httpserver_client->bytesinbuf -= bytes_sent;

				if (lws_partial_buffered(wsi) || lws_send_pipe_choked(wsi))
					break;
			}

			if (httpserver_client->bytesinbuf == 0 && httpserver_client->close_on_buf_empty)
				return -1;

			// Schedule a callback again for async tx.
			libwebsocket_callback_on_writable(context, wsi);
			break;

		case LWS_CALLBACK_WSI_CREATE:
			console_log(LOGLEVEL_HTTPSERVER "httpserver: adding new client\n");
			httpserver_client = (httpserver_client_t *)calloc(1, sizeof(httpserver_client_t));
			if (!httpserver_client) {
				console_log("  error: can't allocate memory for the new client\n");
				return -1;
			}
			strncpy(httpserver_client->host, "n/a", sizeof(httpserver_client->host));
			httpserver_client->wsi = wsi;
			if (httpserver_clients == NULL)
				httpserver_clients = httpserver_client;
			else {
				// Adding httpserver_client to the beginning of the linked list.
				httpserver_client->next = httpserver_clients;
				httpserver_clients->prev = httpserver_client;
				httpserver_clients = httpserver_client;
			}
			break;

		case LWS_CALLBACK_WSI_DESTROY:
			if (httpserver_clients == NULL)
				break;

			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client) {
				console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: closing session\n", httpserver_client->host);
				// Removing from the linked list.
				if (httpserver_client->prev)
					httpserver_client->prev->next = httpserver_client->next;
				if (httpserver_client->next)
					httpserver_client->next->prev = httpserver_client->prev;
				if (httpserver_client == httpserver_clients)
					httpserver_clients = httpserver_client->next;
				free(httpserver_client);
				break;
			}
			break;

		case LWS_CALLBACK_ADD_POLL_FD:
			daemon_poll_addfd(pa->fd, pa->events);
			break;

		case LWS_CALLBACK_DEL_POLL_FD:
			daemon_poll_removefd(pa->fd);
			break;

		case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
			daemon_poll_changefd(pa->fd, pa->events);
			break;

		default:
			break;
	}

	return 0;
}

static void httpserver_wesockets_parse_command_line(httpserver_client_t *httpserver_client, char *line, uint8_t *txbuf) {
	char *wordtok = NULL;
	char *wordtok_saveptr = NULL;

	wordtok = strtok_r(line, " ", &wordtok_saveptr); // First word is the command.
	if (strcmp("changestream", wordtok) == 0) {
		wordtok = strtok_r(NULL, " ", &wordtok_saveptr);
		httpserver_client->voicestream = voicestreams_get_stream_by_name(wordtok);
		if (httpserver_client->voicestream != NULL)
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: stream changed to %s\n", httpserver_client->host, wordtok);
		else
			console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "httpserver [%s] error: stream %s not found\n", httpserver_client->host, wordtok);
	}
}

// This function handles websocket voicestream callbacks.
static int httpserver_websockets_voicestream_callback(struct libwebsocket_context *context, struct libwebsocket *wsi,
	enum libwebsocket_callback_reasons reason, void *user, void *in, size_t len)
{
	uint8_t txbuf_padded[LWS_SEND_BUFFER_PRE_PADDING + HTTPSERVER_LWS_TXBUFFER_SIZE + LWS_SEND_BUFFER_POST_PADDING];
	uint8_t *txbuf = &txbuf_padded[LWS_SEND_BUFFER_PRE_PADDING];
	int bytes_sent;
	uint16_t datatosendsize;
	httpserver_client_t *httpserver_client = NULL;
	char *linetok = NULL;
	char *linetok_saveptr = NULL;

	if (context == NULL || wsi == NULL)
		return -1;

	switch (reason) {
		case LWS_CALLBACK_ESTABLISHED:
			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;
			strncpy(httpserver_client->host, httpserver_get_client_host_or_ip(context, wsi), sizeof(httpserver_client->host));
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: websocket client connected\n", httpserver_client->host);

			// Schedule a callback for async tx.
			libwebsocket_callback_on_writable(context, wsi);
			break;

		case LWS_CALLBACK_CLOSED:
			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: websocket client disconnected\n", httpserver_client->host);
			break;

		case LWS_CALLBACK_RECEIVE: // One of the websocket clients sent us something.
			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;
			console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "httpserver [%s]: rx: %s\n", httpserver_client->host, (char *)in);

			linetok = strtok_r((char *)in, "\n", &linetok_saveptr);
			while (linetok != NULL) {
				httpserver_wesockets_parse_command_line(httpserver_client, linetok, txbuf);
				linetok = strtok_r(NULL, "\n", &linetok_saveptr);
			}
			break;

		case LWS_CALLBACK_SERVER_WRITEABLE: // One of the websocket clients got writable.
			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;

			while (httpserver_client->bytesinbuf > 0) {
				datatosendsize = httpserver_calc_datatosendsize(wsi, httpserver_client);
				memcpy(txbuf, httpserver_client->buf, datatosendsize);
				bytes_sent = libwebsocket_write(wsi, txbuf, datatosendsize, LWS_WRITE_BINARY);
				if (bytes_sent < 0)
					return -1;

				// Shifting the buffer, so we can continue sending the data next time.
				memmove(httpserver_client->buf, httpserver_client->buf+bytes_sent, sizeof(httpserver_client->buf)-bytes_sent);
				httpserver_client->bytesinbuf -= bytes_sent;

				if (lws_partial_buffered(wsi) || lws_send_pipe_choked(wsi))
					break;
			}

			// Schedule a callback again for async tx.
			libwebsocket_callback_on_writable(context, wsi);
			break;

		default:
			break;
	}

	return 0;
}

static struct libwebsocket_protocols lwsprotocols[] = {
	// First protocol must always be the HTTP handler
	{
		"http-only",							// Name
		httpserver_http_callback,				// Callback
		0,										// Per session data size
		128,									// RX buffer size // TODO
		0										// No buffer, all partial tx
	},
	{
		"voicestream",
		httpserver_websockets_voicestream_callback,
		0,
		128,
		0
	},
	{ NULL, NULL, 0, 0 }
};

void httpserver_sendtoclients(voicestream_t *voicestream, uint8_t *buf, uint16_t bytestosend) {
	httpserver_client_t *client = httpserver_clients;

	if (voicestream == NULL || buf == NULL || bytestosend == 0 || !config_get_httpserverenabled())
		return;

	// Looping through all clients and putting data into their buffers if the voicestream matches.
	// Sending will be handled by the periodic callbacks.
	while (client) {
		if (voicestream == client->voicestream)
			httpserver_sendtoclient(client, buf, bytestosend);

		client = client->next;
	}
}

static void httpserver_websockets_log(int level, const char *line) {
	if (level == LLL_ERR)
		console_log(LOGLEVEL_HTTPSERVER "httpserver websockets error: %s", line);
	else
		console_log(LOGLEVEL_HTTPSERVER "httpserver websockets: %s", line);
}

void httpserver_process(void) {
	int i;
	int pfdcount;
	struct pollfd *pfd;

	if (!config_get_httpserverenabled() || httpserver_lws_context == NULL)
		return;

	pfdcount = daemon_poll_getpfdcount();
	pfd = daemon_poll_getpfd();

	for (i = 0; i < pfdcount; i++)
		libwebsocket_service_fd(httpserver_lws_context, &pfd[i]);
}

void httpserver_init(void) {
	struct lws_context_creation_info lwsinfo;

	if (!config_get_httpserverenabled())
		return;

	if (!config_get_httpserverport()) {
		console_log("httpserver error: can't get http server port\n");
		return;
	}
	console_log("httpserver: initializing on port %u\n", config_get_httpserverport());

	memset(&lwsinfo, 0, sizeof(lwsinfo));
	lwsinfo.port = config_get_httpserverport();
	lwsinfo.protocols = lwsprotocols;
	lwsinfo.gid = lwsinfo.uid = -1;

//	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO, httpserver_websockets_log);
	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, httpserver_websockets_log);

	httpserver_lws_context = libwebsocket_create_context(&lwsinfo);
	if (httpserver_lws_context == NULL) {
		console_log("httpserver error: libwebsocket init failed\n");
		return;
	}
}

void httpserver_deinit(void) {
	if (httpserver_lws_context) {
		libwebsocket_context_destroy(httpserver_lws_context);
		httpserver_lws_context = NULL;
	}

	console_log("httpserver: deinit\n");
}
