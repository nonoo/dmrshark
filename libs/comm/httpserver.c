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

#define HTTPSERVER_LWS_TXBUFFER_SIZE 32768

static struct libwebsocket_context *httpserver_lws_context = NULL;

typedef struct httpserver_client_st {
	struct libwebsocket *wsi;
	voicestream_t *voicestream;
	uint8_t buf[HTTPSERVER_LWS_TXBUFFER_SIZE];
	uint16_t bytesinbuf;

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

static int httpserver_http_callback(struct libwebsocket_context *context, struct libwebsocket *wsi,
	enum libwebsocket_callback_reasons reason, void *user, void *in, size_t len)
{
	struct libwebsocket_pollargs *pa = (struct libwebsocket_pollargs *)in;
	uint8_t buf[256];
	const char *requrl = (const char *)in;
	flag_t pagefound = 0;
	httpserver_client_t *httpserver_client = NULL;
	char clienthost[100] = {0,};
	char clientip[INET6_ADDRSTRLEN] = {0,};

	if (context == NULL || wsi == NULL)
		return -1;

	libwebsockets_get_peer_addresses(context, wsi, libwebsocket_get_socket_fd(wsi), clienthost, sizeof(clienthost), clientip, sizeof(clientip));
	console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "httpserver [%s]: got request from %s: %s\n", clientip, clienthost, requrl);

	switch (reason) {
		case LWS_CALLBACK_HTTP: // Got a plain HTTP request.
			if (len < 1) {
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_BAD_REQUEST, NULL);
				return -1;
			}

			// HTTP POST not allowed.
			if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI)) {
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_FORBIDDEN, NULL);
				return -1;
			}

			if (strcmp(requrl, "/") == 0) {
				console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: got status page request\n", clientip);
				pagefound = 1;

				// TODO: status page
				snprintf((char *)buf, sizeof(buf),
					"HTTP/1.0 200 OK\r\n"
					"\r\n"
					"Hello World!\r\n");
			}

			if (!pagefound) {
				libwebsockets_return_http_status(context, wsi, HTTP_STATUS_NOT_FOUND, NULL);
				return -1;
			}

			libwebsocket_write(wsi, buf, strlen((char *)buf), LWS_WRITE_HTTP);
			return -1;

		case LWS_CALLBACK_WSI_CREATE:
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: adding new client\n", clientip);
			httpserver_client = (httpserver_client_t *)calloc(1, sizeof(httpserver_client_t));
			if (!httpserver_client) {
				console_log("httpserver [%s] error: can't allocate memory for the new client\n", clientip);
				return -1;
			}
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
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: closing session\n", clientip);

			if (httpserver_clients == NULL)
				break;

			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client) {
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

// This function handles websocket voicestream callbacks.
static int httpserver_websockets_voicestream_callback(struct libwebsocket_context *context, struct libwebsocket *wsi,
	enum libwebsocket_callback_reasons reason, void *user, void *in, size_t len)
{
	uint8_t txbuf_padded[LWS_SEND_BUFFER_PRE_PADDING + HTTPSERVER_LWS_TXBUFFER_SIZE + LWS_SEND_BUFFER_POST_PADDING];
	uint8_t *txbuf = &txbuf_padded[LWS_SEND_BUFFER_PRE_PADDING];
	int res;
	int datatosendsize;
	int peerallowance;
	char clienthost[100] = {0,};
	char clientip[INET6_ADDRSTRLEN] = {0,};
	httpserver_client_t *httpserver_client = NULL;

	libwebsockets_get_peer_addresses(context, wsi, libwebsocket_get_socket_fd(wsi), clienthost, sizeof(clienthost), clientip, sizeof(clientip));

	switch (reason) {
		case LWS_CALLBACK_ESTABLISHED:
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: websocket client connected\n", clientip);

			// Schedule a callback for async tx.
			libwebsocket_callback_on_writable(context, wsi);
			break;

		case LWS_CALLBACK_CLOSED:
			console_log(LOGLEVEL_HTTPSERVER "httpserver [%s]: websocket client disconnected\n", clientip);
			break;

		case LWS_CALLBACK_RECEIVE: // One of the websocket clients sent us something.
			console_log(LOGLEVEL_HTTPSERVER LOGLEVEL_DEBUG "httpserver [%s]: rx: %s\n", (char *)in);
			break;

		case LWS_CALLBACK_SERVER_WRITEABLE: // One of the websocket clients got writable.
			httpserver_client = httpserver_get_client_by_wsi(wsi);
			if (httpserver_client == NULL)
				return -1;

			while (httpserver_client->bytesinbuf > 0) {
				datatosendsize = min(httpserver_client->bytesinbuf, HTTPSERVER_LWS_TXBUFFER_SIZE);
				peerallowance = lws_get_peer_write_allowance(wsi);
				if (peerallowance >= 0)
					datatosendsize = min(datatosendsize, peerallowance);
				memcpy(txbuf, httpserver_client->buf, datatosendsize);
				res = libwebsocket_write(wsi, txbuf, datatosendsize, LWS_WRITE_BINARY);
				if (res < 0)
					return -1;

				// Shifting the buffer, so we can continue sending the data next time.
				memmove(httpserver_client->buf, httpserver_client->buf+res, sizeof(httpserver_client->buf)-res);
				httpserver_client->bytesinbuf -= res;

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

	if (!config_get_httpserverenabled())
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
