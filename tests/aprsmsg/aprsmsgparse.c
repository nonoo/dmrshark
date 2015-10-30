#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define min(a,b) (((a) < (b)) ? (a) : (b))

static void aprs_processreceivedline(char *line, uint16_t line_length) {
	char msg_from_callsign[10] = {0,};
	char msg_to_callsign[10] = {0,};
	char msg[100];
	uint16_t i, j;

	i = 0;
	while (line[i] != '>' && i < line_length)
		i++;
	strncpy(msg_from_callsign, line, min(sizeof(msg_from_callsign), i));

	// Searching for ::
	while (line[i] != ':' && i < line_length)
		i++;
	if (i+1 < line_length && line[i+1] == ':') {
		i += 2;

		// Searching for :
		j = 0;
		while (line[i+j] != ':' && line[i+j] != ' ' && i+j < line_length)
			j++;
		strncpy(msg_to_callsign, line+i, min(sizeof(msg_to_callsign), j));

		while (line[i] != ':' && i < line_length)
			i++;
		i++;

		if (msg_from_callsign[0] != 0 && msg_to_callsign[0] != 0 && i < line_length) {
			printf("aprs: message from %s to %s: %s\n", msg_from_callsign, msg_to_callsign, line+i);
		}
	}
}

int main(void) {
//	char *buf2 = "HA5KDR>APRS,TCPIP*,qAC,SEVENTH::HA2NON-7 :achg";
	char *buf2 = "# aprsc 2.0.18-ge7666c5 29 Oct 2015 22:50:12 GMT T2HUN 185.43.207.219:14580\nHA5KDR>APRS,TCPIP*,qAC,NINTH::HA2NON-7 :hey!"; // TODO
	char *buf = strdup(buf2);
	int bytes_read = strlen(buf2);
	char *tok;

	tok = strtok(buf, "\n");
	while (tok != NULL) {
		aprs_processreceivedline(tok, strlen(tok));
		tok = strtok(NULL, "\n");
	}

	return 0;
}
