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

#ifndef CONFIG_VOICESTREAMS_H_
#define CONFIG_VOICESTREAMS_H_

#include <netinet/ip.h>

char **config_voicestreams_get_streamnames(void);
void config_voicestreams_free_streamnames(char **streamnames);

int config_voicestreams_get_enabled(char *streamname);
char *config_voicestreams_get_repeaterhosts(char *streamname);
char *config_voicestreams_get_savefiledir(char *streamname);
int config_voicestreams_get_savetorawfile(char *streamname);
int config_voicestreams_get_timeslot(char *streamname);

void config_voicestreams_init(void);

#endif
