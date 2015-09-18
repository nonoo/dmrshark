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

#ifndef HTTPSERVER_H_
#define HTTPSERVER_H_

#include <libs/voicestreams/voicestreams.h>

#include <libs/base/types.h>

void httpserver_sendtoclients(voicestream_t *voicestream, uint8_t *buf, uint16_t bytestosend);

void httpserver_print_client_list(void);

void httpserver_process(void);

void httpserver_init(void);
void httpserver_deinit(void);

#endif
