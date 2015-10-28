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

#ifndef CONFIG_APRSOBJS_H_
#define CONFIG_APRSOBJS_H_

char **config_aprsobjs_get_objnames(void);
void config_aprsobjs_free_objnames(char **objnames);

int config_aprsobjs_get_enabled(char *objname);
char *config_aprsobjs_get_callsign(char *objname);
double config_aprsobjs_get_latitude(char *objname);
char config_aprsobjs_get_latitude_ch(char *objname);
double config_aprsobjs_get_longitude(char *objname);
char config_aprsobjs_get_longitude_ch(char *objname);
char *config_aprsobjs_get_description(char *objname);
char config_aprsobjs_get_table_ch(char *objname);
char config_aprsobjs_get_symbol_ch(char *objname);

void config_aprsobjs_init(void);

#endif
