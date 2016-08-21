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

#ifndef CONFIG_H_
#define CONFIG_H_

#include <glib.h>

#include <libs/base/types.h>
#include <libs/daemon/console.h>

GKeyFile *config_get_keyfile(void);
pthread_mutex_t *config_get_mutex(void);

char **config_get_groups(int *length);
void config_free_groups(char **config_groups);

void config_writeconfigfile(void);

void config_set_loglevel(loglevel_t *loglevel);
int config_get_loglevel(void);

char *config_get_logfilename(void);
char *config_get_pidfilename(void);
char *config_get_daemonctlfile(void);
char *config_get_ttyconsoledev(void);
flag_t config_get_ttyconsoleenabled(void);
int config_get_ttyconsolebaudrate(void);
char *config_get_netdevicename(void);
int config_get_repeaterinfoupdateinsec(void);
int config_get_repeaterinactivetimeoutinsec(void);
int config_get_rssiupdateduringcallinmsec(void);
int config_get_calltimeoutinsec(void);
int config_get_datatimeoutinsec(void);
char *config_get_ignoredsnmprepeaterhosts(void);
char *config_get_ignoredhosts(void);
char *config_get_ignoredtalkgroups(void);
char *config_get_allowedtalkgroups(void);
char *config_get_remotedbhost(void);
char *config_get_remotedbuser(void);
char *config_get_remotedbpass(void);
char *config_get_remotedbname(void);
char *config_get_remotedbtableprefix(void);
char *config_get_userdbtablename(void);
char *config_get_callsignbookdbtablename(void);
int config_get_remotedbreconnecttrytimeoutinsec(void);
int config_get_remotedbmaintenanceperiodinsec(void);
int config_get_remotedbdeleteolderthansec(void);
int config_get_remotedbuserlistdlperiodinsec(void);
int config_get_remotedbmsgqueuepollintervalinsec(void);
char *config_get_remotedbmsgqueuetablename(void);
int config_get_updatestatstableenabled(void);
int config_get_httpserverport(void);
int config_get_httpserverenabled(void);
struct in_addr *config_get_masteripaddr(void);
int config_get_smssendmaxretrycount(void);
int config_get_mindatapacketsendretryintervalinsec(void);
int config_get_datapacketsendmaxretrycount(void);
int config_get_smsretransmittimeoutinsec(void);
char *config_get_aprsserverhost(void);
int config_get_aprsserverport(void);
char *config_get_aprsservercallsign(void);
int config_get_aprsserverpasscode(void);
char *config_get_aprsposdescription(void);
flag_t config_get_smsretransmitenabled(void);

// If NULL is given, reloads the current config file.
void config_init(char *configfilename);
void config_deinit(void);

#endif
