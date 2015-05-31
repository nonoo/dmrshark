#ifndef CONFIG_H_
#define CONFIG_H_

#include <libs/base/types.h>
#include <libs/daemon/console.h>

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
int config_get_snmpinfoupdateinsec(void);
int config_get_repeaterinactivetimeoutinsec(void);
int config_get_rssiupdateduringcallinmsec(void);
int config_get_calltimeoutinsec(void);
char *config_get_ignoredrepeaterips(void);

// If NULL is given, reloads the current config file.
void config_init(char *configfilename);
void config_deinit(void);

#endif
