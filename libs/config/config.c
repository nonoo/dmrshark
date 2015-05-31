#include <config/defaults.h>

#include "config.h"

#include <libs/base/types.h>

#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>

static GKeyFile *keyfile = NULL;
static GKeyFileFlags flags;
static char *config_configfilename = NULL;

void config_writeconfigfile(void) {
	GError *error = NULL;
	FILE *f;
	gsize size;
	char *data = NULL;

	if (config_configfilename == NULL) {
		console_log("config error: no config file name given\n");
		return;
	}

	data = g_key_file_to_data(keyfile, &size, &error);
	if (!error && data != NULL) {
		f = fopen(config_configfilename, "w");
		if (f) {
			fwrite(data, 1, size, f);
			fclose(f);
		} else
			console_log("config error: can't save, file %s is not writable\n", config_configfilename);
	} else
		console_log("config error: can't save\n");

	if (data)
		free(data);
}

void config_set_loglevel(loglevel_t *loglevel) {
	g_key_file_set_integer(keyfile, "main", "loglevel", loglevel->raw);
	config_writeconfigfile();
}

int config_get_loglevel(void) {
	GError *error = NULL;
	int defaultvalue = 0;
	int value = g_key_file_get_integer(keyfile, "main", "loglevel", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "loglevel", value);
	}
	return value;
}

char *config_get_logfilename(void) {
	GError *error = NULL;
	char *defaultvalue = APPNAME ".log";
	char *value = g_key_file_get_string(keyfile, "main", "logfile", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "logfile", value);
		}
	}
	return value;
}

char *config_get_pidfilename(void) {
	GError *error = NULL;
	char *defaultvalue = APPNAME ".pid";
	char *value = g_key_file_get_string(keyfile, "main", "pidfile", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "pidfile", value);
		}
	}
	return value;
}

char *config_get_daemonctlfile(void) {
	GError *error = NULL;
	char *defaultvalue = "/tmp/" APPNAME ".ctl";
	char *value = g_key_file_get_string(keyfile, "main", "daemonctlfile", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "daemonctlfile", value);
		}
	}
	return value;
}

char *config_get_ttyconsoledev(void) {
	GError *error = NULL;
	char *defaultvalue = "/dev/ttyUSB0";
	char *value = g_key_file_get_string(keyfile, "main", "ttyconsoledev", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "ttyconsoledev", value);
		}
	}
	return value;
}

flag_t config_get_ttyconsoleenabled(void) {
	GError *error = NULL;
	int defaultvalue = 0;
	int value = g_key_file_get_integer(keyfile, "main", "ttyconsoleenabled", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "ttyconsoleenabled", value);
	}
	return (value != 0 ? 1 : 0);
}

int config_get_ttyconsolebaudrate(void) {
	GError *error = NULL;
	int defaultvalue = 115200;
	int value = g_key_file_get_integer(keyfile, "main", "ttyconsolebaudrate", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "ttyconsolebaudrate", value);
	}
	return value;
}

char *config_get_netdevicename(void) {
	GError *error = NULL;
	char *defaultvalue = "eth0";
	char *value = g_key_file_get_string(keyfile, "main", "netdevicename", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "netdevicename", value);
		}
	}
	return value;
}

int config_get_snmpinfoupdateinsec(void) {
	GError *error = NULL;
	int defaultvalue = 60;
	int value = g_key_file_get_integer(keyfile, "main", "snmpinfoupdateinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "snmpinfoupdateinsec", value);
	}
	return value;
}

int config_get_repeaterinactivetimeoutinsec(void) {
	GError *error = NULL;
	int defaultvalue = 60;
	int value = g_key_file_get_integer(keyfile, "main", "repeaterinactivetimeoutinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "repeaterinactivetimeoutinsec", value);
	}
	return value;
}

void config_init(char *configfilename) {
	GError *error = NULL;

	console_log("config: init\n");

	if (configfilename != NULL)
		config_configfilename = configfilename;

	FILE *f = fopen(config_configfilename, "r");
	if (f == NULL) {
		console_log("config: config file %s doesn't exist, creating\n", config_configfilename);
		f = fopen(config_configfilename, "w");
		if (!f) {
			console_log("config error: can't save, file is not writable\n");
			return;
		}
		fputs("[main]\n", f);
	}
	fclose(f);

	if (keyfile != NULL) {
		g_key_file_free(keyfile);
		keyfile = NULL;
	}

	keyfile = g_key_file_new();

	flags = G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS;
	if (!g_key_file_load_from_file(keyfile, config_configfilename, flags, &error)) {
		console_log("config: error loading file\n");
		g_key_file_free(keyfile);
		keyfile = NULL;
	}

	// We read everything, a default value will be set for non-existent keys in the config file
	config_get_loglevel();
	char *temp = config_get_logfilename();
	free(temp);
	temp = config_get_pidfilename();
	free(temp);
	temp = config_get_daemonctlfile();
	free(temp);
	temp = config_get_ttyconsoledev();
	free(temp);
	config_get_ttyconsoleenabled();
	config_get_ttyconsolebaudrate();
	temp = config_get_netdevicename();
	free(temp);
	config_get_snmpinfoupdateinsec();
	config_get_repeaterinactivetimeoutinsec();

	config_writeconfigfile();
}

void config_deinit(void) {
	console_log("config: deinit\n");

	if (keyfile != NULL) {
		g_key_file_free(keyfile);
		keyfile = NULL;
	}
}
