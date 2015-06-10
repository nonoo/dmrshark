#include <config/defaults.h>

#include "config.h"

#include <libs/base/types.h>

#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static pthread_mutex_t config_mutex;
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

	pthread_mutex_lock(&config_mutex);

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

	pthread_mutex_unlock(&config_mutex);
}

void config_set_loglevel(loglevel_t *loglevel) {
	pthread_mutex_lock(&config_mutex);
	g_key_file_set_integer(keyfile, "main", "loglevel", loglevel->raw);
	pthread_mutex_unlock(&config_mutex);
	config_writeconfigfile();
}

int config_get_loglevel(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 0;
	value = g_key_file_get_integer(keyfile, "main", "loglevel", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "loglevel", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_logfilename(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = APPNAME ".log";
	value = g_key_file_get_string(keyfile, "main", "logfile", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "logfile", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_pidfilename(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = APPNAME ".pid";
	value = g_key_file_get_string(keyfile, "main", "pidfile", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "pidfile", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_daemonctlfile(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = "/tmp/" APPNAME ".ctl";
	value = g_key_file_get_string(keyfile, "main", "daemonctlfile", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "daemonctlfile", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_ttyconsoledev(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = "/dev/ttyUSB0";
	value = g_key_file_get_string(keyfile, "main", "ttyconsoledev", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "ttyconsoledev", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

flag_t config_get_ttyconsoleenabled(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 0;
	value = g_key_file_get_integer(keyfile, "main", "ttyconsoleenabled", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "ttyconsoleenabled", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return (value != 0 ? 1 : 0);
}

int config_get_ttyconsolebaudrate(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 115200;
	value = g_key_file_get_integer(keyfile, "main", "ttyconsolebaudrate", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "ttyconsolebaudrate", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_netdevicename(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = "any";
	value = g_key_file_get_string(keyfile, "main", "netdevicename", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "netdevicename", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

int config_get_repeaterinfoupdateinsec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 300;
	value = g_key_file_get_integer(keyfile, "main", "repeaterinfoupdateinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "repeaterinfoupdateinsec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

int config_get_repeaterinactivetimeoutinsec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 30;
	value = g_key_file_get_integer(keyfile, "main", "repeaterinactivetimeoutinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "repeaterinactivetimeoutinsec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

int config_get_rssiupdateduringcallinmsec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 500;
	value = g_key_file_get_integer(keyfile, "main", "rssiupdateduringcallinmsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "rssiupdateduringcallinmsec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

int config_get_calltimeoutinsec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 5;
	value = g_key_file_get_integer(keyfile, "main", "calltimeoutinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "calltimeoutinsec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_ignoredsnmprepeaterhosts(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = "";
	value = g_key_file_get_string(keyfile, "main", "ignoredsnmprepeaterhosts", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "ignoredsnmprepeaterhosts", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_remotedbhost(void) {
	GError *error = NULL;
	char *defaultvalue = NULL;
	char *value = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = "";
	value = g_key_file_get_string(keyfile, "main", "remotedbhost", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "remotedbhost", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_remotedbuser(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = APPNAME;
	value = g_key_file_get_string(keyfile, "main", "remotedbuser", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "remotedbuser", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_remotedbpass(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = "";
	value = g_key_file_get_string(keyfile, "main", "remotedbpass", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "remotedbpass", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_remotedbname(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = APPNAME;
	value = g_key_file_get_string(keyfile, "main", "remotedbname", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "remotedbname", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

char *config_get_remotedbtableprefix(void) {
	GError *error = NULL;
	char *value = NULL;
	char *defaultvalue = NULL;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = APPNAME "-";
	value = g_key_file_get_string(keyfile, "main", "remotedbtableprefix", &error);
	if (error || value == NULL) {
		value = (char *)malloc(strlen(defaultvalue)+1);
		if (value) {
			strcpy(value, defaultvalue);
			g_key_file_set_string(keyfile, "main", "remotedbtableprefix", value);
		}
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

int config_get_remotedbreconnecttrytimeoutinsec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 5;
	value = g_key_file_get_integer(keyfile, "main", "remotedbreconnecttrytimeoutinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "remotedbreconnecttrytimeoutinsec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

int config_get_remotedbmaintenanceperiodinsec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 3600;
	value = g_key_file_get_integer(keyfile, "main", "remotedbmaintenanceperiodinsec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "remotedbmaintenanceperiodinsec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}


int config_get_remotedbdeleteolderthansec(void) {
	GError *error = NULL;
	int value = 0;
	int defaultvalue = 0;

	pthread_mutex_lock(&config_mutex);
	defaultvalue = 86400;
	value = g_key_file_get_integer(keyfile, "main", "remotedbdeleteolderthansec", &error);
	if (error) {
		value = defaultvalue;
		g_key_file_set_integer(keyfile, "main", "remotedbdeleteolderthansec", value);
	}
	pthread_mutex_unlock(&config_mutex);
	return value;
}

void config_init(char *configfilename) {
	GError *error = NULL;

	console_log("config: init\n");

	pthread_mutex_init(&config_mutex, NULL);

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
	config_get_repeaterinfoupdateinsec();
	config_get_repeaterinactivetimeoutinsec();
	config_get_rssiupdateduringcallinmsec();
	config_get_calltimeoutinsec();
	temp = config_get_ignoredsnmprepeaterhosts();
	free(temp);
	temp = config_get_remotedbhost();
	free(temp);
	temp = config_get_remotedbuser();
	free(temp);
	temp = config_get_remotedbpass();
	free(temp);
	temp = config_get_remotedbname();
	free(temp);
	temp = config_get_remotedbtableprefix();
	free(temp);
	config_get_remotedbreconnecttrytimeoutinsec();
	config_get_remotedbdeleteolderthansec();

	config_writeconfigfile();
}

void config_deinit(void) {
	console_log("config: deinit\n");

	if (keyfile != NULL) {
		g_key_file_free(keyfile);
		keyfile = NULL;
	}

	pthread_mutex_destroy(&config_mutex);
}
