#ifndef SNMP_H_
#define SNMP_H_

void snmp_start_read_rssi(char *host);
void snmp_start_read_repeaterinfo(char *host);

void snmp_process(void);
void snmp_init(void);
void snmp_deinit(void);

#endif
