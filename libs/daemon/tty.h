#ifndef TTY_H_
#define TTY_H_

typedef struct {
	char *devname;
	int fd;
	int speed;
	int parity;
} tty_interface_t;

#define TTY_IS_CONNECTED(tty) ((tty)->fd >= 0)

void tty_init(tty_interface_t *tty, char *devname, int baudrate);
int tty_send(tty_interface_t *ti, char *buffer, int length);
void tty_open(tty_interface_t *ti);
void tty_close(tty_interface_t *ti);
int tty_read(tty_interface_t *ti);

#endif
