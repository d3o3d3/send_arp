#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int getmac (char * interface, uint8_t * ad);
int getip(char * interface, char * ip);