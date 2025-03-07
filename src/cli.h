#ifndef SYNFLOOD_CLI_H
#define SYNFLOOD_CLI_H

#include "utils.h"

#include <ctype.h>
#include <getopt.h>

#define DEFAULT_ATTACK_TIME 1
#define DEFAULT_WAIT_TIME 3
#define DEFAULT_LOOP_COUNT 1
#define MAXPORT 16 


void getOptions(int argc, char *argv[], char hostname[HOSTNAME_BUFFER_LENGTH],
                unsigned short int *port, struct sockaddr_in *host_addr,
                unsigned int *attack_time,
		unsigned int *wait_time , unsigned int *loop_count );

#endif

