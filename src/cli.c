#include "cli.h"

extern int allports[] ; 
extern int maxports ; 
extern char portlist[] ; 


bool verbose = false;
bool enable_sniffer = false;
bool enable_spoofing = false;
bool enable_wait_time = false ; 
bool enable_loop_count = false ; 
bool enable_attack_time = false ; 
bool enable_classc = false ; 

char usage_message[] = "\
Usage: [sudo] synflood [REQUIRED PARAMETERS] [OPTIONAL PARAMETERS]\n\
\n\
Required parameters:\n\
\n\
-h, --hostname\n\
    The hostname or IP address of the target to attack. \n\
    We expect the hostname to resolve to an IPv4 address.\n\
    example: \n\
       -h 192.168.1.1  \n\
\n\
-p, --port\n\
    A port number or a list of port numbers that you want to attack. \n\
    Can be any valid TCP port that's open on the target server. \n\
    examples: \n\
       --port 80 \n\
       -p 80,25,443 \n\
\n\
Optional parameters:\n\
\n\
-t, --attack-time\n\
    The number of seconds to launch the attack for. \n\
    Must be a positive integer less than 120 (seconds).  \n\
    example: \n\
       -t 30 \n\
\n\
-v\n\
    Enable verbose mode (recommended to be used as first argument).\n\
\n\
-s --enable-sniffer\n\
    Enable the packet sniffer. We use libpcap and a child process to manage\n\
    sniffing only the packets we're interested in. If verbose mode is enabled\n\
    you'll be able to see the exact packet capture filter being employed.\n\
\n\
-n --class-c-network-spoofing\n\
    It enables random IPv4 address out of the range where the host is located.\n\
    If the host is within a supernet of class C it will only take 256 IP addresses \n\
    for the spoofed host part. It doesn't care about the real notwork boundaries. \n\
\n\
-e --enable-spoofing\n\
    Enable random IPv4 address spoofing. Not recommended since more often\n\
    than not these packets would be dropped by the network at some point\n\
    or the other. For example, all major VPS providers will block outgoing\n\
    packets with spoofed ip addresses. Even incoming spoofed packets can\n\
    potentially be detected and dropped. \n\
    Usefull for testing within the own network. \n\
\n\
-c, --loop-count\n\
    run synflood for a well defined number of packets sent out. \n\
    Usefull for testing with a small number of packets. \n\
    example: \n\
       -c 10 \n\
\n\
-w, --wait-time\n\
    wait seconds before and after synflood \n\
    values between 0 and 30 \n\
    0 means no wait time \n\
    default value is 2 seconds  \n\
    Usefull to prepare 'tcpdump' or other tools in a different window. \n\
    example: \n\
       -w 0 \n\
\n\
";


/**
 * Validate the given port number string and then return it's unsigned integer value.
*/
unsigned short int
validatePort (const char *inp)
{
  int port_no;
  bool invalid_port_no = false;
  size_t slen = strlen(inp);

  /* vlog ( "validatePort : %s \n" , inp ) ; */ 

  for (int i = 0; i < slen; ++i) {
    if (isdigit(inp[i]))
      continue;
    invalid_port_no = true;
    break;
  }

  if (!invalid_port_no) {
    port_no = atoi(inp);
    if (port_no > 65535 || port_no < 0)
      invalid_port_no = true;
  }

  if (invalid_port_no) {
    fprintf(stderr, "Invalid port.\n");
    exit(EXIT_FAILURE);
  }

  return (unsigned short int) port_no;
}

unsigned short int
allPorts (const char *inp) 
{
  int ch = ',' ; 
  char *position1 , *position2 ; 
  char inpbuffer[256] ; 

  strcpy ( inpbuffer , inp ) ; 
  position1 = (char*)inpbuffer ; 
  if ( strchr ( position1 , ch ) == NULL ) 
      allports[maxports] = validatePort ( position1 ) ; 
    else {
      while ( ( position2 = strchr ( position1 , ch ) ) != NULL ) { 
          strncpy ( position2 , "\x00" , 1 ) ; 
          allports[maxports] = validatePort ( position1 ) ; 
          position1 = ++position2 ; 
          maxports++ ; 
          if ( maxports >= MAXPORT ) {
            fprintf(stderr, "Invalid number of ports, maximum is %d \n", MAXPORT );
            exit(EXIT_FAILURE);
          }
      } ; 
    allports[maxports] = validatePort ( position1 ) ; 
  } ; 

  /* printf ( "allPorts : maxports %d \n" , maxports ) ; */ 
  return ( (unsigned short int)allports[0] ) ; 
} 

/**
 * Validate the input and populate the hostname string. Also perform a DNS lookup of the given
 * hostname and populate host_addr.
 * @returns     true if the hostname is valid and exists. false otherwise.
*/
bool
validateHostname (const char *inp, char hostname[HOSTNAME_BUFFER_LENGTH],
                  unsigned short int port, struct sockaddr_in *host_addr)
{
  if (strlen(inp) > HOSTNAME_BUFFER_LENGTH)
    return false;

  memset(hostname, (int)'\0', HOSTNAME_BUFFER_LENGTH);
  strncpy(hostname, inp, HOSTNAME_BUFFER_LENGTH-1);

  vlog("Performing hostname lookup... \n");
  resolveHostName(hostname, port, host_addr);

  return true;
}


/**
 * Make sure that the attack time is positive and not longer than 2 minutes.
*/
unsigned int
validateAttackTime (char *inp)
{
  bool invalid = false;
  
  size_t inplen = strlen(inp);
  for (int i = 0; i < inplen; ++i) {
    if (!isdigit(inp[i])) {
      invalid = true;
      break;
    }
  }

  int attack_time = atoi(inp);
  if (attack_time > 120)
    invalid = true;

  if (invalid) { 
    fprintf(stderr, "Invalid attack time: %s.\n", inp);
    exit(EXIT_FAILURE);
  }

  return (unsigned int) attack_time;
}


/**
 * Make sure that wait time is positive and not longer than 30 seconds 
*/
unsigned int
validateWaitTime (char *inp)
{
  bool invalid = false;
  
  size_t inplen = strlen(inp);
  for (int i = 0; i < inplen; ++i) {
    if (!isdigit(inp[i])) {
      invalid = true;
      break;
    }
  }

  int wait_time = atoi(inp);
  if (wait_time > 30)
    invalid = true;

  if (invalid) { 
    fprintf(stderr, "Invalid wait time: %s.\n", inp);
    exit(EXIT_FAILURE);
  }

  return (unsigned int) wait_time;
}


/**
 * Make sure that loop count is positive and not bigger than 1000000
 */
unsigned int
validateLoopCount (char *inp)
{
  bool invalid = false;
  
  size_t inplen = strlen(inp);
  for (int i = 0; i < inplen; ++i) {
    if (!isdigit(inp[i])) {
      invalid = true;
      break;
    }
  }

  int loop_count = atoi(inp);
  if ( loop_count > 1000000 )
    invalid = true;

  if (invalid) { 
    fprintf(stderr, "Invalid loop count : %s. Use option -t for longer attacks \n", inp);
    exit(EXIT_FAILURE);
  }

  return (unsigned int) loop_count ; 
}


/**
 * Parse the command line options and represent them in a way we can manipulate and use.
*/
void
getOptions (int argc, char *argv[], char hostname[HOSTNAME_BUFFER_LENGTH],
            unsigned short int *port, struct sockaddr_in *host_addr,
            unsigned int *attack_time, unsigned int *wait_time , unsigned int *loop_count )

{
  /* printf ( "verbose %d \n" , verbose ) ; */ 
  vlog ( "getOptions \n" ) ;
  int opt = 0;
  char *hostname_placeholder;
  bool hostname_initialized = false, port_initialized = false,
       attack_time_initialized = false ,
       wait_time_initialized = false , loop_count_initialized = false ; 

  *attack_time = DEFAULT_ATTACK_TIME;
  *wait_time = DEFAULT_WAIT_TIME;
  *loop_count = DEFAULT_LOOP_COUNT; 

  struct option option_array[] = {
      {"help", no_argument, NULL, (int) 'H'},
      {"hostname", required_argument, NULL, (int) 'h'},
      {"port", required_argument, NULL,  (int) 'p'},
      {"verbose", no_argument, NULL, (int) 'v'},
      {"attack-time", required_argument, NULL,  (int) 't'},
      {"enable-sniffer", no_argument, NULL, (int) 's'},
      {"enable-spoofing", no_argument, NULL, (int) 'e'},
      {"wait-time", required_argument, NULL, (int) 'w'},
      {"loop-count", required_argument, NULL, (int) 'c'},
      {"class-c-network-spoofing", no_argument, NULL, (int) 'n'},
      {0, 0, 0, 0}
  };

  /* for those options without an argument add an "x" */ 
  char *short_opts = "h:p:vx:t:w:c:nx:sx:ex:";

  opt = getopt_long(argc, argv, short_opts, option_array, NULL);
  while (opt != -1) {
    /* -v must be the first option */ 
    /* vlog ( "opt: %d %c %s \n" , opt , (char)opt , optarg ) ; */ 
    switch (opt) {
      case 'h':
        hostname_placeholder = optarg;
        hostname_initialized = true;
        /* vlog ( "hostname_placeholder %s \n" , hostname_placeholder ) ;  */ 
        break;

      case 'p':
        *port = allPorts(optarg);
        port_initialized = true;
	strcpy ( portlist , optarg ) ; 
	/* vlog ( "portlist  %s \n" , portlist ) ; */ 
        break;

      case 'v':
        verbose = true;
        break;

      case 't':
        *attack_time = validateAttackTime(optarg);
        attack_time_initialized = true;
        enable_attack_time = true ; 
        break;

      case 'w':
        *wait_time = validateWaitTime(optarg);
        wait_time_initialized = true;
        enable_wait_time = true ; 
        break;

      case 'c':
        *loop_count = validateLoopCount(optarg);
        loop_count_initialized = true;
        enable_loop_count = true ; 
        break;

      case 's':
        enable_sniffer = true;
        break;

      case 'n':
        enable_classc = true;
        break;

      case 'e':
        enable_spoofing = true;
        break;

      case 'H':
        fprintf(stderr, "%s", usage_message);
        exit(EXIT_SUCCESS);

      default:
        fprintf(stderr, "%s", usage_message);
        exit(EXIT_FAILURE);
    }
    opt = getopt_long(argc, argv, short_opts, option_array, NULL);
  }

  if (!(wait_time_initialized )) {
    vlog ( "wait_time is not initialized \n" ) ; 
  } 
  if (!(attack_time_initialized )) {
    vlog ( "attack_time is not initialized \n" ) ; 
  } 
  if (!(loop_count_initialized )) {
    vlog ( "loop_count is not initialized \n" ) ; 
  } 

  if (!(hostname_initialized && port_initialized )) {
      fprintf(stderr, "%s", usage_message);
      exit(EXIT_FAILURE);
  }

  if (!validateHostname(hostname_placeholder, hostname, *port, host_addr)) {
    fprintf(stderr, "Invalid hostname.\n");
    exit(EXIT_FAILURE);
  }

  return;
}

