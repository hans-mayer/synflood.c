# synflood.c

This is a fork from https://github.com/Hypro999/synflood.c 

Actually this program does not really do an attack as it sends immediately after SYN a RESET.
Therefore there are not so many half opened TCP sessions. 
But it's ok for learning purposes. 

-------------

A TCP SYN Flooding tool written in C for Unix-based systems.

SYN Flooding is a type of DOS (Denial-of-Service) attack which exploits the
first part of the handshake to establish a new TCP connection. Since we are
exploing a network protocol here, this attack can be classified as a
"Protocol Attack".

At a high level, how this works is that we craft our own TCP SYN packets and
then completely flood a server with them. When we send a SYN packet, the
server will respond with a SYN-ACK and allocate some memory in the kernel
buffer in an attempt to set up a new connection with us (at this point the
connection is "half open" which is why the SYN Flooding Attack is also
known as the "Half Open Attack"). The half open connections can be seen on
the server side with `netstat -nat | grep "SYN_RECV"`. By sending multiple
SYNs per second, we can try to get the server to exhaust it's memory and thus
make it to be unable to serve legitimate clients.

To drive an important point home - this DOS attack exhausts a server's memory
and not necessarily bandwidth (which other attacks like ICMP/Ping Flooding do).

**Disclaimer:** This tool is definitely not to be used on targets
that you do not have explicit consent to attack!


## Dependencies
This code was tested on the following platform:
- **OS:** Debian 12.9 bookworm 
- **Kernel:** 6.1.123-1
- **Compiler:** gcc version 12.2.0 (Debian 12.2.0-14) 
- **Linker:** GNU ld (GNU Binutils for Ubuntu) 2.40
- **libpcap:** v 1.10.3-1 


## Direct Installation
On Debian:
```bash
git clone https://github.com/hans-mayer/synflood.c synflood/ 
cd synflood/
make
```

Now the binary will be created and placed in `bin/synflood` (inside the
directory created for the cloned repository - not to be confused with
Linux's `/bin` directory).

For a more "global installation" do one of the following:
- Add the path to the binary to the `$PATH` environment variable (recommended).
- Copy the binary to `/usr/bin` (not recommended).
- Create a soft link to the binary with `ln -s`.


## Usage
This binary needs to be run as a superuser. This is because to craft and send
our own custom TCP SYN packets we need to use raw sockets (see raw(7)) and
raw sockets can only be created by a superuser.

NOTE: Technically any user with the `CAP_NET_RAW` capability can create raw
sockets, so in that sense a superuser isn't exactly needed. But a more
thorough explanation of this is beyond the scope of this README - read
capabilities(7) if you're really interested.

```
Usage: [sudo] synflood [REQUIRED PARAMETERS] [OPTIONAL PARAMETERS]

Required parameters:
-h, --hostname
    The hostname of the target to attack. Only use hostnames of TCP servers
    that are available to your default network interface (usually wlo1 or
    eth0) and that you either directly own or have explicit permission to
    attack. We expect the hostname to resolve to an IPv4 address.
    Because we use wlo1/eth0 you can't use any loopback interface hostnames
    to directly synflood yourself.

-p, --port
    The port number that you want to attack. Can be any valid TCP port that's
    open on the server. For example, aim for webservers (80/443) or SSH (22).

Optional parameters:

-t, --attack-time
    The number of seconds to launch the attack for. Must be a positive integer
    less than 120 (seconds) this is done for your own (and the target)
    network's safety. We just want to demonstrate synflooding here and not
    cause any serious damage lasting longer than a short while (plus 2 minutes
    should actually be enough to take down most test servers).
-v
    Enable verbose mode (recommended).

-s --enable-sniffer
    Enable the packet sniffer. We use libpcap and a child process to manage
    sniffing only the packets we're interested in. If verbose mode is enabled
    you'll be able to see the exact packet capture filter being employed.

-n --class-c-network-spoofing
    It enables random IPv4 address out of the range where the host is located.
    If the host is within a supernet of class C it will only take 256 IP addresses 
    for the spoofed host part. It doesn't care about the real notwork boundaries. 

-e --enable-spoofing
    Enable random IPv4 address spoofing. Not recommended since more often
    than not these packets would be dropped by the network at some point
    or the other. For example, all major VPS providers will block outgoing
    packets with spoofed ip addresses. Even incoming spoofed packets can
    potentially be detected and dropped. This is done for the general good
    of the internet. Note: the spoofer is currently not perfect and does
    not take into consideration special or reserved addresses. It's
    completely random.

-c, --loop-count
    run synflood for a well defined number 

-w, --wait-time
    wait seconds before and after synflood 
    values between 0 and 30 
    0 means no wait time 
    default value is 2 seconds  

```
