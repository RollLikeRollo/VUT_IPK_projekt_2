/**
 * @file ipk-sniffer.h
 * @author xzbori20 Jan Zboril
 * @brief  simple packet sniffer for IPK at Brno University of Technology, Faculty of IT
 * @version 0.1
 * @date 2021-03-31
 * 
 * @copyright Copyright (c) 2021
 * 
 */

using namespace std;

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <getopt.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <signal.h>
#include <time.h>
#include <iostream>
#include <string>
#include <libnet.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <ratio>
#include <thread>
#include <arpa/inet.h>          // inet_ntop()
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/**
 * @brief Output beatifier
 * 
 */
#define SNIFF "#:Sniffer>>   "

/**
 * @brief Exit codes
 * 
 */
#define EX_WRITE_INTERFACE 2
#define EX_NON_EXISTING_INTERFACE 3
#define EX_SNIFF_ERR 4


/**
 * @brief Long option list for argument parsing
 * 
 */
static struct option const long_options[] = {
                {"interface",    optional_argument,  0,  'i' },
                {"tcp",          no_argument,        0,  't' },
                {"udp",          no_argument,        0,  'u' },
                {"arp",          no_argument,        0,  'a'},
                {"icmp",         no_argument,        0,  'c' },
                {"help",         no_argument,        0,  'h' },
                {0,              0,                  0,  0 }
            };

/**
 * @brief Data structures from https://www.tcpdump.org/sniffex.c
 * ----------------------------------------------------------------------------------------------
 */
char *dev; 
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;
struct ether_header *eptr;

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
// ----------------------------------------------------------------------------------------------

/* UDP protocol header. */
// https://gist.github.com/schrodyn/7b525b3f2bde93382d3b3c24cc65a358
struct sniff_udp {
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* udp length */
    u_short uh_sum;                 /* udp checksum */
};

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}arphdr_t;

/**
 * @brief These global variables are needed
 * 
 */
bool freed = false;
pcap_t *socket_glob = NULL;
int data_link_header_len = -1;
int packet_counter;

/**
 * @brief for PCAP
 * 
 */
char errbuf[PCAP_ERRBUF_SIZE];

/**
 * @brief Struct for storing parsed arguments data, my own
 * 
 */
struct PARAMS{
int param = 0;
int i_flag = 0;
std::string i_value = "-1";
bool i_valid  = false;
int p_flag = 0;
int p_value = -1;
int tcp_flag = 0;
int udp_flag = 0;
int arp_flag = 0;
int icmp_flag = 0;
int num_flag = 0;
int num_value = 1;
int option_index = 0;
std::string filter = "";
bool first_param = false;
};
static struct PARAMS params_data;

/**
 * @brief  prints help if bad arguments are given
 * 
 * @return void 
 */
void print_help(){
    printf(SNIFF "Usage: \n");
    printf(SNIFF "./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
}

/**
 * @brief Function checking, parsing and string program arguments
 * @return int 0, if ok, -1 if not ok
 * 
 */
int ArgCheck(int, char**);

/**
 * @brief Opens PCAP list of interfacesm, prints them to standard output and closes PCAP list
 * @return int 0
 */
int WriteInterface();

/**
 * @brief Determines length of Layer 2 header, stores it and creates PCAP capture loop with right parametres
 * 
 * @return int 0 if OK
 * @return int -1 if ERR
 */
int Sniff(pcap_t*);

/**
 * @brief Closes all open PCAP files and frees memory before program exit
 * 
 * @return void 
 */
void MrProper(int signum);

/**
 * @brief Check if interface specified in -i/--interface argument is valid
 * 
 * @return int 0 if OK
 * @return int -1 if ERR
 */
int CheckInterface();

/**
 * @brief Sets up capturing device and sets its filter and other params
 *
 * @return pcap_t* NULL if ERR
 * @return pcap_t* Socket for capturing if OK
 */
pcap_t* CreateSocket();

/**
 * @brief Proccess packet data and writes the main line of sniffer, calls functions to print payload data.
 * @brief Handles IPv4 TCP, UDP, ICMP, ARP
 * @brief Output format:  #:Sniffer>> [RFC3339_time] [src_IP] : [src_port] > [dest_IP] : [dest_port] , length [frame_lenth] bytes
 * @brief Output example: #:Sniffer>> 2021-4-11T10:41:07.089+02:00 192.168.0.1 : 59373 > 255.255.255.255 : 7437 , length 215 bytes
 * @return void
 */
void doPacket(u_char *, struct pcap_pkthdr *, u_char *);

/**
 * @brief Get the Current Time object. Taken from https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc
 * @brief By user https://gist.github.com/jedisct1
 * @brief Changed by xzbori20 to proccess miliseconds
 * @return string, RFC3339 time with miliseconds, example: 2021-4-11T10:15:15.153+02:00
 */
string GetCurrentTimeRFC3339();

/**
 * @brief Function for printing packet data
 * @brief Taken from https://www.tcpdump.org/sniffex.c
 */
void print_payload(const u_char *, int);

/** 
 * @brief Prints packet data ascii lines
 * @brief Taken from https://www.tcpdump.org/sniffex.c
 */
void print_hex_ascii_line(const u_char *, int , int );

#endif

/** Next wall of text is placed here due to used code and its licencing.
****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 *
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 *
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 *
 * The Ethernet size is always 14 bytes.
 *
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if
 * you're using structures, you must use structures where the members
 * always have the same size on all platforms, because the sizes of the
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by
 * the protocol specification, not by the way a particular platform's C
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after
 * the beginning of the packet data.  To find the TCP header, look
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 *
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip"
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end
 * of the captured data in the packet - you might, for example, have a
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too
 * small for an IP header.  The length of the captured data is given in
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than
 * the length of the packet, if you're capturing with a snapshot length
 * other than a value >= the maximum packet size.
 * <end of response>
 *
 ****************************************************************************
 */