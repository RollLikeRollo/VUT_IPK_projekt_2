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

#ifndef IPK_SNIFFER_H
#define IPK_SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string>
#include <iostream>
#include <pcap.h>
#include <libnet.h>

#define SNIFF "#:Sniffer>> "

#define EX_WRITE_INTERFACE 2
#define EX_NON_EXISTING_INTERFACE 3
#define EX_SOCKET_NUMBER 4

using namespace std;


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
 * @brief for PCAP
 * 
 */
char errbuf[PCAP_ERRBUF_SIZE];


/**
 * @brief Struct for storing parsed arguments data
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
 * @brief 
 * 
 * @return int 
 */
int WriteInterface();

/**
 * @brief 
 * 
 * @return int 
 */
int Sniff(pcap_t*);

/**
 * @brief 
 * 
 * @return void 
 */
void MrCleaner( int signum );

/**
 * @brief 
 * 
 * @return int 
 */
int CheckInterface();

/**
 * @brief Create a Socket object
 * 
 * @param interface 
 * @return pcap_t* 
 */
pcap_t* CreateSocket();

/**
 * @brief 
 * 
 */
void do_packet(u_char *, struct pcap_pkthdr *, u_char *);

#endif