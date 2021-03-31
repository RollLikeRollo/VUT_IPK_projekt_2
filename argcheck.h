#ifndef ARGCHECK_H
#define ARGCHECK_H

/**
 * @brief For better looking output
 * 
 */
#define SNIFF "#:Sniffer>> "

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

namespace Checker{
        /**
         * @brief Long option list for argument parsing
         * 
         */
        static struct option const long_options[] = {
                        {"interface",    optional_argument,  0,  'i' },
                        {"tcp",          no_argument,        0,  't' },
                        {"udp",          no_argument,        0,  'u' },
                        {"arp",          no_argument,        0,  'arp'},
                        {"icmp",         no_argument,        0,  'icmp' },
                        {"help",         no_argument,        0,  'h' },
                        {0,              0,                  0,  0 }
                    };

        /**
         * @brief Struct for storing aprsed arguments data
         * 
         */
        struct PARAMS{
            int param = 0;
            int i_flag = 0;
            char *i_value;
            int p_flag = 0;
            int p_value = 0;
            int tcp_flag = 0;
            int udp_flag = 0;
            int arp_flag = 0;
            int icmp_flag = 0;
            int num_flag = 0;
            int option_index = 0;
        };

        static struct PARAMS params_data;
       

        class check_cls{
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
         * @brief 
         * 
         */
        public:
        int argcheck(int argc, char* argv[]);
        };
}

#endif