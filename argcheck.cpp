/**
 * @file argcheck.cpp
 * @author xzbori20 Jan Zboril
 * @brief Used for checking input arguments
 * @version 0.1
 * @date 2021-03-31
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <iostream>

#include "argcheck.h"

using namespace Checker;
using namespace std;

int check_cls::argcheck(int argc, char* argv[]){
 
    while (1){
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        params_data.param = getopt_long (argc, argv, "hip:tun:", Checker::long_options, &option_index);
        if (params_data.param == -1)
            break;
        const char *tmp_optarg = optarg;
        switch(params_data.param){
            case 'i' :
                printf("jesm v i \n");
                printf("i je : %s \n", optarg);

                /**
                 * @brief Převzato https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
                 * @brief Od uživatele https://stackoverflow.com/users/1853939/haystack
                 * 
                 */
                if(!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0]){
                    params_data.i_value = argv[optind++];
                }
                std::cout << "novy opt " << (char*)params_data.i_value << "\n";
                if(params_data.i_flag > 0){
                    printf(SNIFF "ERR - Repeating -i or --interface argument!");
                    check_cls::print_help();
                    return(-1);
                }
                params_data.i_flag++;
                break;
            case 'p':
                printf("jesm v p \n");
                printf("p je : %s \n", optarg);
                if(params_data.p_flag > 0){
                    printf(SNIFF "ERR - Repeating -p argument!");
                }
                params_data.p_value = atoi(optarg);
                if (params_data.p_value <= 0){
                    printf(SNIFF "ERR - -p argument cannot be without positive integer value");
                    check_cls::print_help();
                    return(-1);
                }
                printf("PVALUE je int s hodnotou: %d \n", params_data.p_value);
                params_data.p_flag++;
                break;
            case 't':
                printf("jesm v tcp \n");
                params_data.tcp_flag++;
                break;
            case 'u':
                printf("jesm v udp \n");
                params_data.udp_flag++;
                break;
            case 'arp':
                printf("jesm v arp \n");
                params_data.arp_flag++;
                break;
            case 'icmp':
                printf("jesm v icmp \n");
                params_data.icmp_flag++;
                break;
            case 'n':
                printf("jesm v num \n");
                printf("n je : %s \n", optarg);
                if(params_data.num_flag > 0){
                    printf(SNIFF "ERR - Repeating -n argument!");
                    check_cls::print_help();
                    return(-1);
                }
                params_data.num_flag++;
                break;

            case '?':
            case ':':
            case 0 :
                if (optopt == 'p' || optopt == 'n')
                    printf("ERR ... Option -%c requires an argument.\n" );
                else if(optopt == 'i' && isprint(optopt))
                {
                    printf("OK ... option '-i' without argument \n");
                    break;
                }
                else if (isprint (optopt))
                    printf ("ERR ... Unknown option `-%c'.\n", optopt);
                else
                    printf ("ERR ... Unknown option character `\\x%x'.\n", optopt);
                return -1;

            case 'h' :
            default:
                check_cls::print_help();
                return(-1);
                break;
        }
    }

    if (optind < argc) {
        printf("Invalid argument given: ");
        while (optind < argc)
            printf("%s \n", argv[optind++]);
        check_cls::print_help();
        check_cls::print_help();
        return(-1);
    }

    return 0;
}