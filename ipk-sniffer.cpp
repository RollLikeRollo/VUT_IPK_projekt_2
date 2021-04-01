/**
 * @file ipk-sniffer.cpp
 * @author xzbori20 Jan Zboril
 * @brief simple packet sniffer for IPK at Brno University of Technology, Faculty of IT
 * @version 0.1
 * @date 2021-03-31
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "ipk-sniffer.h"
#include <iostream>
#include <string>
#include <pcap.h>
#include <libnet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <signal.h>

       
using namespace std;

/**
 * @brief Main function responsible for running program
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char* argv[]){

    //int check = check_cls_inst.argcheck(argc, argv, p);
    int check = ArgCheck(argc, argv);

    // if check failed    
    if(check != 0){
        std::cout << SNIFF "Check arguments [ERR] \n";
        return check;
    }else{
        if(params_data.i_value == "-1"){
            check = WriteInterface();
            return EX_WRITE_INTERFACE;
        }else{
            std::cout << SNIFF "Check arguments [OK] \n";
        }
    }

    
    check = CheckInterface();
    if(check == -1){
        return EX_NON_EXISTING_INTERFACE;
    }

    

    pcap_t *socket = CreateSocket();
    if(socket == NULL){
        return EX_NON_EXISTING_INTERFACE;
    }else{
        signal(SIGTERM, MrCleaner);
        signal(SIGINT, MrCleaner);
        signal(SIGQUIT, MrCleaner);
        Sniff(socket);
    }

    MrCleaner(10);

   return 0;
}

int ArgCheck(int argc, char* argv[]){

    std::cout << SNIFF "Checking arguments... \n";
 
    /**
     * @brief Taken from getopt(3) — Linux manual page, https://man7.org/linux/man-pages/man3/getopt.3.html
     * 
     */
    while (1){
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        params_data.param = getopt_long (argc, argv, "hip:tun:", long_options, &option_index);
        if (params_data.param  == -1)
            break;
        const char *tmp_optarg = optarg;
        switch(params_data.param ){
            case 'i' :
                /**
                 * @brief FROM https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
                 * @brief MADE BY https://stackoverflow.com/users/1853939/haystack
                 * 
                 */
                if(!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0]){
                    params_data.i_value = argv[optind++];
                }

                if(params_data.i_value.empty()){
                     params_data.i_value = "-1";
                }
                    //std::cout << "novy opt " << params_data.i_value << endl;
                if(params_data.i_flag > 0){
                    printf(SNIFF "ERR - Repeating -i or --interface argument! \n");
                    print_help();
                    return(-1);
                }
                params_data.i_flag++;
                break;
            case 'p':
                if(params_data.p_flag > 0){
                    printf(SNIFF "ERR - Repeating -p argument! \n");
                }
                params_data.p_value = atoi(optarg);
                if (params_data.p_value <= 0){
                    printf(SNIFF "ERR - -p argument cannot be without positive integer value! \n");
                    print_help();
                    return(-1);
                }
                params_data.p_flag++;
                break;
            case 't': //tcp
                params_data.tcp_flag++;
                params_data.filter.append("tcp ");
                break;
            case 'u': //udp
                params_data.udp_flag++;
                params_data.filter.append("udp ");
                break;
            case 'a': //arp
                params_data.arp_flag++;
                params_data.filter.append("arp ");
                break;
            case 'c': //icmp
                params_data.icmp_flag++;
                params_data.filter.append("ether ");
                break;
            case 'n':
                params_data.num_value = atoi(optarg);
                if (params_data.num_value <= 0){
                    printf(SNIFF "ERR - -n argument cannot be without positive integer value! \n");
                    print_help();
                    return(-1);
                }
                
                if(params_data.num_flag > 0){
                    printf(SNIFF "ERR - Repeating -n argument!");
                    print_help();
                    return(-1);
                }
                params_data.num_flag++;
                break;

            case '?':
            case ':':
            case 0 :
                if (optopt == 'p' || optopt == 'n')
                    printf(SNIFF "ERR ... Option -%d requires an argument.\n", optopt );
                else if(optopt == 'i' && isprint(optopt))
                {
                    printf(SNIFF "OK ... option '-i' without argument \n");
                    break;
                }
                else if (isprint (optopt))
                    printf (SNIFF "ERR ... Unknown option `-%c'.\n", optopt);
                else
                    printf (SNIFF "ERR ... Unknown option character `\\x%x'.\n", optopt);
                return 0;

            case 'h' :
            default:
                print_help();
                return(0);
                break;
        }
    }

    if (optind < argc) {
        printf(SNIFF "Invalid argument given: ");
        while (optind < argc)
            printf("%s \n", argv[optind++]);
        print_help();
        return(-1);
    }

    // if port number is set
    if(params_data.p_value != -1){
        std::string str = to_string(params_data.p_value);
        params_data.filter.append("port ");
        params_data.filter.append(str);
    }else{ // if all ports are to be scanned
        params_data.filter.append("portrange 1-65535 ");
    }

    return 0;
}

int WriteInterface(){
    pcap_if**  alldevsp;
    int i = pcap_findalldevs(alldevsp, errbuf);
    std::cout << SNIFF "List of all interfaces: \n";
    pcap_if* j = alldevsp[0];
    int c = 0;
    while( j->next != NULL){
        // WRONG FLAGS ??? Differrnt from documentation
        // std::cout << std::dec <<j->flags << "\n";
        if(j->flags == PCAP_IF_UP){
            printf("up \n");
        }
        std::cout << SNIFF "Interface n. " << c << " is: " << j->name << "\n";
        if(j->description != NULL){
            std::cout << SNIFF "        " <<j->description << "\n";
        }
        j = j->next;
        c++;
    }
    pcap_freealldevs(j);

    return 0;
}

int CheckInterface(){

    std::cout << SNIFF "Checking argument validity... \n";

    std::string interface = params_data.i_value;

    pcap_if*  alldevsp;
    int i = pcap_findalldevs(&alldevsp, errbuf);
    pcap_if_t* j = alldevsp;
    int c = 0;
    bool exists = false;
    while( j->next != NULL){
        std::string str = j->name;
        if(str == interface){
            exists = true;
            params_data.i_valid = true;
            break;
        }
        j = j->next;
        c++;
    }
    if(exists == false){
        std::cout << SNIFF "Given interface does not exist! \n";
        std::cout << SNIFF "Checking argument validity [ERR] \n";
        return -1;
    }
    //pcap_freealldevs(j);
    pcap_freealldevs(alldevsp);

    std::cout << SNIFF "Checking argument validity [OK] \n";
    return 0;
}

pcap_t* CreateSocket(){

    std::cout << SNIFF "Opening a PCAP device for capturing... \n";

    // string to char* needed for future use
    const char *interface_char = params_data.i_value.c_str();

    // to store PCAP data
    pcap_t* data_stream;

    // true is to pass data from NIC to kernel
    // errbuf has error message
    data_stream = pcap_open_live(interface_char, BUFSIZ, true, 0, errbuf);
    if( data_stream == NULL){
        std::cout << SNIFF "Opening a PCAP device for capturing [ERR] \n";
        std::cout << SNIFF "PCAP error buffer is: " << errbuf <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Opening a PCAP device for capturing [OK] \n";
    std::cout << SNIFF "Getting a PCAP device address for capturing... \n";

    bpf_u_int32 mask;
    bpf_u_int32 ip_add;
    // This is to get subnet mask which is needed for filter setup
    int lookup = pcap_lookupnet(interface_char, &ip_add, &mask, errbuf);
    if( lookup == -1 ){
        std::cout << SNIFF "Getting a PCAP device address for capturing [ERR] \n";
        std::cout << SNIFF "PCAP error buffer is: " << errbuf <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Getting a PCAP device address for capturing [OK] \n";
    std::cout << SNIFF "Preparing up a PCAP filter... \n";

    // Converting filter string (easier usage) to char* (needed)
    const char *filter = params_data.filter.c_str();
    std::cout << filter <<" \n";

    struct bpf_program program;
    // Setting up the packet filter
    int comp = pcap_compile(data_stream, &program, filter, 0, mask);
    if (comp == -1){
        char *err = pcap_geterr(data_stream);
        std::cout << SNIFF "Preparing a PCAP filter [ERR] \n";
        std::cout << SNIFF "PCAP error message is: " << err <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Preparing a PCAP filter [OK] \n";
    std::cout << SNIFF "Setting up a PCAP filter...\n";

    // Applying the packet filter
    int setf = pcap_setfilter(data_stream, &program);
    if( setf == -1 ){
        char *err = pcap_geterr(data_stream);
        std::cout << SNIFF "Setting up a PCAP filter [ERR] \n";
        std::cout << SNIFF "PCAP error message is: " << err <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Setting up a PCAP filter [OK] \n";

    return data_stream;
}

int Sniff(pcap_t* pcap_stream){
    std::cout << SNIFF "Starting packet proccessing... \n";

    int loop = pcap_loop(pcap_stream, params_data.num_value, (pcap_handler)do_packet , 0);
    if( loop == -1){
        char *err = pcap_geterr(pcap_stream);
        std::cout << SNIFF "PCAP packet proccessing [ERR] \n";
        std::cout << SNIFF "PCAP error message is: " << err <<"\n";
        return -1;
    }

    return 0;
}

void do_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr){
    std::cout <<  "DOING PACKET \n";
    return;
}

void MrCleaner( int signum ){
    std::cout << "MR CLEANER \n";
    return;
}



