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
using namespace std;

#include "ipk-sniffer.h"

/**
 * @brief Main function responsible for running program
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char* argv[]){

    /**
     * @brief Set packet counter to default 0 to work properly
     * 
     */
    packet_counter = 0;

    /**
     * @brief Checking argument validity and proccessing them
     * 
     */
    int check = ArgCheck(argc, argv);

    /**
     * @brief If argument check failed
     * 
     */
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

    /**
     * @brief Check if interface specified in -i/--interface argument is valid
     * 
     */
    check = CheckInterface();
    if(check == -1){
        return EX_NON_EXISTING_INTERFACE;
    }

    /**
     * @brief Creates PCAP capturing device, sets filter and if done correctly,
     * set up signals to handle interrups and starts sniffing
     * 
     */
    socket_glob = CreateSocket();
    if(socket_glob == NULL){
        return EX_NON_EXISTING_INTERFACE;
    }else{
        signal(SIGINT, MrProper);
        signal(SIGTERM, MrProper);
        signal(SIGQUIT, MrProper);
        check = Sniff(socket_glob);
        if(check == -1){
            return EX_SNIFF_ERR;
        }
    }

    /**
     * @brief Close and free all resources after sniffing is done
     * 
     */
    if(!freed)
        MrProper(0);

    /**
     * @brief Exits program
     * 
     */
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

                if(params_data.i_flag > 0){
                    printf(SNIFF "ERR - Repeating -i or --interface argument! \n");
                    print_help();
                    return(-1);
                }
                params_data.i_flag++;
                break;
            /**
             * @brief -p argument, port number
             * 
             */
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
            /**
             * @brief --tcp argument, TCP sniffing
             * 
             */
            case 't':
                params_data.tcp_flag++;
                if(params_data.filter.empty())
                    params_data.filter.append("tcp ");
                else
                    params_data.filter.append("or tcp ");
                break;
            /**
             * @brief --udp argument, UDP sniffing
             * 
             */
            case 'u':
                params_data.udp_flag++;
                if(params_data.filter.empty())
                    params_data.filter.append("udp ");
                else
                    params_data.filter.append("or udp ");
                break;
            /**
             * @brief --arp argument, ARP sniffing
             * 
             */
            case 'a':
                params_data.arp_flag++;
                if(params_data.filter.empty())
                    params_data.filter.append("arp ");
                else
                    params_data.filter.append("or arp ");
                break;
            /**
             * @brief --icmp argument, ICMP sniffing
             * 
             */
            case 'c':
                params_data.icmp_flag++;
                if(params_data.filter.empty())
                    params_data.filter.append("icmp ");
                else
                    params_data.filter.append("or icmp ");
                break;
            /**
             * @brief -n argument, number of frame sto capture
             * 
             */
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

            /**
             * @brief Wrong argument format given
             * 
             */
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

    /**
     * @brief Argument not valid
     * 
     */
    if (optind < argc) {
        printf(SNIFF "Invalid argument given: ");
        while (optind < argc)
            printf("%s \n", argv[optind++]);
        print_help();
        return(-1);
    }

    /**
     * @brief if port number is set, add to PCAP filter string
     * 
     */
    if(params_data.p_value != -1){
        std::string str = to_string(params_data.p_value);
        if(params_data.filter.empty())
            params_data.filter.append("port ");
        else
            params_data.filter.append("and port ");     
        params_data.filter.append(str);
    }
    // if all ports are to be scanned
    else{ 
        if(params_data.filter.empty())
            params_data.filter.append("portrange 1-65535  ");
        else if(params_data.icmp_flag != 0){            // port range does not work with icmp filter
            params_data.filter.append("");
        }     
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

    /**
     * @brief checks every interface and chooses the right one
     * 
     */
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
    pcap_freealldevs(alldevsp);

    std::cout << SNIFF "Checking argument validity [OK] \n";
    return 0;
}

pcap_t* CreateSocket(){

    std::cout << SNIFF "Opening a PCAP device for capturing... \n";

    /**
     * @brief Converts string to char* because PCAP needs char*
     * 
     */
    const char *interface_char = params_data.i_value.c_str();

    /**
     * @brief to store PCAP data
     * 
     */
    pcap_t* data_stream;

    /**
     * @brief Opens PCAP file to pass data from NIC to kernel
     * @brief errbuf has error message
     */
    data_stream = pcap_open_live(interface_char, BUFSIZ, true, 1000, errbuf);
    if( data_stream == NULL){
        std::cout << SNIFF "Opening a PCAP device for capturing [ERR] \n";
        std::cout << SNIFF "PCAP error buffer is: " << errbuf <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Opening a PCAP device for capturing [OK] \n";
    std::cout << SNIFF "Getting a PCAP device address for capturing... \n";

    bpf_u_int32 mask;
    bpf_u_int32 ip_add;
    /**
     * @brief Tries to get device adress and subnet mask which is needed for filter setup
     * 
     */
    int lookup = pcap_lookupnet(interface_char, &ip_add, &mask, errbuf);
    if( lookup == -1 ){
        std::cout << SNIFF "Getting a PCAP device address for capturing [ERR] \n";
        std::cout << SNIFF "PCAP error buffer is: " << errbuf <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Getting a PCAP device address for capturing [OK] \n";
    std::cout << SNIFF "Preparing up a PCAP filter... \n";

    /**
     * @brief Converting filter string (ease of use) to char* (needed by PCAP)
     * 
     */
    const char *filter = params_data.filter.c_str();

    struct bpf_program program;
    /**
     * @brief Setting up the packet filter
     * 
     */
    int comp = pcap_compile(data_stream, &program, filter, 0, mask);
    if (comp == -1){
        char *err = pcap_geterr(data_stream);
        std::cout << SNIFF "Preparing a PCAP filter [ERR] \n";
        std::cout << SNIFF "PCAP filter is: " << filter << "\n";
        std::cout << SNIFF "PCAP error message is: " << err <<"\n";
        return NULL;
    }
    std::cout << SNIFF "PCAP filter is: " << filter << "\n";
    std::cout << SNIFF "Preparing a PCAP filter [OK] \n";
    std::cout << SNIFF "Applying a PCAP filter...\n";

    /**
     * @brief Applying the packet filter
     * 
     */
    int setf = pcap_setfilter(data_stream, &program);
    if( setf == -1 ){
        char *err = pcap_geterr(data_stream);
        std::cout << SNIFF "Applying a PCAP filter [ERR] \n";
        std::cout << SNIFF "PCAP error message is: " << err <<"\n";
        return NULL;
    }

    std::cout << SNIFF "Applying a PCAP filter [OK] \n";

    return data_stream;
}

int Sniff(pcap_t* pcap_stream){

    /**
     * @brief To get the right byte offset for reading packet data it is needed to "skip" L2 header
     * This determines the lenght of L2 header. Values from: https://www.tcpdump.org/linktypes.html and other sources listed below
     * 
     */
    uint8_t data_link_header;
    data_link_header = pcap_datalink(pcap_stream) ;
    if(data_link_header == -1){
        char *err = pcap_geterr(pcap_stream);
        return -1;
    }
    else if(data_link_header == DLT_NULL) {         // 0
            data_link_header_len = 4;               // ... he link layer header is a 4-byte field, ...
    }else if(data_link_header == DLT_EN10MB){       // 1 = ethernet
        data_link_header_len = 14;                  // ethernet always has 14 byte header: https://www.tcpdump.org/pcap.html
    }else if(data_link_header == DLT_LINUX_SLL){    // 113
        data_link_header_len = 16;                  // Linux "cooked" capture encapsulation, 16 bytes: https://linux.die.net/man/7/pcap-linktype
    }else if(data_link_header == DLT_SLIP){         // 8
        data_link_header_len = 16;                  // https://www.tcpdump.org/linktypes/LINKTYPE_SLIP.html
    }else if(data_link_header == DLT_PPP){          // 9
        data_link_header_len = 6;                   // https://cs.wikipedia.org/wiki/Point-to-Point_Protocol
    }else if(data_link_header == DLT_RAW){          // 101
        data_link_header_len = 0;                   // packet begins with IP header
    }else if(data_link_header == DLT_IEEE802_11){   // 105
        data_link_header_len = 24;                  // wifi: https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
    }else{
        std::cout << SNIFF "Wrong link-layer header type: " << data_link_header << "\n";
        return -1;
    }
    
    std::cout << SNIFF "Starting packet proccessing... \n";
    std::cout << SNIFF "Number of packets to capture: " << params_data.num_value <<"\n";

    /**
     * @brief Creates loop in which each packet is proccessed. Loop is executed n (from -n argument) times
     * Every loop doPacket() is called
     */
    int loop = pcap_loop(pcap_stream, params_data.num_value, (pcap_handler)doPacket , 0);
    if( loop == -1){
        char *err = pcap_geterr(pcap_stream);
        std::cout << SNIFF "PCAP packet proccessing [ERR] \n";
        std::cout << SNIFF "PCAP error message is: " << err <<"\n";
        return -1;
    }

    std::cout << SNIFF "=======================\n";
    return 0;
}


void doPacket(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr){

    /**
     * @brief Prints dividing line and packet number
     * 
     */
    std::cout << SNIFF "=======================\n";
    std::cout << SNIFF "This is packet no. " << packet_counter << "\n";
    packet_counter++;
    
    /**
     * @brief Gets current time in RFC3339 format with miliseconds
     * 
     */
    std::string current_time = GetCurrentTimeRFC3339();
    if( current_time == "-1"){
        std::cout << SNIFF "Time reading [ERR] \n";
        MrProper(10);
        exit(-1);
    }else{
        if (current_time.size() > 0){
            current_time.resize(current_time.size() - 1);
        }
    }

    /**
     * @brief Skips L2 header of frame to get packet data
     * 
     */
    u_char* parse_pkt = packetptr + data_link_header_len;

    /**
     * @brief if ARP, proccess here, because it is L2 protocol
     * taken from https://github.com/lsanotes/libpcap-tutorial/blob/master/arpsniffer.c
     * Modified by xzbori20
     */
    struct ether_header *eptr;
    eptr = (struct ether_header *) packetptr;
    /**
     * @brief If l2 protocol is ARP
     * 
     */
    if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        arphdr *arpheader = (struct arphdr *)(packetptr+14);
        int i = 0;
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 

            std::string src_mac = "";
            std::string dest_mac = "";
            char *buffer_char = (char*)malloc(sizeof(char)*6);
            /**
             * @brief Fill src_mac string with data from frame
             * 
             */
            for(i=0; i<6;i++){
                snprintf(buffer_char, sizeof(char)*6, "%02X.",arpheader->sha[i]);
                src_mac.append(buffer_char);
            }
            /**
             * @brief Fill dest_mac string with data from frame
             * 
             */
            for(i=0; i<6;i++){
                snprintf(buffer_char, sizeof(char)*6, "%02X:", arpheader->tha[i]); 
                dest_mac.append(buffer_char);
            }

            /**
             * @brief Write main data line to standard output
             * 
             */
            std::cout << SNIFF "Protocol: ARP \n";
            std::cout << SNIFF << current_time << src_mac << " : " << "" << " > " <<  dest_mac << " : " << "" << " , length " << packethdr->len << " bytes\n";

            /**
             * @brief Set pointer to start of frame for output of all data
             * 
             */
            const u_char * payload = (u_char *)(parse_pkt - 14); // 14 is ethernet header length

            /**
             * @brief Prints data in HEX and ASCII
             * 
             */
            print_payload(payload, packethdr->len);
        }
        return;
    }
    
    /**
     * @brief Lenght of packet/frame
     * 
     */
    int pkt_len = packethdr->len;

    struct ip* iphdr;
    struct ip6* ip6hdr;

    const struct sniff_ip *ip;
    ip = (struct sniff_ip*)(packetptr + 14); // 14 is ethernet header size
    int size_ip = IP_HL(ip)*4;

    /**
     * @brief Gets IPv4 addresses from packet
     * 
     */
    iphdr = (struct ip *) parse_pkt;
    std::string ip_src = inet_ntoa(iphdr->ip_src);
    std::string ip_dst = inet_ntoa(iphdr->ip_dst);


    /**
     * @brief For storing port numbers 
     * 
     */
    int src_port = -1;
    int dest_port = -1;
    int proto = -1;

    /**
     * @brief Sets pointer after L2 header and gets port numbers 
     * 
     */
    parse_pkt = packetptr + data_link_header_len;
    parse_pkt += 4 * iphdr->ip_hl;
    struct tcphdr* tcphead;
    tcphead = (struct tcphdr *) parse_pkt;
    src_port = ntohs(tcphead->source);
    dest_port = ntohs(tcphead->dest);

    /**
     * ==============================================================================================================
     * @brief This section is taken from https://www.tcpdump.org/sniffex.c
     * My own modifications have been made.
     * 
     */

    /**
     *  Determine which protocol is used
     *   
     */
	switch(iphdr->ip_p) {
		case IPPROTO_TCP:
            proto = 0;
			break;
		case IPPROTO_UDP:
            proto = 1;
			break;
		case IPPROTO_ICMP:
            proto = 2;
			break;
		case IPPROTO_IP:
            proto = 3;
			break;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

    /* define/compute tcp header offset */
    if(proto == 0){     // TCP
        struct sniff_tcp* tcp = (struct sniff_tcp*)(parse_pkt + 14 + size_ip);      // ethernet size is 14
        int size_tcp = TH_OFF(tcp)*4;
        // if (size_tcp < 20) {
        //     std::cout << SNIFF "   * Invalid TCP header length: " << size_tcp << " bytes\n";
        //     return;
        // }

        /* define/compute tcp payload (segment) offset */
        const u_char * payload = (u_char *)(parse_pkt - 14 - 20);

        /* compute tcp payload (segment) size */
        int size_payload = pkt_len;

        std::cout << SNIFF "Protocol: TCP \n";
        std::cout << SNIFF << current_time << ip_src << " : " << "" << " > " << ip_dst << " : " << "" << " , length " << pkt_len << " bytes\n";

        /**
        * Print payload data; it might be binary, so don't just
        * treat it as a string.
        */
        if (size_payload > 0) {
            //printf("   Payload (%d bytes):\n", size_payload);
            print_payload(payload, size_payload);
        }
    }
    // END OF TAKEN SECTION ==============================================================================================================

    /**
     * @brief If protocol used is UDP
     * 
     */
    else if(proto == 1){ 

        /**
         * @brief Sets pointer to start of frame for HEX and ASCII output
         * 
         */
        const u_char * payload_udp = (u_char *)(parse_pkt - 14 - size_ip);  // 14 - ethernet header size

        /**
         * @brief Write main data line to standard output
         * 
         */
        std::cout << SNIFF "Protocol: UDP \n";
        std::cout << SNIFF << current_time << ip_src << " : " << src_port << " > " << ip_dst << " : " << dest_port << " , length " << pkt_len << " bytes\n";

        /**
         * @brief Prints data in HEX and ASCII
         * 
         */
        if (pkt_len > 0) {
            print_payload(payload_udp, pkt_len);
        }
    }

    else if(proto == 2){     // ICMP

        /**
         * @brief Sets pointer to start of frame for HEX and ASCII output
         * 
         */
        const u_char * payload = (u_char *)(parse_pkt - 14 - size_ip);  // 14 - ethernet header size

        /**
         * @brief Payload size is size of whole frame
         * 
         */
        int size_payload = pkt_len;       

        std::cout << SNIFF "Protocol: ICMP \n";
        std::cout << SNIFF << current_time << ip_src << " : " << src_port << " > " << ip_dst << " : " << dest_port << " , length " << pkt_len << " bytes\n";


        /**
         * @brief Prints data in HEX and ASCII
         * 
         */
        if (size_payload > 0) {
            print_payload(payload, size_payload);
        }
      
    }
    
    return;
}

void MrProper(int signum){
    std::cout << SNIFF "Running Mr. Proper! \n";

    /**
     * @brief Close PCAP files
     * 
     */
    pcap_breakloop(socket_glob);
    pcap_close(socket_glob);

    freed = true;

    std::cout << SNIFF "Exiting program! \n";
    exit(signum);
}

string GetCurrentTimeRFC3339(){
    // Taken from https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc
    // By user https://gist.github.com/jedisct1
    // Modified to show miliseconds
    const int8_t TIME_SIZE = 50;
    char* time_val = (char *)malloc(TIME_SIZE);
    time_t now = time(NULL);
    struct tm *tm;
    int off_sign;
    int off;
    struct timeval tv;              // for miliseconds
    gettimeofday(&tv, NULL); 

    if ((tm = localtime(&now)) == NULL) {
        return "-1";
    }
    off_sign = '+';
    off = (int) tm->tm_gmtoff;
    if (tm->tm_gmtoff < 0) {
        off_sign = '-';
        off = -off;
    }
    /**
     * @brief prints formated timestamp into variable time_val
     * 
     */
    snprintf(time_val, TIME_SIZE, "%d-%d-%dT%02d:%02d:%02d.%.3ld%c%02d:%02d \n",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec/1000,
           off_sign, off / 3600, off % 3600);

    /**
     * @brief Converts time data stored in char* to C++ string for future easier manipulation
     * 
     * @return std::string 
     */
    std::string to_ret(time_val);
    return to_ret;
}

// --------------- |||| ------------------------------------ |||| --------------- //
// --------------- VVVV CODE TAKEN FROM OTHERS SECTION BELOW VVVV --------------- //

/**
 * @brief Function for printing packet data
 * @brief Taken from https://www.tcpdump.org/sniffex.c
 * @param payload 
 * @param len 
 * @param offset 
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset){

	int i;
	int gap;
	const u_char *ch;

	/* offset */
    std::cout << SNIFF;
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

    return;
}

/**
 * @brief Prints packet data ascii lines
 * @brief Taken from https://www.tcpdump.org/sniffex.c
 * 
 * @param payload 
 * @param len 
 */
void print_payload(const u_char *payload, int len){

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

    return;
}