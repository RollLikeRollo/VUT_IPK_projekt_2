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
using namespace Checker;

/**
 * @brief Main function responsible for running program
 * 
 * @param argc 
 * @param argv 
 * @return int 
 */
int main(int argc, char* argv[]){

    printf("start main \n");
    printf("%s \n", argv[1]);
  
    check_cls check_cls_inst;
    int check = check_cls_inst.argcheck(argc, argv);
    if(check != 0){
        return check;
    }

    std::string s0 ("Initial string");

    std::cout << "strih je :" << s0 << "\n" ;

    s0.append("konec");
    std::cout << "strih je :" << s0 << "\n" ;

   
    return 0;
}



