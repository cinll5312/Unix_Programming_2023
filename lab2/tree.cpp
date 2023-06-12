//g++ tree.cpp -std=c++17 -lstdc++fs -static 
#include <string>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <filesystem>
using recursive_directory_iterator = std::filesystem::recursive_directory_iterator;
int main(int argc, char *argv[]){

    std::string myPath = argv[1];
    std::string s = argv[2];
    std::string ans;
    for (const auto& dirEntry : recursive_directory_iterator(myPath)){
        
        if (dirEntry.is_directory()) {
        }
        else if (dirEntry.is_regular_file()) {
            // fprintf(stderr, dirEntry.path().c_str());
            // fprintf(stderr, "  \n");
            std::ifstream input(dirEntry.path());
            std::string ss;
            while(getline(input,ss)){
                if(ss==s)ans = dirEntry.path().c_str();
                // fprintf(stderr, ss.c_str());
                // fprintf(stderr, "\n");
            }
        }
        
    }
    fprintf(stdout,ans.c_str());
    // fprintf(stderr, ans.c_str());
    // fprintf(stderr, "\n");
}
