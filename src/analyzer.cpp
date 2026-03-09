#include<iostream>
#include<fstream>
#include<regex>
#include "../include/analyzer.h"
using namespace std;
void detect_credentials(const string file){
    ifstream f(file);
    if(!f.is_open()){
        cout << "Cannot open" << file;
    }
    string line;
    regex cred("(admin|root).{0,10}[:=].{1,20}");
    while(getline(f,line)){
        if(regex_search(line,cred)){
            cout << "[!] Credential found in: " << file << endl;
        }
    }
};
void detect_private_keys(const string file){
    ifstream f(file);
    if(!f.is_open()){
        cout << "Cannot open" << file;
    }
    string line;
    regex cred("(admin|root).{0,10}[:=].{1,20}");
    while(getline(f,line)){
        if(line.find("RSA PRIVATE KEY")!=string::npos){
            cout << "[!] Private key found in: " << file << endl;
        }
    }
};
void detect_dangerous_functions(const string file){
     std::ifstream f(file);
    if(!f) return;

    std::string line;

    while(std::getline(f,line)){
        if(line.find("system(") != std::string::npos){
            std::cout << "[!] Dangerous function system() in " << file << "\n";
        }
    }
};
void detect_command_injection(const string file){
     std::ifstream f(file);
    if(!f) return;

    std::string line;

    while(std::getline(f,line)){
        if(line.find("QUERY_STRING") != std::string::npos &&
           line.find("system(") != std::string::npos)
        {
            std::cout << "[!] Possible command injection in " << file << "\n";
        }
    }
};

