#include<iostream>
#include<fstream>
#include<regex>
#include "../include/analyzer.h"
using namespace std;
void log_finding(const std::string& msg){
    std::ofstream out("report.txt", std::ios::app);
    if(out){
        out << msg << std::endl;
    }
}
void detect_credentials(const string& file){
    ifstream f(file);
    if(!f.is_open()){
        cout << "Cannot open " << file << endl;
        return;
    }

    string line;
    regex cred("(admin|root).{0,10}[:=].{1,20}");

    while(getline(f,line)){
        if(regex_search(line,cred)){
            string msg = "[!] Credential found in: " + file;
            cout << msg << endl;
            log_finding(msg);
        }
    }
}

void detect_private_keys(const string& file){
    ifstream f(file);
    if(!f.is_open()){
        cout << "Cannot open " << file << endl;
        return;
    } 

    string line;

    while(getline(f,line)){
        if(line.find("RSA PRIVATE KEY") != string::npos){
            string msg = "[!] Private key found in: " + file;
            cout << msg << endl;
            log_finding(msg);
        }
    }
}

void detect_dangerous_functions(const string& file){
    ifstream f(file);
    if(!f) return;

    string line;

    while(getline(f,line)){
        if(line.find("system(") != string::npos){
            string msg = "[!] Dangerous function system() in " + file;
            cout << msg << endl;
            log_finding(msg);
        }
    }
}

void detect_command_injection(const string& file){
    ifstream f(file);
    if(!f) return;

    string line;

    while(getline(f,line)){
        if(line.find("QUERY_STRING") != string::npos &&
           line.find("system(") != string::npos){

            string msg = "[!] Possible command injection in " + file;
            cout << msg << endl;
            log_finding(msg);
        }
    }
}
