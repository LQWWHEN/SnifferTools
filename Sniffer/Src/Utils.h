#pragma once
#include <pcap.h>
#include <chrono>
#include <thread>
#include <string>
#include <vector>
#include "ParameterInput.h"

#define MAX_IP_ITER_RANGE (u_long)1<<16


char* iptos(u_long in);
char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen);
unsigned short CheckSum(unsigned short* packet, int size);
unsigned long long ipToInt(const char* ip);
std::string intToIP(u_long ipInt);



EC HandlePortFrag(const std::string& frag, std::vector<std::string>& tokens);
bool isValidIPv4(const std::string& ip);
EC HandleIPFrag(const std::string& frag, std::vector<std::string>& tokens);
EC ParseDelimiterString(const std::string& s, std::vector<std::string>& result, EC(*HandleFrag)(const std::string&, std::vector<std::string>&), char delimiter = ';');


bool cmp_port(const std::string& s1, const std::string& s2);
bool cmp_ip(const std::string& s1, const std::string& s2);
void ProcessTokens(std::vector<std::string>& tokens, bool (*cmp)(const std::string& s1, const std::string& s2));



class MyThread {
private:
	std::thread& m_t;

public:
	explicit MyThread(std::thread& t) :m_t(t) {}


	~MyThread() {
		if (m_t.joinable()) {
			m_t.join();
		}
	}

	MyThread(MyThread const&) = delete;
	MyThread& operator= (MyThread const&) = delete;


};


class WSAInitManager {
public:
	WSAInitManager() {
		Init();
	}
	;
	EC Init() {
		WSADATA wsaData;
		int result;

		// Initialize Winsock
		result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (result != 0) {
			printf("WSAStartup failed: %d\n", result);
			return EC::ERROR_INIT_WSA;
		}
		return EC::OK;
	}

	~WSAInitManager() {
		WSACleanup();
	};
};