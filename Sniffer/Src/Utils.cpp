#include "Utils.h"
#include <string>
#include "ParameterInput.h"
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <windows.h>

#include <WinSock2.h>
#include <ws2ipdef.h>
#include <WinDNS.h>
#include <iphlpapi.h>


/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12


char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}

unsigned long long ipToInt(const char* ip) {
	unsigned long long result = 0;
	const char* dot = strchr(ip, '.');
	while (dot) {
		result = (result << 8) | atoi(ip);
		ip = dot + 1;
		dot = strchr(ip, '.');
	}
	result = (result << 8) | atoi(ip);
	return result;
}



std::string intToIP(u_long ipInt) {
	std::ostringstream oss;
	// Convert each byte to decimal and append to the stream
	for (int i = 3; i >= 0; --i) {
		oss << std::dec << ((ipInt >> (i * 8)) & 0xFF);
		if (i > 0) {
			oss << ".";
		}
	}
	return oss.str();
}

//校验和计算
unsigned short CheckSum(unsigned short* packet, int size)
{
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *packet++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)packet;
	}
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	cksum += (cksum >> 16);

	return (USHORT)(~cksum);
}

template<class T>
void Deduplicate(std::vector<T>& v)
{
	std::sort(v.begin(), v.end());

	// Use unique() to bring all the duplicates to the end and get the iterator for the modified vector
	auto it = std::unique(v.begin(), v.end());

	// Use erase method to remove all the duplicates from the vector
	v.erase(it, v.end());
}


bool is_all_digits(const std::string& str) {
	return !str.empty() && std::all_of(str.begin(), str.end(), ::isdigit);
}

bool isValidPortRange(const std::string& str) {
	// Step 1: Check if the string starts or ends with a hyphen
	if (!str.empty() && (str.front() == '-' || str.back() == '-')) {
		return false;
	}

	// Step 2: Count the occurrences of the hyphen
	int dashCount = 0;
	for (char c : str) {
		if (c == '-') {
			dashCount++;
			if (dashCount > 1) { // More than one hyphen found
				return false;
			}
		}
	}

	// Step 3: Ensure all characters are digits
	for (char c : str) {
		if (!isdigit(c) && c != '-') { // Using isdigit function from cctype header
			return false;
		}
	}

	// All checks passed
	return true;
}

bool isValidIPv4Range(const std::string& str) {
	// Step 1: Check if the string starts or ends with a hyphen
	if (!str.empty() && (str.front() == '-' || str.back() == '-')) {
		return false;
	}

	// Step 2: Count the occurrences of the hyphen
	int dashCount = 0;
	for (char c : str) {
		if (c == '-') {
			dashCount++;
			if (dashCount > 1) { // More than one hyphen found
				return false;
			}
		}
	}

	// Step 3: Ensure all characters are digits
	for (char c : str) {
		if (!isdigit(c) && c != '-'&&c!='.') { // Using isdigit function from cctype header
			return false;
		}
	}

	// All checks passed
	return true;
}
std::vector<std::string> splitByHyphen(const std::string& str) {
	std::vector<std::string> tokens;
	std::stringstream ss(str);
	std::string token;

	char delimiter = '-';
	while (std::getline(ss, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
}


EC HandlePortFrag(const std::string& frag, std::vector<std::string>& tokens)
{
	if (is_all_digits(frag))
	{
		int port = std::stoi(frag);
		if (port < 0 || port>65535)
			return EC::ERROR_PARSE_STRING;
		else {
			tokens.push_back(frag);
		}
	}
	else if (isValidPortRange(frag))
	{
		std::vector<std::string> range = splitByHyphen(frag);
		if (range.size() != 2)
			return EC::ERROR_PARSE_STRING;
		int start = std::stoi(range[0]);
		int end = std::stoi(range[1]);
		if (start < 0 || start>65535 || end < 0 || end>65536 || start > end)
			return EC::ERROR_PARSE_STRING;

		for (int i = start; i <= end; i++)
			tokens.push_back(std::to_string(i));
	}
	else
		return EC::ERROR_PARSE_STRING;

	return EC::OK;
}

bool isValidIPv4(const std::string& ip)
{
	WSAInitManager M;
    const char* ipAddressString = ip.c_str();
    struct in_addr ipAddress;
    int result = inet_pton(AF_INET, ipAddressString, &ipAddress);
    if (result <= 0) {
        return false;
    }
    return true;

}
EC HandleIPFrag(const std::string& frag, std::vector<std::string>& tokens)
{
	if (isValidIPv4(frag))
	{
		tokens.push_back(frag);
	}
	else if (isValidIPv4Range(frag))
	{
		std::vector<std::string> range = splitByHyphen(frag);
		if (range.size() != 2)
			return EC::ERROR_PARSE_STRING;



		u_long start = ipToInt(range[0].c_str());
		u_long end = ipToInt(range[1].c_str());
		if (!isValidIPv4(range[0]) || !isValidIPv4(range[1]) || start > end ||  end-start > MAX_IP_ITER_RANGE)
			return EC::ERROR_PARSE_STRING;

		for (u_long i = start; i <= end; i++)
		{
			tokens.push_back(intToIP(i));

		}


	}
	else
		return EC::ERROR_PARSE_STRING;

	return EC::OK;


}

EC ParseDelimiterString(const std::string& s, std::vector<std::string>& result, EC(*HandleFrag)(const std::string&, std::vector<std::string>&), char delimiter)
{
	std::vector<std::string> tokens;
	std::string::size_type lastPos = s.find_first_not_of(delimiter, 0);
	std::string::size_type pos = s.find_first_of(delimiter, lastPos);

	while (pos != std::string::npos && lastPos != std::string::npos) {
		std::string frag;
		frag = s.substr(lastPos, pos - lastPos);
		if (HandleFrag(frag, tokens) == EC::ERROR_PARSE_STRING)
			return EC::ERROR_PARSE_STRING;


		lastPos = s.find_first_not_of(delimiter, pos);
		pos = s.find_first_of(delimiter, lastPos);
	}

	if (lastPos != std::string::npos) {
		std::string frag;
		frag = s.substr(lastPos);
		if (HandleFrag(frag, tokens) == EC::ERROR_PARSE_STRING)
			return EC::ERROR_PARSE_STRING;
	}
	result = tokens;
	return EC::OK;
}


bool cmp_port(const std::string& s1, const std::string& s2) {
	return std::stoi(s1) < std::stoi(s2);
}

bool cmp_ip(const std::string& s1, const std::string& s2) {
	return ipToInt(s1.c_str()) < ipToInt(s2.c_str());
}

void ProcessTokens(std::vector<std::string>& tokens, bool (*cmp)(const std::string& s1, const std::string& s2))
{
	Deduplicate<std::string>(tokens);

	std::sort(tokens.begin(), tokens.end(), cmp);
	
}
