#pragma once



#include <winsock2.h>
#include "iphlpapi.h" // For SendARP
#include "ParameterInput.h"
#include <string>
#include <map>
#include <vector>



class HostDetection
{
public:
	HostDetection(u_long start_ip, u_long end_ip) :start(start_ip), end(end_ip){
		InitWSA();
	};
	HostDetection(const std::string &start_ip,const std::string &end_ip);
	HostDetection(const std::string& ip);
	HostDetection();
	EC RunDetection(int repeat=1,int timeout = 100);
	~HostDetection();
	std::map<std::string,std::map<DWORD,int>>  result;
	
private:
	static EC InitWSA();
	u_long start,end;
	int timeout = 100;
	EC SendICMP(const std::string& ip);

public:
	EC GetMacAddress(std::string& macstr, struct in_addr destip)
	{
		unsigned char mac[6] = { 0 };
		DWORD ret;
		IPAddr srcip;
		ULONG MacAddr[2];
		ULONG PhyAddrLen = 6;  // Default to length of six bytes
		int i;

		srcip = 0;

		// Send an ARP packet
		ret = SendARP((IPAddr)destip.S_un.S_addr, srcip, MacAddr, &PhyAddrLen);

		// Prepare the MAC address
		if (ret == NO_ERROR)
		{
			BYTE* bMacAddr = (BYTE*)&MacAddr;
			for (i = 0; i < (int)PhyAddrLen; i++)
			{
				mac[i] = (char)bMacAddr[i];
			}
			char buffer[50];
			snprintf(buffer, sizeof(buffer), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			macstr = std::string(buffer);
			return EC::OK;
		}
		else {
			macstr = "------";
			return EC::ERROR_OCCUR;
		}
	}
};

