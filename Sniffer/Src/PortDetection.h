#pragma once
#include <string>
#include <map>
#include <iostream>
#include <vector>
#include <WinSock2.h>
#include <iphlpapi.h>
#include "ParameterInput.h"
#include <mutex>
#include <functional>
#define	SCAN_THREAD_NUM 100

enum class PortStatus:int{
	OPEN,
	CLOSE

};


struct Params {
	std::string Host;
	int port;
};

struct HostResult {
	std::string ip;
	std::map<int, int> port_info;
};


class PortDetection 
{
	
public:
	
	std::map<std::string, std::map<int, int>> result;
	PortDetection() {
		InitWSA();
	};
	PortDetection(const std::vector<std::string> &HostRange,std::vector<std::string> &PortRange) {
		InitWSA();

		for (int i = 0; i < HostRange.size(); i++)
		{
			HostResult temp;
			temp.ip = HostRange[i];
			std::map<int, int> tmap;
			for (int j = 0; j < PortRange.size(); j++)
			{
				tmap.insert(std::make_pair(std::stoi(PortRange[j]), WSAETIMEDOUT));
			}
			result.insert(std::make_pair(HostRange[i],tmap));
		}
	};
	EC RunDetection();
	~PortDetection()
	{
		WSACleanup();

	};
private:
	static EC InitWSA();


};

class PortScanTask {


public:
	PortScanTask(const std::string& host, int port,int *status) : host(host), port(port),status(status) {}

	void operator()(void);

private:
	std::string host;
	int port;
	int *status;
};
std::wstring ParseErrorMessage(DWORD errorCode);