#include <pcap.h>
#include "ParameterInput.h"
#include <vector>
#include "DeviceManager.h"
#include <Packet32.h>
#include <iostream>

#include "Utils.h"

ErrorCode DeviceManager::GetDeviceList(pcap_if_t** alldevsp, char* errbuf) {
	if (pcap_findalldevs(alldevsp, errbuf) == -1)
		return EC::ERROR_FIND_ALLDEVS;
	return EC::OK;
}

ErrorCode DeviceManager::FreeDeviceList(pcap_if_t* alldevs)
{
	pcap_freealldevs(alldevs);
	return EC::OK;
}





EC DeviceManager::OpenDevice(int index, int portion /*= 65536*/, int mode /*= PCAP_OPENFLAG_PROMISCUOUS*/,int read_timeout/*=1000*/,pcap_rmtauth* auth/*=NULL*/)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	if (index < 0 || index >= this->DeviceList.size())
		return EC::DEVICE_INDEX_OUT_OF_BOUND;
	if ((this->currentdevicehandle = pcap_open(DeviceList[index].name.c_str(),portion,mode,read_timeout,auth,errbuf))==NULL)
	{
		std::cout << "\nUnable to open the adapter.Not supported by WinPcap" << std::endl;
		return EC::ERROR_OPEN_DEVICE;
	}
	return EC::OK;
}

void DeviceManager::Print()
{
	for (DeviceInfo x : this->DeviceList)
	{
		std::cout << "-------------------------" << std::endl;
		std::cout << x.name << std::endl;
		std::cout << x.description << std::endl;
		for (Address a : x.address)
		{
			std::cout << a.type << std::endl;
			std::cout << a.ip_addr << std::endl;
			std::cout << a.net_mask << std::endl;

		}
		std::cout << "-------------------------" << std::endl<<std::endl;


	}
}

DeviceManager::~DeviceManager()
{
	FreeDeviceList(devlist);
}

EC DeviceManager::Init()
{
	char errbuf[PCAP_ERRBUF_SIZE];
	//load list
	if (pcap_findalldevs(&devlist, errbuf) == -1)
		return EC::ERROR_FIND_ALLDEVS;
	pcap_if_t* p;
	for (p = (pcap_if_t*)devlist; p != NULL; p = p->next)
	{
		DeviceInfo currentdev;
		if (p->description)
			currentdev.description = p->description;
		else
			currentdev.description = "";
		currentdev.name = p->name;
		currentdev.dev = p;

		pcap_addr_t* a;
		for (a = p->addresses; a; a = a->next) {
			Address addr;
			switch (a->addr->sa_family)
			{
				case AF_INET:
					if (a->addr) {
						struct sockaddr_in* ip = (struct sockaddr_in*)a->addr;
						struct sockaddr_in* net_mask = (struct sockaddr_in*)a->netmask;
						addr.ip_addr = inet_ntoa(ip->sin_addr);
						addr.net_mask = inet_ntoa(net_mask->sin_addr);
						addr.type = AF_INET;
						currentdev.address.push_back(addr);
					}
					break;
				case AF_INET6:
					if (a->addr)
					{
						char ip6str[128];
						addr.ip_addr = ip6tos(a->addr, ip6str, sizeof(ip6str));
						addr.type = AF_INET6;
						currentdev.address.push_back(addr);

					}
					break;
				default:
					break;
			}
		}

		DeviceList.push_back(currentdev);
	}

	
	
	//no device
	if (DeviceList.size() == 0)
		return EC::DEVICE_NOT_FOUND;


	return EC::OK;
}
