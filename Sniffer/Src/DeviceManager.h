#pragma once
#include <string>
#include <pcap.h>

struct Address {
	int type=NULL;
	std::string ip_addr;
	std::string net_mask;

};

typedef struct {
	pcap_if_t* dev;
	std::string name;
	std::string description;
	std::vector<Address> address;
}DeviceInfo;


class DeviceManager
{
public:
	pcap_if_t* devlist;
	std::vector<DeviceInfo> DeviceList;
	~DeviceManager();
	EC Init();
	EC GetDeviceList(pcap_if_t** alldevsp, char* errbuf);
	EC FreeDeviceList(pcap_if_t* alldevs);
	EC OpenDevice(int index ,int portion = 65536,int mode = PCAP_OPENFLAG_PROMISCUOUS,int read_timeout=1000, pcap_rmtauth* auth = NULL);
	void Print();
private:
	/// <summary>
	/// default = NULL 
	/// pointer 
	/// </summary>
	pcap_t* currentdevicehandle=NULL;


};

