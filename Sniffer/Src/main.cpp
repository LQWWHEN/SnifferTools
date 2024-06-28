#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define _WINSOCK_DEPRECATED_NO_WARNINGS





#include <vector>
#include "pcap.h"
#include "Headers.h"

#include "ParameterInput.h"
#include "PacketCapture.h"
#include "DeviceManager.h"
#include "HostDetection.h"
#include "PortDetection.h"
#include "Utils.h"
/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


void DeviceTest()
{
 	DeviceManager DM;
 	DM.Init();
 	DM.Print();
 	
}

void HostDetectionTest() {
	HostDetection H("100.80.90.0","100.80.90.255");

	
	H.RunDetection(1,20);	
	return;
}

void PortDetectionTest()
{
	std::vector<std::string> IPLIST = { "100.80.106.190", "100.80.106.191" };
	std::vector<std::string> PORTLIST = { "80","135", "445" };
	PortDetection P(IPLIST, PORTLIST);
	P.RunDetection();
}

int main()
{
// 	std::vector<std::string> r;
// 	//ParseDelimiterString(test_portstr2,r,HandlePortFrag);
// 	ParseDelimiterString(test_ipstr, r, HandleIPFrag);
// 	ProcessTokens(r, cmp_ip);
	std::vector<std::string> IPLIST = { "100.80.106.190","100.80.90.244"};
	std::vector<std::string> PORTLIST = { "80","135","445"};
	PortDetection P(IPLIST, PORTLIST);
	{
		P.RunDetection();
	}

	P.result;
	return 0;
}



void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
}


