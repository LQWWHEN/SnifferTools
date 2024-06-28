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

	//timeout较长可以分辨超时和不可访问
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


// int main()
// {
// 	pcap_if_t* alldevs;
// 	pcap_if_t* d;
// 	int inum;
// 	int i = 0;
// 	pcap_t* adhandle;
// 	int res;
// 	char errbuf[PCAP_ERRBUF_SIZE];
// 	struct tm ltime;
// 	char timestr[16];
// 	struct pcap_pkthdr* header;
// 	const u_char* pkt_data;
// 	time_t local_tv_sec;
// 
// 
// 	/* Retrieve the device list on the local machine */
// 	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
// 	{
// 		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
// 		exit(1);
// 	}
// 
// 	/* Print the list */
// 	for (d = alldevs; d; d = d->next)
// 	{
// 		printf("%d. %s", ++i, d->name);
// 		if (d->description)
// 			printf(" (%s)\n", d->description);
// 		else
// 			printf(" (No description available)\n");
// 	}
// 
// 	if (i == 0)
// 	{
// 		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
// 		return -1;
// 	}
// 
// 	printf("Enter the interface number (1-%d):", i);
// 	scanf_s("%d", &inum);
// 
// 	if (inum < 1 || inum > i)
// 	{
// 		printf("\nInterface number out of range.\n");
// 		/* Free the device list */
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
// 
// 	/* Jump to the selected adapter */
// 	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
// 
// 	/* Open the device */
// 	if ((adhandle = pcap_open(d->name,          // name of the device
// 		65536,            // portion of the packet to capture. 
// 		// 65536 guarantees that the whole packet will be captured on all the link layers
// 		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
// 		1000,             // read timeout
// 		NULL,             // authentication on the remote machine
// 		errbuf            // error buffer
// 	)) == NULL)
// 	{
// 		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
// 		/* Free the device list */
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
// 
// 	printf("\nlistening on %s...\n", d->description);
// 
// 	/* At this point, we don't need any more the device list. Free it */
// 	pcap_freealldevs(alldevs);
// 
// 	/* Retrieve the packets */
// 	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
// 
// 		if (res == 0)
// 			/* Timeout elapsed */
// 			continue;
// 
// 		/* convert the timestamp to readable format */
// 		local_tv_sec = header->ts.tv_sec;
// 		localtime_s(&ltime, &local_tv_sec);
// 		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
// 
// 		printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
// 	}
// 
// 	if (res == -1) {
// 		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
// 		return -1;
// 	}
// 
// 	return 0;
// }

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


/*
// 	printf("Enter the interface number (1-%d):", i);
// 	scanf("%d", &inum);
//
// 	/ * Check if the user specified a valid adapter * /
// 	if (inum < 1 || inum > i)
// 	{
// 		printf("\nAdapter number out of range.\n");
//
// 		/ * Free the device list * /
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
//
// 	/ * Jump to the selected adapter * /
// 	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
//
// 	/ * Open the adapter * /
// 	if ((adhandle = pcap_open_live(d->name,	// name of the device
// 		65536,			// portion of the packet to capture.
// 		// 65536 grants that the whole packet will be captured on all the MACs.
// 		1,				// promiscuous mode (nonzero means promiscuous)
// 		1000,			// read timeout
// 		errbuf			// error buffer
// 	)) == NULL)
// 	{
// 		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
// 		/ * Free the device list * /
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
//
// 	/ * Check the link layer. We support only Ethernet for simplicity. * /
// 	if (pcap_datalink(adhandle) != DLT_EN10MB)
// 	{
// 		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
// 		/ * Free the device list * /
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
//
// 	if (d->addresses != NULL)
// 		/ * Retrieve the mask of the first address of the interface * /
// 		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
// 	else
// 		/ * If the interface is without addresses we suppose to be in a C class network * /
// 		netmask = 0xffffff;
//
//
// 	//compile the filter
// 	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
// 	{
// 		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
// 		/ * Free the device list * /
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
//
// 	//set the filter
// 	if (pcap_setfilter(adhandle, &fcode) < 0)
// 	{
// 		fprintf(stderr, "\nError setting the filter.\n");
// 		/ * Free the device list * /
// 		pcap_freealldevs(alldevs);
// 		return -1;
// 	}
//
// 	printf("\nlistening on %s...\n", d->description);
//
// 	/ * At this point, we don't need any more the device list. Free it * /
// 	pcap_freealldevs(alldevs);
//
// 	/ * start the capture * /
// 	pcap_loop(adhandle, 0, packet_handler, NULL);
//
*/