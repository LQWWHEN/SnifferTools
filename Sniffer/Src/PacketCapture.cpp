#include "PacketCapture.h"
#include <iostream>



EC CaptureHandler::capture_start(pcap_t* adhandle)
{

	return EC::OK;
}

EC CaptureHandler::capture_next(pcap_t* adhandle, u_int netmask)
{
	int res;
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	if (res = pcap_next_ex(adhandle, &header, &pkt_data) >= 0)
	{
		if (res == 0)
			return EC::TIMEOUT_ELAPSED;



		pkt_handler(header, pkt_data);

		return EC::OK;
	}
	else if(res==-1)
	{
		std::cout << "Error reading the packets:\n"<< pcap_geterr(adhandle) << std::endl;
		return EC::ERROR_READING_PKT;
	}
	
	return EC::ERROR_UNKNOWN;
}

EC CaptureHandler::compile_filter(pcap_t* adhandle, u_int netmask, const std::string filter)
{

	if (pcap_compile(adhandle, &fcode, filter.c_str(), 1, netmask) < 0)
	{
		std::cout << "\nUnable to compile the packet filter. Check the syntax.\n";
		return EC::ERROR_COMPILE_FILTER;
	}
	return EC::OK;

}

EC CaptureHandler::set_filter(pcap_t * adhandle)
{
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		std::cout << "\nError setting the filter.\n";
		return EC::ERROR_SET_FILTER;
	}
	return EC::OK;
}

EC CaptureHandler::pkt_handler(const struct pcap_pkthdr* header, const u_char* pkt_data)
{





	return EC::OK;

}
