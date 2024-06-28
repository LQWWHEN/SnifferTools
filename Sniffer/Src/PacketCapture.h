#pragma once
#include "ParameterInput.h"
#include <pcap.h>
#include <vector>
#include <string>
#include <unordered_map>

class PacketInfo {
	std::string no;
	std::string time;
	std::string source;
	std::string destination;
	std::string proto;
	int length;
	std::string info;


	const char* content;
};

class CaptureHandler {
public:
	std::vector<PacketInfo> PacketCache;
	std::unordered_map<std::string, int> ip_flow, proto_flow;

private:
	struct bpf_program fcode;
	EC save_to_file(std::string path);
	EC clear_cache() {
		PacketCache.clear();
	};
	EC capture_start(pcap_t* adhandle);
	EC capture_next(pcap_t* adhandle, u_int netmask);
	EC compile_filter(pcap_t* adhandle, u_int netmask, const std::string filter);
	EC set_filter(pcap_t* adhandle);
	EC pkt_handler( const struct pcap_pkthdr* header, const u_char* pkt_data);
};