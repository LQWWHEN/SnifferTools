#include "HostDetection.h"
#include <iostream>
#include "Utils.h"


#include <windows.h>

#include <winsock2.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>

std::string ParseIpStatus(DWORD status)
{
	std::string message;
	switch (status)
	{
		case IP_SUCCESS:
			message = "操作成功";
			break;
		case IP_BUF_TOO_SMALL:
			message = "回复缓冲区太小";
			break;
		case IP_DEST_NET_UNREACHABLE:
			message = "无法访问目标网络";
			break;
		case IP_DEST_HOST_UNREACHABLE:
			message = "无法访问目标主机";
			break;
		case IP_DEST_PROT_UNREACHABLE:
			message = "无法访问目标协议";
			break;
		case IP_DEST_PORT_UNREACHABLE:
			message = "无法访问目标端口";
			break;
		case IP_NO_RESOURCES:
			message = "可用 IP 资源不足";
			break;
		case IP_BAD_OPTION:
			message = "指定了错误的 IP 选项";
			break;
		case IP_HW_ERROR:
			message = "发生硬件错误";
			break;
		case IP_PACKET_TOO_BIG:
			message = "数据包太大";
			break;
		case IP_REQ_TIMED_OUT:
			message = "请求超时";
			break;
		case IP_BAD_REQ:
			message = "错误的请求";
			break;
		case IP_BAD_ROUTE:
			message = "一条糟糕的路线";
			break;
		case IP_TTL_EXPIRED_TRANSIT:
			message = "TTL (生存时间) 在传输中过期";
			break;
		case IP_TTL_EXPIRED_REASSEM:
			message = "片段重新组合期间生存时间已过期";
			break;
		case IP_PARAM_PROBLEM:
			message = "参数问题";
			break;
		case IP_SOURCE_QUENCH:
			message = "数据报到达太快，无法处理，数据报可能已被丢弃";
			break;
		case IP_OPTION_TOO_BIG:
			message = "IP 选项太大";
			break;
		case IP_BAD_DESTINATION:
			message = "一个糟糕的目标";
			break;
		case IP_GENERAL_FAILURE:
			message = "常规故障";
			break;
		default:
			message = "未知的 IP_STATUS 值：" + std::to_string(status);
			break;
	}
	return message;
}

EC HostDetection::SendICMP(const std::string &ip)
{
	HANDLE hICMP = IcmpCreateFile();
	if (hICMP == INVALID_HANDLE_VALUE)
	{
		std::cout << "Unable to open handle:" << ip << std::endl;
		return EC::ERROR_UNABLE_OPEN_HANDLE;

	}

	DWORD ret = 0;
	char databuffer[] = "2153816&2154304";
	LPVOID RplBuffer = NULL;
	DWORD RplSize = 0;
	RplSize = sizeof(ICMP_ECHO_REPLY) + sizeof(databuffer);
	RplBuffer = (VOID*)malloc(RplSize);


	if (RplBuffer == NULL) {
		std::cout << "Unable to allocate memory." << std::endl;
		return EC::ERROR_ALLOC_MEM;
	}
	/*time out=1000*/
	ret = IcmpSendEcho(hICMP, inet_addr(ip.c_str()), databuffer, sizeof(databuffer),
		NULL, RplBuffer, RplSize, timeout);


	if (ret != 0) {
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)RplBuffer;
		struct in_addr ReplyAddr;
		ReplyAddr.S_un.S_addr = pEchoReply->Address;
		printf("Sent icmp message to %s\n", ip.c_str());
		if (ret > 1) {
			printf("\tReceived %ld icmp message responses\n", ret);
			printf("\tInformation from the first response:\n");
			
		}
		else {
			printf("\tReceived %ld icmp message response\n", ret);
			printf("\tInformation from this response:\n");

		}
		printf("\t  Received from %s\n", inet_ntoa(ReplyAddr));
		printf("\t  Status = %s\n",ParseIpStatus(pEchoReply->Status).c_str());
		result[ip][pEchoReply->Status]+=ret;
		printf("\t  Roundtrip time = %ld milliseconds\n",
			pEchoReply->RoundTripTime);
		std::cout << "Received reply from " << inet_ntoa(ReplyAddr) << std::endl;
	}
	else {
		PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)RplBuffer;
		std::cout  << "Call to IcmpSendEcho failed." << std::endl;
		std::cout << ParseIpStatus(pEchoReply->Status) << std::endl;
		result[ip][pEchoReply->Status]++;
		free(RplBuffer);
		IcmpCloseHandle(hICMP);
		return EC::ERROR_CALL_ICMP;
	}

	free(RplBuffer);


	IcmpCloseHandle(hICMP);
	return EC::OK;
}



HostDetection::HostDetection()
{
	InitWSA();
	this->start = ipToInt("127.0.0.1");
	this->end = ipToInt("127.0.0.1");

}

HostDetection::HostDetection(const std::string& start_ip, const std::string& end_ip)
{
	start = ipToInt(start_ip.c_str());
	end = ipToInt(end_ip.c_str());
	InitWSA();
}

HostDetection::HostDetection(const std::string& ip)
{
	start = ipToInt(ip.c_str());
	end = ipToInt(ip.c_str());
	InitWSA();
}

EC HostDetection::RunDetection(int repeat,int timeout)
{
	
	if (repeat <= 0)
		return EC::ERROR_ILLEGAL_PARAM;
	bool hasErr=false;
	this->timeout = timeout;
	for (u_long i = start; i <= end; i++)
	{
		
		std::string ip = intToIP(i);

		for (int r = 0; r < repeat; r++) {
			if (SendICMP(ip) != EC::OK) {
				hasErr = true;
				continue;
			}
		}

	}


	if (hasErr)
		return EC::ERROR_OCCUR;

	return EC::OK;

}

HostDetection::~HostDetection()
{
	WSACleanup();
}

EC HostDetection::InitWSA()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		std::cout << "WSAStartup failed." << std::endl;
		return EC::ERROR_INIT_WSA;
	}
	return EC::OK;
}
