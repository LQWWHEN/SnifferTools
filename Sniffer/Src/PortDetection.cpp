#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "PortDetection.h"
#include "ThreadPool.h"
#include "Utils.h"
std::mutex cout_mutex;
EC PortDetection::RunDetection()
{

	ThreadPool pool(std::thread::hardware_concurrency());
	for (auto host : this->result) 
	{

		for (auto ports : host.second) 
		{
			int* addr = &result[host.first][ports.first];
			 pool.enqueue(PortScanTask(host.first, ports.first,addr));

		}
	}
	

	return EC::OK;
}

EC PortDetection::InitWSA()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		std::cout << "WSAStartup failed." << std::endl;
		return EC::ERROR_INIT_WSA;
	}
	return EC::OK;
}

std::wstring ParseErrorMessage(DWORD errorCode) {
	// 存储错误消息的缓冲区
	LPTSTR lpMsgBuf;

	// 调用FormatMessage函数检索错误消息
	DWORD dwChars = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPTSTR>(&lpMsgBuf),
		0,
		nullptr
	);


	// 将LPVOID类型的lpMsgBuf转换为std::string
	std::wstring errorMessage = lpMsgBuf;

	// 输出错误消息

	// 释放分配的内存
	LocalFree(lpMsgBuf);
	return errorMessage;
}


void PortScanTask::operator()(void)
{
	//std::cout << "Thread " << host << ':' << port << std::endl;


	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
		std::cout << "WSAStartup failed." << std::endl;
		return;
	}



	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientSocket == INVALID_SOCKET) {
		std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
		WSACleanup();
		return;
	}
	int timeout = 100; // 毫秒
	if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
		std::cout << "Setsockopt failed: " << WSAGetLastError() << std::endl;
		closesocket(clientSocket);
		WSACleanup();
		return;
	}
	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.S_un.S_addr = inet_addr(host.c_str());
	service.sin_port = htons(port);




	std::lock_guard<std::mutex> lock(cout_mutex);
	if (connect(clientSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) {
		int ec = WSAGetLastError();
		std::cerr << "Connection("<<host<<':'<<port << ") failed: " << ec << std::endl;
		*status = ec;
	}
	else {
		std::cerr << "Connection(" << host << ':' << port << ") success "  << std::endl;
		*status = 0;
	}

	closesocket(clientSocket);
	WSACleanup();
}
