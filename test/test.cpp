#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;
#include <iostream>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mutex>

std::mutex cout_mutex;

// 函数定义
std::wstring DisplayErrorMessage(DWORD errorCode) {
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
	std::wstring errorMessage =lpMsgBuf;

	// 输出错误消息

	// 释放分配的内存
	LocalFree(lpMsgBuf);
	return errorMessage;
}


#pragma comment(lib, "ws2_32.lib")
class PortScanTask {
public:
	PortScanTask(const std::string& host, const std::string& port) : host(host), port(port) {}

	void operator()(void) {
		std::cout << "Thread Start"<<endl;


		SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (clientSocket == INVALID_SOCKET) {
			std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
			return;
		}

		sockaddr_in service;
		service.sin_family = AF_INET;
		service.sin_addr.S_un.S_addr = inet_addr(host.c_str());
		service.sin_port = htons(std::stoi(port));

		//std::lock_guard<std::mutex> lock(cout_mutex);
		if (::connect(clientSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) {
			int ec = WSAGetLastError();
			std::cerr << "Connection failed: " << ec<< std::endl;
			LPTSTR lpMsgBuf;
			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				ec,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpMsgBuf,
				0, NULL);
		
		
			std::wstring str   = DisplayErrorMessage(ec);
		}
		else {
			std::cout << "Port " << port << " is open." << std::endl;
		}

		closesocket(clientSocket);

	}

private:

	std::string host;
	std::string port;
};
// 线程池类
class ThreadPool {
public:
	ThreadPool(int size) : stop(false) {
		for (int i = 0; i < size; ++i) {
			threads.emplace_back([this] {
				while (true) {
					function<void()> task;
					{
						unique_lock<mutex> lock(mutex_);
						condition_.wait(lock, [this] { return stop || !tasks_.empty(); });
						if (stop && tasks_.empty()) return;
						task = move(tasks_.front());
						tasks_.pop();
					}
					task();
				}
				});
		}
	}

	~ThreadPool() {
		{
			unique_lock<mutex> lock(mutex_);
			stop = true;
		}
		condition_.notify_all();
		for (auto& thread : threads) {
			thread.join();
		}
	}

	template<typename F>
	void enqueue(F&& f) {
		{
			unique_lock<mutex> lock(mutex_);
			tasks_.emplace(forward<F>(f));
		}
		condition_.notify_one();
	}

private:
	vector<thread> threads;
	queue<function<void()>> tasks_;
	mutex mutex_;
	condition_variable condition_;
	bool stop;
};

// 线程池管理类
// class ThreadPoolManager {
// public:
// 	static ThreadPool& getThreadPool() {
// 		static ThreadPool threadPool(thread::hardware_concurrency());
// 		return threadPool;
// 	}
// };

int main() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
		return 0;
	}
	{
		ThreadPool pool(10); // 创建一个包含10个线程的线程池

		std::vector<std::string> hosts = { "100.80.106.190", "100.80.106.191" };
		std::vector<std::string> ports = { "80", "445" };

		for (const auto& host : hosts) {
			for (const auto& port : ports) {
				pool.enqueue(PortScanTask(host, port));
			}
		}}
	cout << "main end";
	WSACleanup();
	return 0;
}