#pragma once
#include <iostream>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>


#include <winsock2.h>
#include <ws2tcpip.h>
// 线程池类
class ThreadPool {
public:
	ThreadPool(int size) : stop(false) {
		for (int i = 0; i < size; ++i) {
			threads.emplace_back([this] {
				while (true) {
					std::function<void()> task;
					{
						std::unique_lock<std::mutex> lock(mutex_);
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
			std::unique_lock < std:: mutex > lock(mutex_);
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
			std::unique_lock<std::mutex> lock(mutex_);
			tasks_.emplace(std::forward<F>(f));
		}
		condition_.notify_one();
	}

private:
	std::vector<std::thread> threads;
	std::queue<std::function<void()>> tasks_;
	std::mutex mutex_;
	std::condition_variable condition_;
	bool stop;
};

// 线程池管理类
class ThreadPoolManager {
public:
	static ThreadPool& getThreadPool() {
		static ThreadPool threadPool(std::thread::hardware_concurrency());
		return threadPool;
	}
};

