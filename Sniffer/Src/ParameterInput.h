#pragma once
#include <string>

enum class  ErrorCode :int
{
	OK,
	ERROR_FIND_ALLDEVS,
	ERROR_OPEN_DEVICE,
	ERROR_COMPILE_FILTER,
	ERROR_SET_FILTER,
	ERROR_READING_PKT,
	ERROR_UNKNOWN,
	ERROR_INIT_WSA,
	ERROR_UNABLE_OPEN_HANDLE,
	ERROR_ALLOC_MEM,
	ERROR_CALL_ICMP,
	ERROR_ILLEGAL_PARAM,
	ERROR_OCCUR,
	ERROR_PARSE_STRING,
	DEVICE_NOT_FOUND,
	DEVICE_INDEX_OUT_OF_BOUND,
	TIMEOUT_ELAPSED


};
typedef ErrorCode EC;

