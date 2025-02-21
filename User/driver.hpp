#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <algorithm>

namespace driver
{
	constexpr ULONG dump_driver_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	constexpr ULONG dump_process_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

	HANDLE hDevice = nullptr;

	typedef struct _DRIVER_REQUEST {
		char* driver_name;
		DWORD process_id;
	} DRIVER_REQUEST, * PDRIVER_REQUEST;
	
	void initdriver()
	{
		hDevice = CreateFileA("\\\\.\\BrazilPastingOnTop",
			GENERIC_READ | GENERIC_WRITE,
			0,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);
	}

	void dump_driver(const char* driver_name)
	{
		DRIVER_REQUEST req = {};
		req.driver_name = (char*)driver_name;

		DWORD bytesReturned = 0;
		DeviceIoControl(
			hDevice,
			dump_driver_code,
			&req,
			sizeof(req),
			&req,
			sizeof(req),
			&bytesReturned,
			nullptr);
	}

	void dump_process(DWORD process_id)
	{
		DRIVER_REQUEST req = {};
		req.process_id = process_id;

		DWORD bytesReturned = 0;
		DeviceIoControl(
			hDevice,
			dump_process_code,
			&req,
			sizeof(req),
			&req,
			sizeof(req),
			&bytesReturned,
			nullptr);
	}
}