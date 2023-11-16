#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include <Windows.h>
#else
#endif

namespace custom_std
{

	void* malloc(unsigned long uNumberOfBytes);


	void free(void* pMemory);

	size_t strlen(const char* str);

	bool strcmp(const char* str1, const char* str2);

	size_t wcslen(const wchar_t* str);

	bool wcscmp(const wchar_t* str1, const wchar_t* str2);


	void memcpy(void* dst, const void* src, unsigned long amount);

	void memset(void* dst, unsigned char val, unsigned long amount);
};
