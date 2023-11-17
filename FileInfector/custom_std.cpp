#include "custom_std.h"

namespace custom_std
{

	void* malloc(unsigned long uNumberOfBytes)
	{

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)

		return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uNumberOfBytes);
#else

#error not implemented
#endif
	}

	void free(void* pMemory)
	{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)

		HeapFree(GetProcessHeap(), 0, pMemory);
#else

#error not implemented
#endif
	}


	size_t strlen(const char* str)
	{
		size_t length = 0;
		while (*str)
		{
			length++;
			str++;
		}

		return length;
	}

	bool strcmp(const char* str1, const char* str2)
	{
		while (*str1 && *str2)
		{
			if (*str1 != *str2)
			{
				return false;
			}

			str1++;
			str2++;
		}

		if (*str1 || *str2)
		{
			return false;
		}

		return true;
	}

	size_t wcslen(const wchar_t* str)
	{
		size_t length = 0;
		while (*str)
		{
			length++;
			str++;
		}

		return length;
	}

	bool wcscmp(const wchar_t* str1, const wchar_t* str2)
	{
		while (*str1 && *str2)
		{
			if (*str1 != *str2)
			{
				return false;
			}

			str1++;
			str2++;
		}

		if (*str1 || *str2)
		{
			return false;
		}

		return true;
	}

	void memcpy(void* dst, const void* src, unsigned long amount)
	{
		for (size_t i = 0; i < amount; i++)
		{
			reinterpret_cast<unsigned char*>(dst)[i] = reinterpret_cast<const unsigned char*>(src)[i];
		}

	}

	void memset(void* dst, unsigned char val, unsigned long amount)
	{
		for (size_t i = 0; i < amount; i++)
		{
			reinterpret_cast<char*>(dst)[i] = val;
		}
	}


	bool memcmp(const void* dst, const void* src, unsigned long amount)
	{
		for (size_t i = 0; i < amount; i++)
		{
			if (reinterpret_cast<const unsigned char*>(dst)[i] != reinterpret_cast<const unsigned char*>(src)[i])
			{
				return false;
			}
		}

		return true;
	}


};



