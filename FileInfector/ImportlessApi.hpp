/*
MIT License

Copyright (c) 2022 Yoav Shaharabani

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include <Windows.h>
#include <winreg.h>

/*
    Define IMPORTLESSAPI_CONSISTENT_COMPILATION so each compilation the hash value will stay constant (Do not use DATE_AND_TIME)

    Define IMPORTLESSAPI_REMOVE_INLINE so all the search functions will be forced inline, not defining this works well when making a shellcode


*/


/* Convert definition to function name. CreateFile to CreateFileA or CreateFileW based on configurations. */
#define REAL_DEFINITION(x) #x

#define IMPORTLESS_API_START_NUMBER 0x1928471f

#ifndef IMPORTLESSAPI_CONSISTENT_COMPILATION
#define DATE_AND_TIME __TIME__ __DATE__
#else
#define DATE_AND_TIME "ImportlessApiConsistentCompilation"
#endif


#define TO_UNICODE_HELPER(x) L##x
#define TO_UNICODE(x) TO_UNICODE_HELPER(x)
#define DATE_AND_TIME_UNICODE TO_UNICODE(DATE_AND_TIME)


#ifndef IMPORTLESSAPI_REMOVE_INLINE
#define IMPORTLESSAPI_INLINED __forceinline
#else
#define IMPORTLESSAPI_INLINED
#endif

namespace importless_api
{
    namespace win {
        struct LIST_ENTRY_T {
            LIST_ENTRY_T* Flink;
            LIST_ENTRY_T* Blink;
        };

        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            wchar_t* Buffer;
        };

        struct PEB_LDR_DATA_T {
            unsigned long Length;
            unsigned long Initialized;
            const char* SsHandle;
            LIST_ENTRY_T  InMemoryOrderLinks;
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            const char* Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
        };

        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY_T InLoadOrderLinks;
            LIST_ENTRY_T InMemoryOrderLinks;
            LIST_ENTRY_T InInitializationOrderLinks;
            char* DllBase;
            const char* EntryPoint;
            union {
                unsigned long SizeOfImage;
                const char* _dummy;
            };
            UNICODE_STRING_T FullDllName;
            UNICODE_STRING_T BaseDllName;
        };


    }

    /*
        Hash string with start value.
        Choosed the hash function based on "The Last Stage of Delerium. Win32 Assembly Components"
    */
    constexpr UINT32 hash_str(const char* func_name, const UINT32 value)
    {

        UINT32 hash = value;
        for (;;)
        {
            char c = *func_name;
            func_name++;
            if (!c)
                return hash;

            hash = (((hash << 5) | (hash >> 27)) + c) & 0xFFFFFFFF;
        }
    }

    template<UINT32 hash> class importless_api
    {

    private:
        /* Getting the PEB struct from register based on architecture. */
        const win::PEB_T* peb()
        {
#if defined(_M_X64) || defined(__amd64__)
            return reinterpret_cast<const win::PEB_T*>(__readgsqword(0x60));
#elif defined(_M_IX86) || defined(__i386__)
            return reinterpret_cast<const win::PEB_T*>(__readfsdword(0x30));
#elif defined(_M_ARM) || defined(__arm__)
            return *reinterpret_cast<const win::PEB_T**>(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#elif defined(_M_ARM64) || defined(__aarch64__)
            return *reinterpret_cast<const win::PEB_T**>(__getReg(18) + 0x60);
#elif defined(_M_IA64) || defined(__ia64__)
            return *reinterpret_cast<const win::PEB_T**>(static_cast<char*>(_rdteb()) + 0x60);
#else
#error Unsupported platform. 
#endif
        }




    public:

        IMPORTLESSAPI_INLINED importless_api()
        {}

        IMPORTLESSAPI_INLINED UINT32 get_hash()
        {
            return hash;
        }

        /* Iterates over the PEB and all exported functions to find function by hash. */
        IMPORTLESSAPI_INLINED LPVOID get_function()
        {
            win::LDR_DATA_TABLE_ENTRY_T* curr_module = (win::LDR_DATA_TABLE_ENTRY_T*)peb()->Ldr->InMemoryOrderLinks.Flink;

            /* Iterate over loaded modules. */
            while (curr_module->BaseDllName.Buffer != NULL) {
                char* hBase = curr_module->DllBase;


                IMAGE_DOS_HEADER* hImageDosHeader = (IMAGE_DOS_HEADER*)hBase;
                IMAGE_NT_HEADERS* hImageNtHeaders = (IMAGE_NT_HEADERS*)(hBase + hImageDosHeader->e_lfanew);

                /* If export table exists. */
                if (hImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress != 0)
                {
                    IMAGE_EXPORT_DIRECTORY* hImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(hBase + hImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

                    PDWORD pNamePointers = (PDWORD)(hBase + hImageExportDirectory->AddressOfNames);
                    PWORD pOrdinalPointers = (PWORD)(hBase + hImageExportDirectory->AddressOfNameOrdinals);
                    PDWORD pAddressesPointers = (PDWORD)(hBase + hImageExportDirectory->AddressOfFunctions);

                    /* Iterate over functions and check their hash. */
                    for (size_t i = 0; i < hImageExportDirectory->NumberOfNames; ++i, ++pNamePointers, ++pOrdinalPointers)
                    {
                        UINT32 func_hash = hash_str(hBase + *pNamePointers, importless_api<hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER)>().get_hash());
                        if (func_hash == hash)
                        {
                            DWORD dwFuncRVA = pAddressesPointers[*pOrdinalPointers];

                            /* Return function address. */
                            return hBase + dwFuncRVA;
                        }
                    }
                }

                curr_module = (win::LDR_DATA_TABLE_ENTRY_T*)curr_module->InLoadOrderLinks.Flink;
            }

            return NULL;
        }

        /* Iterates over the PEB and all exported functions to find function by hash. */
        IMPORTLESSAPI_INLINED LPVOID get_function(void* pBase)
        {

            char* hBase = reinterpret_cast<char*>(pBase);


            IMAGE_DOS_HEADER* hImageDosHeader = (IMAGE_DOS_HEADER*)hBase;
            IMAGE_NT_HEADERS* hImageNtHeaders = (IMAGE_NT_HEADERS*)(hBase + hImageDosHeader->e_lfanew);

            /* If export table exists. */
            if (hImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress != 0)
            {
                IMAGE_EXPORT_DIRECTORY* hImageExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(hBase + hImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

                PDWORD pNamePointers = (PDWORD)(hBase + hImageExportDirectory->AddressOfNames);
                PWORD pOrdinalPointers = (PWORD)(hBase + hImageExportDirectory->AddressOfNameOrdinals);
                PDWORD pAddressesPointers = (PDWORD)(hBase + hImageExportDirectory->AddressOfFunctions);

                /* Iterate over functions and check their hash. */
                for (size_t i = 0; i < hImageExportDirectory->NumberOfNames; ++i, ++pNamePointers, ++pOrdinalPointers)
                {
                    UINT32 func_hash = hash_str(hBase + *pNamePointers, importless_api<hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER)>().get_hash());
                    if (func_hash == hash)
                    {
                        DWORD dwFuncRVA = pAddressesPointers[*pOrdinalPointers];

                        /* Return function address. */
                        return hBase + dwFuncRVA;
                    }
                }
            }
        }
    };
};


namespace importless_module
{
    namespace win {
        struct LIST_ENTRY_T {
            LIST_ENTRY_T* Flink;
            LIST_ENTRY_T* Blink;
        };

        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            wchar_t* Buffer;
        };

        struct PEB_LDR_DATA_T {
            unsigned long Length;
            unsigned long Initialized;
            const char* SsHandle;
            LIST_ENTRY_T  InMemoryOrderLinks;
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            const char* Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
        };

        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY_T InLoadOrderLinks;
            LIST_ENTRY_T InMemoryOrderLinks;
            LIST_ENTRY_T InInitializationOrderLinks;
            char* DllBase;
            const char* EntryPoint;
            union {
                unsigned long SizeOfImage;
                const char* _dummy;
            };
            UNICODE_STRING_T FullDllName;
            UNICODE_STRING_T BaseDllName;
        };


    }

    /*
        Hash string with start value.
        Choosed the hash function based on "The Last Stage of Delerium. Win32 Assembly Components"
    */
    constexpr UINT32 hash_str(const wchar_t* module_name, const UINT32 value)
    {

        UINT32 hash = value;
        for (;;)
        {
            wchar_t c = *module_name;
            if (c >= L'A' && c <= L'Z')
            {
                c = c - L'A' + L'a';
            }

            module_name++;
            if (!c)
                return hash;

            hash = (((hash << 5) | (hash >> 27)) + c) & 0xFFFFFFFF;
        }
    }

    template<UINT32 hash> class importless_module
    {

    private:
        /* Getting the PEB struct from register based on architecture. */
        const win::PEB_T* peb()
        {
#if defined(_M_X64) || defined(__amd64__)
            return reinterpret_cast<const win::PEB_T*>(__readgsqword(0x60));
#elif defined(_M_IX86) || defined(__i386__)
            return reinterpret_cast<const win::PEB_T*>(__readfsdword(0x30));
#elif defined(_M_ARM) || defined(__arm__)
            return *reinterpret_cast<const win::PEB_T**>(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#elif defined(_M_ARM64) || defined(__aarch64__)
            return *reinterpret_cast<const win::PEB_T**>(__getReg(18) + 0x60);
#elif defined(_M_IA64) || defined(__ia64__)
            return *reinterpret_cast<const win::PEB_T**>(static_cast<char*>(_rdteb()) + 0x60);
#else
#error Unsupported platform. 
#endif
        }


    public:

        IMPORTLESSAPI_INLINED importless_module()
        {}

        IMPORTLESSAPI_INLINED UINT32 get_hash()
        {
            return hash;
        }

        /* Iterates over the PEB and all exported functions to find function by hash. */
        IMPORTLESSAPI_INLINED LPVOID get_base()
        {
            win::LDR_DATA_TABLE_ENTRY_T* curr_module = (win::LDR_DATA_TABLE_ENTRY_T*)peb()->Ldr->InMemoryOrderLinks.Flink;

            /* Iterate over loaded modules. */
            while (curr_module->BaseDllName.Buffer != NULL) {
                char* hBase = curr_module->DllBase;

                UINT32 module_hash = hash_str(curr_module->BaseDllName.Buffer, importless_module<hash_str(DATE_AND_TIME_UNICODE, IMPORTLESS_API_START_NUMBER)>().get_hash());
                if (module_hash == hash)
                {
                    /* Return module base. */
                    return hBase;
                }


                curr_module = (win::LDR_DATA_TABLE_ENTRY_T*)curr_module->InLoadOrderLinks.Flink;
            }

            return NULL;
        }


    };

};

/*
    Example usage:
        Handle hFile = IMPORTLESS_API(CreateFile)(Parameters);
*/
#define IMPORTLESS_API(func_name) static_cast<decltype(&func_name)>(importless_api::importless_api<importless_api::hash_str(REAL_DEFINITION(func_name), importless_api::hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER))>().get_function())

#define IMPORTLESS_API_STR(func_name, t) static_cast<t>(importless_api::importless_api<importless_api::hash_str(func_name, importless_api::hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER))>().get_function())

#define IMPORTLESS_API_WITH_MODULE(func_name, base) static_cast<decltype(&func_name)>(importless_api::importless_api<importless_api::hash_str(REAL_DEFINITION(func_name), importless_api::hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER))>().get_function(base))

#define IMPORTLESS_API_STR_WITH_BASE(func_name, base, t) static_cast<t>(importless_api::importless_api<importless_api::hash_str(func_name, importless_api::hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER))>().get_function(base))



#define IMPORTLESS_MODULE(module_name) importless_module::importless_module<importless_module::hash_str(module_name, importless_module::hash_str(DATE_AND_TIME_UNICODE, IMPORTLESS_API_START_NUMBER))>().get_base()
