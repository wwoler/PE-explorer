#include <stdio.h>
#include <Windows.h>

PIMAGE_SECTION_HEADER GetSections(PIMAGE_SECTION_HEADER pSH, size_t sections_number, const DWORD_PTR importAddr);
void GetDosHeaderInfo(PIMAGE_DOS_HEADER pDos);
void GetNTHeaderInfo32(PIMAGE_DOS_HEADER pNT);
void GetNTHeaderInfo64(PIMAGE_DOS_HEADER pNT);
void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pID, const DWORD_PTR offset, const PIMAGE_SECTION_HEADER pSH);
void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pID, const DWORD_PTR offset, const PIMAGE_SECTION_HEADER pSH);

int main(int argc, char** argv)
{
	HANDLE hFile = NULL;
	PVOID pvBuffer = NULL;
	DWORD dwFileSize = 0;

	if (argc != 2)
	{
		printf("Bad args: specify the file\a");
		exit(1);
	}

	hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwFileSize = GetFileSize(hFile, 0);
		pvBuffer = LocalAlloc(LPTR, dwFileSize);
		if (pvBuffer)
		{
			DWORD dwBytesRead = 0;
			if (!ReadFile(hFile, pvBuffer, dwFileSize, &dwBytesRead, NULL))
			{
				LocalFree(pvBuffer);
				CloseHandle(hFile);
			}
		}
	}
	else
	{
		printf("Cannot open the file\a");
		exit(1);
	}

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)(pvBuffer);
	GetDosHeaderInfo(pDos);
	const auto pNT = (PIMAGE_NT_HEADERS)((DWORD_PTR)pvBuffer + pDos->e_lfanew);
	if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		GetNTHeaderInfo32(pDos);
	if (pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		GetNTHeaderInfo64(pDos);

	return 0;
}

void GetDosHeaderInfo(PIMAGE_DOS_HEADER pDos)
{
	if (pDos == nullptr)
		return;
	printf("[~] DOS Header:\n");
	printf("\te_lfanew: 0x%X\n", pDos->e_lfanew);
	printf("\te_cblp: 0x%X\n", pDos->e_cblp);
	printf("\te_cp: 0x%X\n", pDos->e_cp);
	printf("\te_cparhdr: 0x%X\n", pDos->e_cparhdr);
	printf("\te_crlc: 0x%X\n", pDos->e_crlc);
	printf("\te_csum: 0x%X\n", pDos->e_csum);
	printf("\te_ip: 0x%X\n", pDos->e_ip);
	printf("\te_lfanew: 0x%X\n", pDos->e_lfanew);
	printf("\te_lfarlc: 0x%X\n", pDos->e_lfarlc);
	printf("\te_magic: 0x%X\n", pDos->e_magic);
	printf("\te_maxalloc: 0x%X\n", pDos->e_maxalloc);
	printf("\te_minalloc: 0x%X\n", pDos->e_minalloc);
	printf("\te_oemid: 0x%X\n", pDos->e_oemid);
	printf("\te_oeminfo: 0x%X\n", pDos->e_oeminfo);
	printf("\te_ovno: 0x%X\n", pDos->e_ovno);
	printf("\te_res: 0x%X\n", pDos->e_res);
	printf("\te_res2: 0x%X\n", pDos->e_res2);
	printf("\te_sp: 0x%X\n", pDos->e_sp);
	printf("\te_ss: 0x%X\n", pDos->e_ss);
}

void GetNTHeaderInfo32(PIMAGE_DOS_HEADER pNT)
{
	if (pNT == nullptr)
		return;

	const auto pNT32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)pNT + pNT->e_lfanew);

	IMAGE_FILE_HEADER& pFH = pNT32->FileHeader;
	IMAGE_OPTIONAL_HEADER32 pOH = pNT32->OptionalHeader;

	printf("\n[~] NT Header:\n");
	printf("\t Signature: 0x%X\n", pNT32->Signature);

	printf("\n[~] File Header:\n");
	printf("\tCharacteristics: 0x%X\n", pFH.Characteristics);
	printf("\tMachine: 0x%X\n", pFH.Machine);
	printf("\tNumberOfSections: 0x%X\n", pFH.NumberOfSections);
	printf("\tNumberOfSymbols: 0x%X\n", pFH.NumberOfSymbols);
	printf("\tPointerToSymbolTable: 0x%X\n", pFH.PointerToSymbolTable);
	printf("\tSizeOfOptionalHeader: 0x%X\n", pFH.SizeOfOptionalHeader);
	printf("\tTimeDateStamp: 0x%X\n", pFH.TimeDateStamp);

	printf("\n[~] Optional Header:\n");
	printf("\tAddressOfEntryPoint: 0x%X\n", pOH.AddressOfEntryPoint);
	printf("\tBaseOfCode: 0x%X\n", pOH.BaseOfCode);
	printf("\tCheckSum: 0x%X\n", pOH.CheckSum);
	printf("\tDataDirectory: 0x%X\n", pOH.DataDirectory);
	printf("\tDllCharacteristics: 0x%X\n", pOH.DllCharacteristics);
	printf("\tFileAlignment: 0x%X\n", pOH.FileAlignment);
	printf("\tImageBase: 0x%X\n", pOH.ImageBase);
	printf("\tLoaderFlags: 0x%X\n", pOH.LoaderFlags);
	printf("\tMagic: 0x%X\n", pOH.Magic);
	printf("\tMajorImageVersion: 0x%X\n", pOH.MajorImageVersion);
	printf("\tMajorLinkerVersion: 0x%X\n", pOH.MajorLinkerVersion);
	printf("\tMajorOperatingSystemVersion: 0x%X\n", pOH.MajorOperatingSystemVersion);
	printf("\tMajorSubsystemVersion: 0x%X\n", pOH.MajorSubsystemVersion);
	printf("\tMinorImageVersion: 0x%X\n", pOH.MinorImageVersion);
	printf("\tMinorLinkerVersion: 0x%X\n", pOH.MinorLinkerVersion);
	printf("\tMinorOperatingSystemVersion: 0x%X\n", pOH.MinorOperatingSystemVersion);
	printf("\tMinorSubsystemVersion: 0x%X\n", pOH.MinorSubsystemVersion);
	printf("\tNumberOfRvaAndSizes: 0x%X\n", pOH.NumberOfRvaAndSizes);
	printf("\tSectionAlignment: 0x%X\n", pOH.SectionAlignment);
	printf("\tSizeOfCode: 0x%X\n", pOH.SizeOfCode);
	printf("\tSizeOfHeaders: 0x%X\n", pOH.SizeOfHeaders);
	printf("\tSizeOfHeapCommit: 0x%X\n", pOH.SizeOfHeapCommit);
	printf("\tSizeOfHeapReserve: 0x%X\n", pOH.SizeOfHeapReserve);
	printf("\tSizeOfImage: 0x%X\n", pOH.SizeOfImage);
	printf("\tSizeOfInitializedData: 0x%X\n", pOH.SizeOfInitializedData);
	printf("\tSizeOfStackCommit: 0x%X\n", pOH.SizeOfStackCommit);
	printf("\tSizeOfStackReserve: 0x%X\n", pOH.SizeOfStackReserve);
	printf("\tSizeOfUninitializedData: 0x%X\n", pOH.SizeOfUninitializedData);
	printf("\tSubsystem: 0x%X\n", pOH.Subsystem);
	printf("\tWin32VersionValue: 0x%X\n", pOH.Win32VersionValue);
	
	PIMAGE_SECTION_HEADER pSH = IMAGE_FIRST_SECTION(pNT32);
	if (pSH)
		pSH = GetSections(pSH, pNT32->FileHeader.NumberOfSections, pOH.DataDirectory[1].VirtualAddress);

	DWORD_PTR offset = (DWORD_PTR)pNT + pSH->PointerToRawData;
	PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)(offset + (pOH.DataDirectory[1].VirtualAddress - pSH->VirtualAddress));
	if (pID)
		GetImports32(pID, offset, pSH);

}

void GetNTHeaderInfo64(PIMAGE_DOS_HEADER pNT)
{
	if (pNT == nullptr)
		return;

	const auto pNT64 = (PIMAGE_NT_HEADERS)((DWORD_PTR)pNT + pNT->e_lfanew);

	IMAGE_FILE_HEADER& pFH = pNT64->FileHeader;
	IMAGE_OPTIONAL_HEADER64& pOH = pNT64->OptionalHeader;

	printf("\n[~] NT Header:\n");
	printf("\t Signature: 0x%X\n", pNT64->Signature);

	printf("\n[~] File Header:\n");
	printf("\tCharacteristics: 0x%X\n", pFH.Characteristics);
	printf("\tMachine: 0x%X\n", pFH.Machine);
	printf("\tNumberOfSections: 0x%X\n", pFH.NumberOfSections);
	printf("\tNumberOfSymbols: 0x%X\n", pFH.NumberOfSymbols);
	printf("\tPointerToSymbolTable: 0x%X\n", pFH.PointerToSymbolTable);
	printf("\tSizeOfOptionalHeader: 0x%X\n", pFH.SizeOfOptionalHeader);
	printf("\tTimeDateStamp: 0x%X\n", pFH.TimeDateStamp);

	printf("\n[~] Optional Header:\n");
	printf("\tAddressOfEntryPoint: 0x%X\n", pOH.AddressOfEntryPoint);
	printf("\tBaseOfCode: 0x%X\n", pOH.BaseOfCode);
	printf("\tCheckSum: 0x%X\n", pOH.CheckSum);
	printf("\tDataDirectory: 0x%X\n", pOH.DataDirectory);
	printf("\tDllCharacteristics: 0x%X\n", pOH.DllCharacteristics);
	printf("\tFileAlignment: 0x%X\n", pOH.FileAlignment);
	printf("\tImageBase: 0x%X\n", pOH.ImageBase);
	printf("\tLoaderFlags: 0x%X\n", pOH.LoaderFlags);
	printf("\tMagic: 0x%X\n", pOH.Magic);
	printf("\tMajorImageVersion: 0x%X\n", pOH.MajorImageVersion);
	printf("\tMajorLinkerVersion: 0x%X\n", pOH.MajorLinkerVersion);
	printf("\tMajorOperatingSystemVersion: 0x%X\n", pOH.MajorOperatingSystemVersion);
	printf("\tMajorSubsystemVersion: 0x%X\n", pOH.MajorSubsystemVersion);
	printf("\tMinorImageVersion: 0x%X\n", pOH.MinorImageVersion);
	printf("\tMinorLinkerVersion: 0x%X\n", pOH.MinorLinkerVersion);
	printf("\tMinorOperatingSystemVersion: 0x%X\n", pOH.MinorOperatingSystemVersion);
	printf("\tMinorSubsystemVersion: 0x%X\n", pOH.MinorSubsystemVersion);
	printf("\tNumberOfRvaAndSizes: 0x%X\n", pOH.NumberOfRvaAndSizes);
	printf("\tSectionAlignment: 0x%X\n", pOH.SectionAlignment);
	printf("\tSizeOfCode: 0x%X\n", pOH.SizeOfCode);
	printf("\tSizeOfHeaders: 0x%X\n", pOH.SizeOfHeaders);
	printf("\tSizeOfHeapCommit: 0x%X\n", pOH.SizeOfHeapCommit);
	printf("\tSizeOfHeapReserve: 0x%X\n", pOH.SizeOfHeapReserve);
	printf("\tSizeOfImage: 0x%X\n", pOH.SizeOfImage);
	printf("\tSizeOfInitializedData: 0x%X\n", pOH.SizeOfInitializedData);
	printf("\tSizeOfStackCommit: 0x%X\n", pOH.SizeOfStackCommit);
	printf("\tSizeOfStackReserve: 0x%X\n", pOH.SizeOfStackReserve);
	printf("\tSizeOfUninitializedData: 0x%X\n", pOH.SizeOfUninitializedData);
	printf("\tSubsystem: 0x%X\n", pOH.Subsystem);
	printf("\tWin32VersionValue: 0x%X\n", pOH.Win32VersionValue);

	PIMAGE_SECTION_HEADER pSH = IMAGE_FIRST_SECTION(pNT64);
	if (pSH)
		pSH = GetSections(pSH, pNT64->FileHeader.NumberOfSections, pOH.DataDirectory[1].VirtualAddress);

	DWORD_PTR offset = (DWORD_PTR)pNT + pSH->PointerToRawData;
	PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)(offset + (pOH.DataDirectory[1].VirtualAddress - pSH->VirtualAddress));
	if (pID)
		GetImports64(pID, offset, pSH);
}

PIMAGE_SECTION_HEADER GetSections(PIMAGE_SECTION_HEADER pSH, size_t sections_number, const DWORD_PTR importAddr)
{
	PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;
	printf("\n[~] Sections\n");
	for (size_t k = 0; k < sections_number; ++k)
	{
		printf("\tSection: %s\n", pSH->Name);
		printf("Size: %i bytes\n", pSH->SizeOfRawData);

		if (importAddr >= pSH->VirtualAddress && importAddr < pSH->VirtualAddress + pSH->Misc.VirtualSize)
			pImageImportHeader = pSH;
		++pSH;
	}
	return pImageImportHeader;
}

void GetImports32(PIMAGE_IMPORT_DESCRIPTOR pID, const DWORD_PTR offset, const PIMAGE_SECTION_HEADER pSH)
{
	printf("\n[~] IMPORTED DLL:");

	while (pID->Name != 0)
	{
		printf("\n\tDLL Name: %s\n", (char*)(offset + (pID->Name - pSH->VirtualAddress)));

		if (pID->OriginalFirstThunk == 0)
			continue;

		auto pTH = (PIMAGE_THUNK_DATA32)(offset + (pID->OriginalFirstThunk - pSH->VirtualAddress));

		printf("\n\tImported functions:\n");

		while (pTH->u1.AddressOfData != 0)
		{
			if (pTH->u1.AddressOfData >= IMAGE_ORDINAL_FLAG32)
			{
				++pTH;
				continue;
			}

			const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)pTH->u1.AddressOfData;
			if (pImageImportByName == nullptr)
				continue;

			if (pTH->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				printf("\t\t0x%X (Ordinal): %s\n", (uintptr_t)pTH->u1.AddressOfData, offset + (pImageImportByName->Name - pSH->VirtualAddress));
			else
				printf("\t\t%s\n", offset + (pImageImportByName->Name - pSH->VirtualAddress));

			++pTH;
		}

		++pID;
	}
}

void GetImports64(PIMAGE_IMPORT_DESCRIPTOR pID, const DWORD_PTR offset, const PIMAGE_SECTION_HEADER pSH)
{
	printf("\n[~] Imported DLL:\n");

	while (pID->Name != 0)
	{
		printf("\tDLL Name: %s\n", (char*)(offset + (pID->Name - pSH->VirtualAddress)));

		if (pID->OriginalFirstThunk == 0)
			continue;

		auto pTH = (PIMAGE_THUNK_DATA64)(offset + (pID->OriginalFirstThunk - pSH->VirtualAddress));

		printf("\n[~] Imported functions:\n");

		while (pTH->u1.AddressOfData != 0)
		{
			if (pTH->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64)
			{
				++pTH;
				continue;
			}

			const auto pImageImportByName = (PIMAGE_IMPORT_BY_NAME)pTH->u1.AddressOfData;
			if (pImageImportByName == nullptr)
				continue;

			if (pTH->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				printf("\t0x%X (Ordinal): %s\n", (uintptr_t)pTH->u1.AddressOfData, offset + (pImageImportByName->Name - pSH->VirtualAddress));
			else
				printf("\t%s\n", offset + (pImageImportByName->Name - pSH->VirtualAddress));

			++pTH;
		}

		++pID;
	}
}