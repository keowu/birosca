/*
 _   __ _____ _____  _    _ _   _
| | / /|  ___|  _  || |  | | | | |
| |/ / | |__ | | | || |  | | | | |
|    \ |  __|| | | || |/\| | | | |
| |\  \| |___\ \_/ /\  /\  / |_| |
\_| \_/\____/ \___/  \/  \/ \___/
							2023
Copyright (c) Fluxuss Cyber Tech Desenvolvimento de Software, SLU (FLUXUSS)
Copyright (c) Fluxuss Software Security, LLC
*/
#include <Windows.h>
#include <vector>
#include <functional>
#include <algorithm>
#include "WINPESection.hh"

class WINPEParser {

private:

#define GetInitialHeaderReadSz(bReadSectionHeaders) sizeof(IMAGE_DOS_HEADER) + 0x300 + sizeof(IMAGE_NT_HEADERS64)
#define AlignValue(dwBadValue, dwAlignTo) (((dwBadValue + dwAlignTo - 1) / dwAlignTo) * dwAlignTo)

	const uintptr_t FileAlignConst = 0x200;
	const char* chFileName;
	uintptr_t uipModuleBaseAddress{ 0 };

	PIMAGE_DOS_HEADER pDOSH{ 0 };
	unsigned char* pDOSStub{ 0 };
	uintptr_t uipDosStubSz{ 0 };
	PIMAGE_NT_HEADERS32 pIMGNTH32{ 0 };
	PIMAGE_NT_HEADERS64 pIMGNTH64{ 0 };

	std::vector<WINPESection> vecPESect;
	unsigned char* ucOverLayData{ 0 };
	uintptr_t uipOverlaySz{ 0 };

	unsigned char* chFileMemory{ 0 };
	unsigned char* chHeaderMemory{ 0 };

	HANDLE hFile{ 0 };
	uintptr_t uipFileSz{ 0 };

	HANDLE hProcess{ 0 };

	std::function<uintptr_t(unsigned char*, int)> isMemoryNotNull = [&](unsigned char* data, int iDataSz) -> uintptr_t {

		for (auto i = (iDataSz - 1); i >= 0; --i) if (data[i] != 0) return i + 1;

		return 0;
	};

	std::function<BOOL(BOOL)> ReadPEHeaderFromProcess = [&](BOOL bReadSectionHeaders) -> BOOL {

		DWORD dwCorrectSize = 0;

		auto dwReadSize = GetInitialHeaderReadSz(bReadSectionHeaders);

		this->chHeaderMemory = new unsigned char[dwReadSize];

		if (!ReadProcessMemory(this->hProcess, reinterpret_cast<LPCVOID>(this->uipModuleBaseAddress), this->chHeaderMemory, dwReadSize, NULL))
			return FALSE;//throw std::runtime_error("Error read process memory for pe parser on pe fixer");

		this->GetDosAndNTHeader(this->chHeaderMemory, dwReadSize);

		if (IsValidPE()) {

			dwCorrectSize = this->CalcCorrectPEHeaderSz(bReadSectionHeaders);

			if (dwReadSize < dwCorrectSize) {

				delete[] this->chHeaderMemory;

				this->chHeaderMemory = new unsigned char[dwCorrectSize];

				if (!ReadProcessMemory(this->hProcess, reinterpret_cast<LPCVOID>(this->uipModuleBaseAddress), this->chHeaderMemory, dwCorrectSize, NULL)) return FALSE;

				this->GetDosAndNTHeader(this->chHeaderMemory, dwCorrectSize);

			}

		}

		return TRUE;
	};

	std::function<BOOL()> GetSectionHeaders = [&]() -> BOOL {

		auto pSectionHeader = IMAGE_FIRST_SECTION(this->pIMGNTH32);

		WINPESection peSection;

		this->vecPESect.clear();

		this->vecPESect.reserve(this->GetNumberOfSections());

		for (auto i = 0; i < this->GetNumberOfSections(); i++) {

			RtlCopyMemory(&peSection.imgSec, pSectionHeader, sizeof(IMAGE_SECTION_HEADER));

			this->vecPESect.push_back(peSection);

			pSectionHeader++;
		}

		return TRUE;
	};

	std::function<void(unsigned char*, long)> GetDosAndNTHeader = [&](unsigned char* ucMemory, long lSz) -> void {

		this->pDOSH = reinterpret_cast<PIMAGE_DOS_HEADER>(ucMemory);

		this->pIMGNTH32 = 0;

		this->pIMGNTH64 = 0;

		this->pDOSStub = 0;

		if (this->pDOSH->e_lfanew > 0 && this->pDOSH->e_lfanew < lSz) {

			this->pIMGNTH32 = reinterpret_cast<PIMAGE_NT_HEADERS32>((uintptr_t)this->pDOSH + this->pDOSH->e_lfanew);

			this->pIMGNTH64 = reinterpret_cast<PIMAGE_NT_HEADERS64>((uintptr_t)this->pDOSH + this->pDOSH->e_lfanew);

			if (this->pDOSH->e_lfanew > sizeof(IMAGE_DOS_HEADER)) {

				this->uipDosStubSz = this->pDOSH->e_lfanew - sizeof(IMAGE_DOS_HEADER);

				this->pDOSStub = reinterpret_cast<unsigned char*>((uintptr_t)this->pDOSH + sizeof(IMAGE_DOS_HEADER));

			}
			else if (this->pDOSH->e_lfanew < sizeof(IMAGE_DOS_HEADER)) this->pDOSH->e_lfanew = sizeof(IMAGE_DOS_HEADER);

		}

	};

	std::function<uintptr_t(BOOL)> CalcCorrectPEHeaderSz = [&](BOOL bReadSecHeaders) -> uintptr_t {

		auto szCorrect = this->pDOSH->e_lfanew + 50;

		if (bReadSecHeaders) szCorrect += this->GetNumberOfSections() * sizeof(IMAGE_SECTION_HEADER);
		if (this->IsPE32()) szCorrect += sizeof(IMAGE_NT_HEADERS32);
		else if (this->IsPE64()) szCorrect += sizeof(IMAGE_NT_HEADERS64);
		else szCorrect = 0;

		return szCorrect;
	};

	std::function<BOOL()> OpenFileHandle = [&]() -> BOOL {

		this->hFile = CreateFileA(this->chFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

		return this->hFile != INVALID_HANDLE_VALUE;
	};

	std::function<void()> RemoveIatDir = [&]() -> void {

	};

	std::function<void()> CloseFileHandle = [&]() -> void {

		if (this->hFile == INVALID_HANDLE_VALUE) return;

		CloseHandle(this->hFile);

		this->hFile = INVALID_HANDLE_VALUE;

	};

	std::function<BOOL(const char*)> OpenWriteFileHandle = [&](const char* chFile) -> BOOL {

		if (chFile) this->hFile = CreateFileA(chFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		return this->hFile != INVALID_HANDLE_VALUE;
	};

	std::function<BOOL(HANDLE, uintptr_t, uintptr_t)> WriteZeroMemoryToFile = [&](HANDLE hFile, uintptr_t uipFileOffset, uintptr_t uipSz) -> BOOL {

		auto pZeroMem = std::calloc(uipSz, 1);

		this->WriteMemoryFile(hFile, uipFileOffset, uipSz, pZeroMem);

		std::free(pZeroMem);

		return TRUE;
	};

	std::function<BOOL(uintptr_t, WINPESection&, BOOL)> ReadSectionFrom = [&](uintptr_t uipReadOffset, WINPESection& PeFileSection, BOOL isProcess) -> BOOL {

		auto bRet{ TRUE };

		const auto dwMaxReadSz = 100;

		auto dwCurrentReadSz{ 0 };

		unsigned char ucData[dwMaxReadSz]{ 0 };

		auto dwValuesFound{ 0 };

		auto dwReadSz{ 0 };

		uintptr_t uipCurrentOffset{ 0 };

		PeFileSection.data = { 0 };

		PeFileSection.uipDataSz = { 0 };

		dwReadSz = PeFileSection.uipNormalSz;

		/*
			Section withou data is valid
		*/
		if (!uipReadOffset || !dwReadSz) return TRUE;

		if (dwReadSz <= dwMaxReadSz) {

			PeFileSection.uipDataSz = dwReadSz;

			PeFileSection.uipNormalSz = dwReadSz;

			if (isProcess) return ReadPESectionFromProcess(uipReadOffset, PeFileSection);
			//else we do not use files here, only memory

		}

		dwCurrentReadSz = dwReadSz % dwMaxReadSz;

		if (!dwCurrentReadSz) dwCurrentReadSz = dwMaxReadSz;

		uipCurrentOffset = uipReadOffset + dwReadSz - dwCurrentReadSz;

		while (uipCurrentOffset >= uipReadOffset) {

			ZeroMemory(ucData, dwCurrentReadSz);

			if (isProcess) bRet = ReadProcessMemory(this->hProcess, reinterpret_cast<LPCVOID>(uipCurrentOffset), ucData, dwCurrentReadSz, NULL);

			if (!bRet) break;

			dwValuesFound = isMemoryNotNull(ucData, dwCurrentReadSz);

			if (dwValuesFound) {

				uipCurrentOffset += dwValuesFound;

				if (uipReadOffset < uipCurrentOffset) {

					PeFileSection.uipDataSz = static_cast<DWORD>(uipCurrentOffset - uipReadOffset);

					PeFileSection.uipDataSz += sizeof(DWORD);

					if (PeFileSection.uipNormalSz < PeFileSection.uipDataSz) PeFileSection.uipDataSz = PeFileSection.uipNormalSz;

				}

				break;
			}

			dwCurrentReadSz = dwMaxReadSz;

			uipCurrentOffset -= dwCurrentReadSz;

		}

		if (PeFileSection.uipDataSz) if (isProcess) bRet = ReadPESectionFromProcess(uipReadOffset, PeFileSection);

		return bRet;
	};

	std::function<BOOL(uintptr_t, WINPESection&)> ReadPESectionFromProcess = [&](uintptr_t uipReadOffset, WINPESection& peSection) -> BOOL {

		peSection.data = new unsigned char[peSection.uipDataSz];

		return ReadProcessMemory(this->hProcess, reinterpret_cast<LPCVOID>(uipReadOffset), peSection.data, peSection.uipDataSz, NULL);

	};

public:

	std::function<void(HANDLE, uintptr_t, BOOL)> PE = [&](HANDLE hProcess, uintptr_t uipImageBase, BOOL bReadSecH = true) {

		this->uipModuleBaseAddress = uipImageBase;

		this->hProcess = hProcess;

		this->ReadPEHeaderFromProcess(bReadSecH);

		if (bReadSecH) if (this->IsValidPE()) this->GetSectionHeaders();

	};

	std::function<BOOL()> IsValidPE = [&]() -> BOOL {

		return this->pDOSH->e_magic == IMAGE_DOS_SIGNATURE && this->pIMGNTH32->Signature == IMAGE_NT_SIGNATURE;
	};

	std::function<BOOL()> IsPE64 = [&]() -> BOOL {

		return this->IsValidPE() ? this->pIMGNTH32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC : FALSE;
	};

	std::function<BOOL()> IsPE32 = [&]() -> BOOL {

		return this->IsValidPE() ? this->pIMGNTH32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC : FALSE;
	};

	std::function<DWORD()> GetNumberOfSections = [&]() -> uintptr_t {

		return this->pIMGNTH32->FileHeader.NumberOfSections;
	};

	std::function<BOOL(uintptr_t, uintptr_t, const char*)> DumpProcess = [&](uintptr_t uipImageBase, uintptr_t OEP, const char* chDumpFilePath) -> BOOL {

		if (this->ReadPESectionsFromProcess()) {

			this->SetDefaultFileAlignment();

			this->SetEntryPointRVA(static_cast<uintptr_t>(OEP - this->uipModuleBaseAddress));

			this->AlignAllSectionHeaders();

			this->FixPEHeaders();

			this->GetFileOverlay();

			this->SavePEFileToDisk(chDumpFilePath);

		}


		return FALSE;
	};

	std::function<BOOL()> ReadPESectionsFromProcess = [&]() -> BOOL {

		auto dwReadOffset = 0;

		this->vecPESect.reserve(this->GetNumberOfSections());

		for (auto i = 0; i < this->GetNumberOfSections(); i++) {

			dwReadOffset = this->vecPESect[i].imgSec.VirtualAddress + this->uipModuleBaseAddress;

			this->vecPESect[i].uipNormalSz = this->vecPESect[i].imgSec.Misc.VirtualSize;

			if (!ReadSectionFrom(dwReadOffset, this->vecPESect[i], true)) return FALSE;

		}

		return TRUE;
	};

	std::function<void()> SetDefaultFileAlignment = [&]() -> void {

		if (this->IsPE32()) this->pIMGNTH32->OptionalHeader.FileAlignment = this->FileAlignConst; else this->pIMGNTH64->OptionalHeader.FileAlignment = this->FileAlignConst;

	};

	std::function<void(uintptr_t)> SetEntryPointRVA = [&](uintptr_t uipEntryPoint) -> void {

		if (this->IsPE32()) this->pIMGNTH32->OptionalHeader.AddressOfEntryPoint = uipEntryPoint; else this->pIMGNTH64->OptionalHeader.AddressOfEntryPoint = uipEntryPoint;

	};

	std::function<void()> AlignAllSectionHeaders = [&]() -> void {

		auto dwSectionAlignment{ 0 };

		auto dwFileAlignment{ 0 };

		auto dwNewFileSz{ 0 };

		if (this->IsPE32()) {

			dwSectionAlignment = this->pIMGNTH32->OptionalHeader.SectionAlignment;

			dwFileAlignment = this->pIMGNTH32->OptionalHeader.FileAlignment;

		}
		else {

			dwSectionAlignment = this->pIMGNTH64->OptionalHeader.SectionAlignment;

			dwFileAlignment = this->pIMGNTH64->OptionalHeader.FileAlignment;

		}

		std::sort(this->vecPESect.begin(), this->vecPESect.end(), [&](const WINPESection& psecOne, const WINPESection& psecTwo) -> bool {

			return psecOne.imgSec.PointerToRawData < psecTwo.imgSec.PointerToRawData;

			});

		dwNewFileSz = this->pDOSH->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + this->pIMGNTH32->FileHeader.SizeOfOptionalHeader + (this->GetNumberOfSections() * sizeof(IMAGE_SECTION_HEADER));

		for (auto i = 0; i < this->GetNumberOfSections(); i++) {

			this->vecPESect[i].imgSec.VirtualAddress = AlignValue(this->vecPESect[i].imgSec.VirtualAddress, dwSectionAlignment);
			this->vecPESect[i].imgSec.Misc.VirtualSize = AlignValue(this->vecPESect[i].imgSec.Misc.VirtualSize, dwSectionAlignment);

			this->vecPESect[i].imgSec.PointerToRawData = AlignValue(dwNewFileSz, dwSectionAlignment);
			this->vecPESect[i].imgSec.SizeOfRawData = AlignValue(this->vecPESect[i].uipDataSz, dwSectionAlignment);

			dwNewFileSz = this->vecPESect[i].imgSec.PointerToRawData + this->vecPESect[i].imgSec.SizeOfRawData;

		}

		std::sort(this->vecPESect.begin(), this->vecPESect.end(), [&](const WINPESection& psecOne, const WINPESection& psecTwo) -> bool {

			return psecOne.imgSec.VirtualAddress < psecTwo.imgSec.VirtualAddress;

			});

	};

	std::function<void()> FixPEHeaders = [&]() -> void {

		auto dwSz = this->pDOSH->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

		if (this->IsPE32()) {

			/*
				Remove bound import directory
			*/
			this->pIMGNTH32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
			this->pIMGNTH32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

			/*
				Max 16, zero is used for possible garbage values
			*/
			for (auto i = this->pIMGNTH32->OptionalHeader.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {

				this->pIMGNTH32->OptionalHeader.DataDirectory[i].Size = 0;
				this->pIMGNTH32->OptionalHeader.DataDirectory[i].VirtualAddress = 0;

			}

			this->pIMGNTH32->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			this->pIMGNTH32->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);

			this->pIMGNTH32->OptionalHeader.SizeOfImage = this->GetSectionHeaderBasedSizeOfImage();

			if (this->uipModuleBaseAddress) this->pIMGNTH32->OptionalHeader.ImageBase = this->uipModuleBaseAddress;

			this->pIMGNTH32->OptionalHeader.SizeOfHeaders = AlignValue(dwSz + this->pIMGNTH32->FileHeader.SizeOfOptionalHeader + (this->GetNumberOfSections() * sizeof(IMAGE_SECTION_HEADER)), this->pIMGNTH32->OptionalHeader.FileAlignment);

		}
		else {

			/*
				Remove bound import directory
			*/
			this->pIMGNTH64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
			this->pIMGNTH64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;

			/*
				Max 16, zero is used for possible garbage values
			*/
			for (auto i = this->pIMGNTH64->OptionalHeader.NumberOfRvaAndSizes; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {

				this->pIMGNTH64->OptionalHeader.DataDirectory[i].Size = 0;
				this->pIMGNTH64->OptionalHeader.DataDirectory[i].VirtualAddress = 0;

			}

			this->pIMGNTH64->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
			this->pIMGNTH64->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

			this->pIMGNTH64->OptionalHeader.SizeOfImage = this->GetSectionHeaderBasedSizeOfImage();

			if (this->uipModuleBaseAddress) this->pIMGNTH64->OptionalHeader.ImageBase = this->uipModuleBaseAddress;

			this->pIMGNTH64->OptionalHeader.SizeOfHeaders = AlignValue(dwSz + this->pIMGNTH64->FileHeader.SizeOfOptionalHeader + (this->GetNumberOfSections() * sizeof(IMAGE_SECTION_HEADER)), this->pIMGNTH64->OptionalHeader.FileAlignment);

		}

		//this->RemoveIatDir(); not remove because vmp1.x breake it some circunstancies

	};

	std::function<uintptr_t()> GetSectionHeaderBasedSizeOfImage = [&]() -> uintptr_t {

		auto dwLastVirtualOffset{ 0 }, dwLastVirtualSz{ 0 };

		for (auto i = 0; i < this->GetNumberOfSections(); i++) {

			if ((this->vecPESect[i].imgSec.VirtualAddress + this->vecPESect[i].imgSec.Misc.VirtualSize) > (dwLastVirtualOffset + dwLastVirtualSz)) {

				dwLastVirtualOffset = this->vecPESect[i].imgSec.VirtualAddress;
				dwLastVirtualSz = this->vecPESect[i].imgSec.Misc.VirtualSize;

			}

		}

		return (dwLastVirtualSz + dwLastVirtualOffset);

	};

	std::function<BOOL()> GetFileOverlay = [&]() -> BOOL {

		DWORD dwNumberOfBytesRead{ 0 };
		auto bRetValue = FALSE;

		auto chFileName = this->chFileName;

		if (std::invoke([&]() -> BOOL { // Has Over Lay Data

			/*
				Get File Size
			*/
			LONGLONG dwFileSz{ 0 };

			auto hFile = CreateFileA(chFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

			if (hFile == INVALID_HANDLE_VALUE) return FALSE;

			LARGE_INTEGER liFileSz{ 0 };

			if (!GetFileSizeEx(hFile, &liFileSz)) return FALSE;

			CloseHandle(hFile);

			/*
				Checking overlay in this binary
			*/
			return liFileSz.QuadPart > this->GetSectionHeaderBasedFileSize();

			})) return FALSE;

		if (this->OpenFileHandle()) {

			auto dwOverlayOffset = this->GetSectionHeaderBasedFileSize();

			LARGE_INTEGER liFileSz{ 0 };

			if (!GetFileSizeEx(this->hFile, &liFileSz)) return FALSE;
			
			auto dwOverlaySz = liFileSz.QuadPart - dwOverlayOffset;

			this->ucOverLayData = new unsigned char[dwOverlaySz];
			
			SetFilePointer(this->hFile, dwOverlayOffset, NULL, FILE_BEGIN);

			if (ReadFile(this->hFile, this->ucOverLayData, dwOverlaySz, &dwNumberOfBytesRead, NULL)) bRetValue = TRUE;

			this->CloseFileHandle();

		}

		return bRetValue;
	};

	std::function<uintptr_t()> GetSectionHeaderBasedFileSize = [&]() -> uintptr_t {

		auto dwLastRawOffset{ 0 }, dwLastRawSz{ 0 };

		for (auto i = 0; i < this->GetNumberOfSections(); i++) {

			if ((this->vecPESect[i].imgSec.PointerToRawData + this->vecPESect[i].imgSec.SizeOfRawData) > (dwLastRawOffset + dwLastRawSz)) {

				dwLastRawOffset = this->vecPESect[i].imgSec.PointerToRawData;

				dwLastRawSz = this->vecPESect[i].imgSec.SizeOfRawData;

			}

		}

		return (dwLastRawSz + dwLastRawOffset);

	};

	std::function<BOOL(const char*)> SavePEFileToDisk = [&](const char* chFile) -> BOOL {

		auto bRetValue = TRUE;

		auto dwFileOffset{ 0 }, dwWriteSz{ 0 };

		if (this->GetNumberOfSections() != this->vecPESect.size()) return FALSE;

		if (this->OpenWriteFileHandle(chFile)) {

			dwWriteSz = sizeof(IMAGE_DOS_HEADER);

			if (!this->WriteMemoryFile(hFile, dwFileOffset, dwWriteSz, this->pDOSH)) return FALSE;

			dwFileOffset += dwWriteSz;

			if (this->uipDosStubSz && this->pDOSStub) {

				dwWriteSz = this->uipDosStubSz;

				if (!this->WriteMemoryFile(hFile, dwFileOffset, dwWriteSz, this->pDOSStub)) return FALSE;

				dwFileOffset += dwWriteSz;

			}

			if (this->IsPE32()) dwWriteSz = sizeof(IMAGE_NT_HEADERS32); else dwWriteSz = sizeof(IMAGE_NT_HEADERS64);

			if (!this->WriteMemoryFile(hFile, dwFileOffset, dwWriteSz, this->pIMGNTH32)) return FALSE;

			dwFileOffset += dwWriteSz;

			dwWriteSz = sizeof(IMAGE_SECTION_HEADER);

			for (auto i = 0; i < this->GetNumberOfSections(); i++) {

				if (!this->WriteMemoryFile(hFile, dwFileOffset, dwWriteSz, &this->vecPESect[i].imgSec)) return FALSE;

				dwFileOffset += dwWriteSz;

			}

			for (auto i = 0; i < this->GetNumberOfSections(); i++) {

				if (!this->vecPESect[i].imgSec.PointerToRawData) continue;

				if (this->vecPESect[i].imgSec.PointerToRawData > dwFileOffset) {

					dwWriteSz = this->vecPESect[i].imgSec.PointerToRawData - dwFileOffset;

					if (!this->WriteZeroMemoryToFile(hFile, dwFileOffset, dwWriteSz)) return FALSE;

					dwFileOffset += dwWriteSz;

				}

				dwWriteSz = this->vecPESect[i].uipDataSz;

				if (dwWriteSz) {

					if (!this->WriteMemoryFile(hFile, this->vecPESect[i].imgSec.PointerToRawData, dwWriteSz, this->vecPESect[i].data)) return FALSE;

					dwFileOffset += dwWriteSz;

					if (this->vecPESect[i].uipDataSz < this->vecPESect[i].imgSec.SizeOfRawData) {

						dwWriteSz = this->vecPESect[i].imgSec.SizeOfRawData - this->vecPESect[i].uipDataSz;

						if (!this->WriteZeroMemoryToFile(hFile, dwFileOffset, dwWriteSz)) return FALSE;

						dwFileOffset += dwWriteSz;

					}

				}

			}

			if (this->uipOverlaySz && this->ucOverLayData) {

				dwWriteSz = this->uipOverlaySz;

				if (!this->WriteMemoryFile(hFile, dwFileOffset, dwWriteSz, this->ucOverLayData)) return FALSE;

				dwFileOffset += dwWriteSz;

			}

			SetEndOfFile(hFile);

			CloseHandle(hFile);

		}

		return bRetValue;
	};

	std::function<BOOL(HANDLE, LONG, DWORD, LPCVOID)> WriteMemoryFile = [&](HANDLE hFile, LONG lOffset, DWORD dwSz, LPCVOID lpBuffer) -> BOOL {


		if ((hFile != INVALID_HANDLE_VALUE) && lpBuffer) {


			if ((SetFilePointer(hFile, lOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) && (GetLastError() != NO_ERROR)) return FALSE;

			if (WriteFile(hFile, lpBuffer, dwSz, NULL, NULL)) return TRUE;

		}

		return FALSE;
	};

};
