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
#pragma once
#include <iostream>
#include <functional>
#include <filesystem>
#include <Windows.h>
#include <psapi.h>
#include <winternl.h>
#include <shlobj_core.h>
#pragma comment(lib, "ntdll.lib") //To fix references from ntdll
#include "VMPType.hh"
#include "VMPkEOVirtualMachine.hh"

class VMPProcess {

private:

	typedef struct _VMPP {
		std::string strProcessName{ 0 };
		STARTUPINFOA si{ 0 };
		PROCESS_INFORMATION pi{ 0 };
		uintptr_t ImageBase{ 0 };
		long long llPeSzDisk{ 0 };
		uintptr_t uipVmpStubEntryPoint{ 0 };
		VMPType::VMPROTECT_VERSION vmpType;
	} VMPP;

	VMPP vmpp;

	std::function<BOOL()> IsValidPE = [&]() -> BOOL {

		UINT16 MZ{ 0 };

		ReadProcessMemory(this->vmpp.pi.hProcess, (LPCVOID)this->vmpp.ImageBase, &MZ, sizeof(UINT16), NULL);

		return MZ == IMAGE_DOS_SIGNATURE;
	};

	std::function<VOID()> GetPeDiskSz = [&]() -> VOID {

		auto hFile = CreateFileA(this->vmpp.strProcessName.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile != INVALID_HANDLE_VALUE) {

			LARGE_INTEGER liSz{ 0 };

			GetFileSizeEx(hFile, &liSz);

			this->vmpp.llPeSzDisk = liSz.QuadPart;

			CloseHandle(hFile);

		}

		return;
	};


	std::function<void()> PreparateVmpMachineStub = [&]() {

		if (!IsUserAnAdmin()) throw std::runtime_error("I need admin permission for PreparateVmpMachineStub");

		auto strPath(std::filesystem::current_path().string());

		strPath.append("KELAIN.dll");

		if(!CopyFileA(strPath.c_str(), "C:\\KELAIN.dll", FALSE)) throw std::runtime_error("Fail copy Lain to serial memory of your computer!");

		auto hFile = CreateFileA(this->vmpp.strProcessName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		
		if (hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("Error on open PE FILE");

		auto dwFileSz = GetFileSize(hFile, NULL);

		auto pByte = new BYTE[dwFileSz];

		if (!ReadFile(hFile, pByte, dwFileSz, NULL, NULL)) throw std::runtime_error("Error on read PE FILE");

		auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pByte);

		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("Invalid PE File !");

		auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<UINT_PTR>(pByte) + dosHeader->e_lfanew);
		auto sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
		auto fileHeader = &(ntHeaders->FileHeader);

		//Save original VMP Machine entry point
		this->vmpp.uipVmpStubEntryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;

		auto firstSection = reinterpret_cast<PIMAGE_SECTION_HEADER>((reinterpret_cast<UINT_PTR>(fileHeader)) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);

		auto nSectionInjection = &firstSection[ntHeaders->FileHeader.NumberOfSections];

		auto lastSection = &firstSection[ntHeaders->FileHeader.NumberOfSections - 1];

		memset(nSectionInjection, 0, sizeof(IMAGE_SECTION_HEADER));

		memcpy(&nSectionInjection->Name, ".KEOVMP", min(strlen(".KEOVMP"), 8));

		nSectionInjection->Misc.VirtualSize = 2048;

		nSectionInjection->VirtualAddress = P2ALIGNUP(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);
		
		nSectionInjection->SizeOfRawData = P2ALIGNUP(2048, ntHeaders->OptionalHeader.FileAlignment);
		
		nSectionInjection->PointerToRawData = dwFileSz;

		nSectionInjection->Characteristics = 0x60000020;

		ntHeaders->FileHeader.NumberOfSections += 1;

		ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(nSectionInjection->VirtualAddress + nSectionInjection->Misc.VirtualSize, ntHeaders->OptionalHeader.SectionAlignment);

		memset(reinterpret_cast<PVOID>(reinterpret_cast<UINT_PTR>(pByte) + nSectionInjection->PointerToRawData), 0, nSectionInjection->SizeOfRawData);

		SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

		//Find begin stub
		auto rva{ 0 };

		for (; rva < 1000; rva++) if (memcmp(&*(g_FLU_KEO_VMP_LOADER + rva), g_INIT_ASM, 4) == 0) break;

		ntHeaders->OptionalHeader.AddressOfEntryPoint = nSectionInjection->VirtualAddress + rva; //set new oep

		WriteFile(hFile, pByte, dwFileSz, NULL, NULL);

		auto first = IMAGE_FIRST_SECTION(ntHeaders);
		auto last = first + (ntHeaders->FileHeader.NumberOfSections - 1);

		SetFilePointer(hFile, last->PointerToRawData, NULL, FILE_BEGIN);

		memcpy(&*(g_FLU_KEO_VMP_LOADER + 0x3CA), &this->vmpp.uipVmpStubEntryPoint, 4);

		WriteFile(hFile, g_FLU_KEO_VMP_LOADER, 2048, NULL, NULL);

		CloseHandle(hFile);

		std::cout << "KeoStub is now on the file. please remove this option(SET TO FALSE), and re-run the same file to init unpacking process\n";

		ExitProcess(-1);

	};

public:

	std::function<VMPP()> GetVMPP = [&]() -> VMPP {
		return this->vmpp;
	};

	/// <summary>
	///		This is used for old OS 32-bit based processor. please don't use. use a x64 os instahed
	/// </summary>
	std::function<BOOL(std::string&, VMPType::VMPROTECT_VERSION, BOOL)> InitProcess32 = [&](std::string& strName, VMPType::VMPROTECT_VERSION vmpInfo, BOOL insertKeoStub) -> BOOL {

		this->vmpp.strProcessName = strName;

		if (insertKeoStub) this->PreparateVmpMachineStub();

		this->vmpp.si.cb = sizeof(this->vmpp.si);
																					//CREATE_SUSPENDED
		if (!CreateProcessA(this->vmpp.strProcessName.c_str(), NULL, NULL, NULL, FALSE, PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &this->vmpp.si, &this->vmpp.pi)) return FALSE;

		WOW64_CONTEXT ctx{ 0 };

		ctx.ContextFlags = CONTEXT_INTEGER;

		Wow64GetThreadContext(this->vmpp.pi.hThread, &ctx);

		uintptr_t ptrImageBase{ 0 };

		//Using the PEB to get Image Base of the suspended vmp process
		/*
			ntdll!_PEB32.ImageBaseAddress
		*/
		ReadProcessMemory(this->vmpp.pi.hProcess, (LPVOID)(ctx.Ebx + 8), &ptrImageBase, sizeof(uintptr_t), NULL);

		this->vmpp.ImageBase = ptrImageBase;

		return FALSE;
	};

	std::function<BOOL(std::string&, VMPType::VMPROTECT_VERSION, BOOL)> InitProcess64 = [&](std::string& strName, VMPType::VMPROTECT_VERSION vmpInfo, BOOL insertKeoStub) -> BOOL {

		this->vmpp.vmpType = vmpInfo;

		this->vmpp.strProcessName = strName;

		if (insertKeoStub) this->PreparateVmpMachineStub();

		this->vmpp.si.cb = sizeof(this->vmpp.si);
	
		if (!CreateProcessA(this->vmpp.strProcessName.c_str(), NULL, NULL, NULL, FALSE, PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &this->vmpp.si, &this->vmpp.pi)) return FALSE;
	
		//Thanks to last post at https://forum.tuts4you.com/topic/36036-how-to-get-base-of-new-created-process/
		PROCESS_BASIC_INFORMATION pi;
	
		NtQueryInformationProcess(this->vmpp.pi.hProcess, ProcessBasicInformation, &pi, sizeof(pi), nullptr);

		/*
		ntdll!_PEB64
				+0x000 InheritedAddressSpace : UChar
				+0x001 ReadImageFileExecOptions : UChar
				+0x002 BeingDebugged    : UChar
				+0x003 BitField         : UChar
				+0x003 ImageUsesLargePages : Pos 0, 1 Bit
				+0x003 IsProtectedProcess : Pos 1, 1 Bit
				+0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
				+0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
				+0x003 IsPackagedProcess : Pos 4, 1 Bit
				+0x003 IsAppContainer   : Pos 5, 1 Bit
				+0x003 IsProtectedProcessLight : Pos 6, 1 Bit
				+0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
				+0x004 Padding0         : [4] UChar
				+0x008 Mutant           : Ptr64 Void
				+0x010 ImageBaseAddress : Ptr64 Void
				+0x018 Ldr              : Ptr64 _PEB_LDR_DATA
				+0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
				+0x028 SubSystemData    : Ptr64 Void
				+0x030 ProcessHeap      : Ptr64 Void
				+0x038 FastPebLock      : Ptr64 _RTL_CRITICAL_SECTION
				+0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
				+0x048 IFEOKey          : Ptr64 Void
				+0x050 CrossProcessFlags : Uint4B
				+0x050 ProcessInJob     : Pos 0, 1 Bit
				+0x050 ProcessInitializing : Pos 1, 1 Bit
				+0x050 ProcessUsingVEH  : Pos 2, 1 Bit
				+0x050 ProcessUsingVCH  : Pos 3, 1 Bit
				+0x050 ProcessUsingFTH  : Pos 4, 1 Bit
				+0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
				+0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
				+0x050 ReservedBits0    : Pos 7, 25 Bits
				+0x054 Padding1         : [4] UChar
				+0x058 KernelCallbackTable : Ptr64 Void
				+0x058 UserSharedInfoPtr : Ptr64 Void
				+0x060 SystemReserved   : Uint4B
				+0x064 AtlThunkSListPtr32 : Uint4B
				+0x068 ApiSetMap        : Ptr64 Void
				+0x070 TlsExpansionCounter : Uint4B
				+0x074 Padding2         : [4] UChar
				+0x078 TlsBitmap        : Ptr64 Void
				+0x080 TlsBitmapBits    : [2] Uint4B
				+0x088 ReadOnlySharedMemoryBase : Ptr64 Void
				+0x090 SharedData       : Ptr64 Void
				+0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
				+0x0a0 AnsiCodePageData : Ptr64 Void
				+0x0a8 OemCodePageData  : Ptr64 Void
				+0x0b0 UnicodeCaseTableData : Ptr64 Void
				+0x0b8 NumberOfProcessors : Uint4B
				+0x0bc NtGlobalFlag     : Uint4B
				+0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
				+0x0c8 HeapSegmentReserve : Uint8B
				+0x0d0 HeapSegmentCommit : Uint8B
				+0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
				+0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
				+0x0e8 NumberOfHeaps    : Uint4B
				+0x0ec MaximumNumberOfHeaps : Uint4B
				+0x0f0 ProcessHeaps     : Ptr64 Ptr64 Void
				+0x0f8 GdiSharedHandleTable : Ptr64 Void
				+0x100 ProcessStarterHelper : Ptr64 Void
				+0x108 GdiDCAttributeList : Uint4B
				+0x10c Padding3         : [4] UChar
				+0x110 LoaderLock       : Ptr64 _RTL_CRITICAL_SECTION
				+0x118 OSMajorVersion   : Uint4B
				+0x11c OSMinorVersion   : Uint4B
				+0x120 OSBuildNumber    : Uint2B
				+0x122 OSCSDVersion     : Uint2B
				+0x124 OSPlatformId     : Uint4B
				+0x128 ImageSubsystem   : Uint4B
				+0x12c ImageSubsystemMajorVersion : Uint4B
				+0x130 ImageSubsystemMinorVersion : Uint4B
				+0x134 Padding4         : [4] UChar
				+0x138 ActiveProcessAffinityMask : Uint8B
				+0x140 GdiHandleBuffer  : [60] Uint4B
				+0x230 PostProcessInitRoutine : Ptr64     void 
				+0x238 TlsExpansionBitmap : Ptr64 Void
				+0x240 TlsExpansionBitmapBits : [32] Uint4B
				+0x2c0 SessionId        : Uint4B
				+0x2c4 Padding5         : [4] UChar
				+0x2c8 AppCompatFlags   : _ULARGE_INTEGER
				+0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
				+0x2d8 pShimData        : Ptr64 Void
				+0x2e0 AppCompatInfo    : Ptr64 Void
				+0x2e8 CSDVersion       : _UNICODE_STRING
				+0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
				+0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
				+0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
				+0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
				+0x318 MinimumStackCommit : Uint8B
				+0x320 FlsCallback      : Ptr64 _FLS_CALLBACK_INFO
				+0x328 FlsListHead      : _LIST_ENTRY
				+0x338 FlsBitmap        : Ptr64 Void
				+0x340 FlsBitmapBits    : [4] Uint4B
				+0x350 FlsHighIndex     : Uint4B
				+0x358 WerRegistrationData : Ptr64 Void
				+0x360 WerShipAssertPtr : Ptr64 Void
				+0x368 pUnused          : Ptr64 Void
				+0x370 pImageHeaderHash : Ptr64 Void
				+0x378 TracingFlags     : Uint4B
				+0x378 HeapTracingEnabled : Pos 0, 1 Bit
				+0x378 CritSecTracingEnabled : Pos 1, 1 Bit
				+0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
				+0x378 SpareTracingBits : Pos 3, 29 Bits
				+0x37c Padding6         : [4] UChar
				+0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
				+0x388 TppWorkerpListLock : Uint8B
				+0x390 TppWorkerpList   : _LIST_ENTRY
				+0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
				+0x7a0 TelemetryCoverageHeader : Ptr64 Void
				+0x7a8 CloudFileFlags   : Uint4B
				+0x7ac CloudFileDiagFlags : Uint4B
				+0x7b0 PlaceholderCompatibilityMode : Char
				+0x7b1 PlaceholderCompatibilityModeReserved : [7] Char
		*/
		auto PebImageBaseAddress = (DWORD_PTR)pi.PebBaseAddress + 0x10;

		uintptr_t ImageBase = 0;

		ReadProcessMemory(this->vmpp.pi.hProcess, (LPCVOID)PebImageBaseAddress, &ImageBase, sizeof(uintptr_t), NULL);

		this->vmpp.ImageBase = ImageBase;

		std::printf("[X] Image Base catch from PEB: 0x%llx\n", this->vmpp.ImageBase);
	
		this->GetPeDiskSz();

		return this->IsValidPE();
	};

	std::function<void()> ResumeProcess = [&]() -> void {

		ResumeThread(this->vmpp.pi.hThread);

	};

};

