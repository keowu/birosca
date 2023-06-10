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
#include <list>
#include <filesystem>
#include "VMPProcess.hh"
#include "VMPDisasm.hh"
#include "VMPFIXEngine.hh"

class VMPDebugger {

private:

	const unsigned char INT3 = 0xCC; //https://www.felixcloutier.com/x86/intn:into:int3:int1

	typedef struct _VMPROTECTCONFIGURATION {
		unsigned char vmp11_vmexitVirtualizedRoutine32[11]{ 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x58, 0x61, 0x9D, 0xC3 }; //vmexit routine vmprotect 1.1 packer stub
		unsigned char vmp14_vmexitVirtualizedRoutine32[13]{ 0x89, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3 }; //vmexit routine vmprotect 1.4 packer stub
		unsigned char vmp154_vmexitVirtualizedRoutine32[13]{ 0x89, 0xEC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3 }; //vmexit routine vmprotect 1.54 packer stub
		unsigned char vmp1704_vmexitVirtualizedRoutine32[25]{ 0xFC, 0xFC, 0x9C, 0xFF, 0x74, 0x24, 0x18, 0x9D, 0x60, 0x68, 0x62, 0x0F, 0xAC, 0x2D, 0x54, 0x88, 0x04, 0x24, 0xFF, 0x74, 0x24, 0x44, 0xC2, 0x48, 0x00 };//{ 0xC2, 0x48, 0x00, 0x89, 0x4C, 0x24, 0x04, 0x8D, 0x34, 0xED, 0x8F, 0x31, 0xFE, 0x4C, 0xE8, 0x4F }; //vmexit routine vmprotect 1.70.4 packer stub
	} VMPROTECTCONFIGURATION;

	typedef struct _VMPMACHINESECTION {
		std::string machineName;
		uintptr_t virtualAddress;
		uintptr_t sizeofRawData;
		uintptr_t pointToRawData;
	} VMPMACHINESECTION;

	typedef struct _VMPDBG {
		std::string defaultVMPSegmentNames = "vmp";
		DEBUG_EVENT dbgEvent{ 0 };
		uintptr_t vmProtectvmExitLiftAddy{ 0 };
		uintptr_t AddressOfEntryPoint{ 0 };
		uintptr_t AddressOfEntryPointRelative{ 0 };
		uintptr_t vmExitAddressRoutine{ 0 };
		BOOL is32{ 0 };
		VMPROTECTCONFIGURATION vmpConfiguration;
		std::list<VMPMACHINESECTION> machines;
	} VMPDBG;

	VMPDBG vmpdbg;


	std::function<void(std::unique_ptr<VMPProcess>& vmp)> InitVmpInterceptRoutine = [&](std::unique_ptr<VMPProcess>& vmp) {

		//Parsear o PE Header
		//Obter o tamanho e endereço das seções mapeadas na memória do processo
		auto imgDosH = new IMAGE_DOS_HEADER;

		ReadProcessMemory(vmp->GetVMPP().pi.hProcess, (LPCVOID)vmp->GetVMPP().ImageBase, imgDosH, sizeof(IMAGE_DOS_HEADER), NULL);

		if (imgDosH->e_magic != 0X5A4D) throw std::runtime_error("ERROR INVALID MZ !");

		auto imgNtH = new IMAGE_NT_HEADERS;

		ReadProcessMemory(vmp->GetVMPP().pi.hProcess, (LPCVOID)(vmp->GetVMPP().ImageBase + imgDosH->e_lfanew), imgNtH, sizeof(IMAGE_NT_HEADERS), NULL);

		if (imgNtH->Signature != 0x4550) throw std::runtime_error("ERROR INVALID PE!");

		this->vmpdbg.AddressOfEntryPoint = imgNtH->OptionalHeader.AddressOfEntryPoint;

		this->vmpdbg.AddressOfEntryPointRelative = vmp->GetVMPP().ImageBase + imgNtH->OptionalHeader.AddressOfEntryPoint;

		this->vmpdbg.is32 = imgNtH->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? TRUE : FALSE;

		auto imgSecH = new IMAGE_SECTION_HEADER[imgNtH->FileHeader.NumberOfSections];

		ReadProcessMemory(vmp->GetVMPP().pi.hProcess, (LPCVOID)(vmp->GetVMPP().ImageBase + imgDosH->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + imgNtH->FileHeader.SizeOfOptionalHeader), imgSecH, sizeof(IMAGE_SECTION_HEADER) * imgNtH->FileHeader.NumberOfSections, NULL);

		for (auto i = 0; i < imgNtH->FileHeader.NumberOfSections; i++) {

			if (std::string((char*)imgSecH[i].Name).find(this->vmpdbg.defaultVMPSegmentNames) != std::string::npos) {

				std::printf("[X] Virtual Machine Section -> %s\n", imgSecH[i].Name);

				vmpdbg.machines.push_back({
					std::string(reinterpret_cast<char*>(imgSecH[i].Name)),
					imgSecH[i].VirtualAddress,
					imgSecH[i].PointerToRawData,
					imgSecH[i].SizeOfRawData
					});
		
			}

		}

		delete imgDosH;
		delete imgNtH;
		delete[] imgSecH;
		
		//Vm Protect 1.1 Create a default entry point with one jump
		std::cout << "[!] Let's Disasm VMP PACKER Entry. please remember that if you have injected KeoStub into the protected file\nthis will be KeoStubVm ASM.\n";

		unsigned char jmp[64]{ 0 };

		ReadProcessMemory(vmp->GetVMPP().pi.hProcess, (LPCVOID)this->vmpdbg.AddressOfEntryPointRelative, jmp, sizeof(jmp), NULL);

		VMPDisasm::DisasmAndPrint(this->vmpdbg.AddressOfEntryPointRelative, jmp, 64, this->vmpdbg.is32, "BEGIN VM PROTECT PACKER ENTRY DISAM\n_______\n", "_______\nEND VM PROTECT PACKER ENTRY DISAM\n");

		BOOL bVmProtectTraquinagens{ 0 };

		//Acessing struct member of entrypoint virtualized: 
		this->vmpdbg.vmExitAddressRoutine = std::invoke([&]() -> uintptr_t {

			for (auto vmpMachineSection : this->vmpdbg.machines) {

				std::printf("[?] Searching on %s\n", vmpMachineSection.machineName.c_str());

				if (vmpMachineSection.sizeofRawData == 0) {
					
					std::printf("[OPS] Look's like VmProtect removed the sizeofRawData. we need to search more in dept.\n");

					bVmProtectTraquinagens = TRUE;

				}

				for (auto i = 0; i < vmpMachineSection.sizeofRawData; i++) {

					unsigned char chk[22]{ 0 };

					ReadProcessMemory(vmp->GetVMPP().pi.hProcess, (LPCVOID)(vmp->GetVMPP().ImageBase + vmpMachineSection.virtualAddress + i), chk, sizeof(chk), NULL);

					switch (vmp->GetVMPP().vmpType) {

						case VMPType::VMPROTECT_1_1:
							if (memcmp(chk, this->vmpdbg.vmpConfiguration.vmp11_vmexitVirtualizedRoutine32, 11) == 0) return vmp->GetVMPP().ImageBase + vmpMachineSection.virtualAddress + i;
							break;

						case VMPType::VMPROTECT_1_4:
						case VMPType::VMPROTECT_1_54: {

							//On vmprotect 1.4 and <= vmprotect 1.70.4 Ivan have changed some bytes on vmexit, but some bytes need to be the same for all versions and the vmexit rotine continues to have 13 bytes
							chk[2] = 0x00, chk[3] = 0x00, chk[4] = 0x00, chk[5] = 0x00, chk[6] = 0x00, chk[7] = 0x00, chk[8] = 0x00, chk[9] = 0x00, chk[10] = 0x00, chk[11] = 0x00;

							if (memcmp(chk, this->vmpdbg.vmpConfiguration.vmp14_vmexitVirtualizedRoutine32, 13) == 0) return vmp->GetVMPP().ImageBase + vmpMachineSection.virtualAddress + i;
						
							break;
						}

						case VMPType::VMPROTECT_1_70_4: {

							//0   1  2  3  4 5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 
							//FC FC 9C FF 74 24 18 9D 60 68 62 0F AC 2D 54 88 04 24 FF 74 24 44 C2 48 00
							//						     68 00 00 00 00 00 00 00 00 00 00 00 00 C2 00 00

							if (bVmProtectTraquinagens) {
							
								std::printf("[!] VMProtect 1.70.x Hide Vmexit. let's search it. this maybe take a little time.\n");

								/*
									This will be very fast, just 1 second
								*/
								for (auto i = 0; i < vmp->GetVMPP().llPeSzDisk; i++) {

									ReadProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPCVOID>(vmp->GetVMPP().ImageBase + vmpMachineSection.virtualAddress + i), chk, sizeof(chk), NULL);

									if (memcmp(chk, this->vmpdbg.vmpConfiguration.vmp1704_vmexitVirtualizedRoutine32, 16) == 0) return vmp->GetVMPP().ImageBase + vmpMachineSection.virtualAddress + i;

								}

							}


							//If all ok with size of sections:
							if (memcmp(chk, this->vmpdbg.vmpConfiguration.vmp1704_vmexitVirtualizedRoutine32, 16) == 0) return vmp->GetVMPP().ImageBase + vmpMachineSection.virtualAddress + i;


							break;
						}
		
					}			

				}

			}
		});

	};

public:

	std::function<void(std::unique_ptr<VMPProcess>& vmp)> InitContext = [&](std::unique_ptr<VMPProcess>& vmp) {

		this->InitVmpInterceptRoutine(vmp);

		DebugActiveProcess(vmp->GetVMPP().pi.dwProcessId);

		//Set breakpoint on vmp out routines
		switch (vmp->GetVMPP().vmpType) {

		case VMPType::VMPROTECT_1_1:
			this->vmpdbg.vmExitAddressRoutine = this->vmpdbg.vmExitAddressRoutine + 10;
			break;

		case VMPType::VMPROTECT_1_4:
			this->vmpdbg.vmExitAddressRoutine = this->vmpdbg.vmExitAddressRoutine + 11;
			break;

		case VMPType::VMPROTECT_1_54:
			this->vmpdbg.vmExitAddressRoutine = this->vmpdbg.vmExitAddressRoutine + 12;
			break;

		case VMPType::VMPROTECT_1_70_4: 

			this->vmpdbg.vmExitAddressRoutine = this->vmpdbg.vmExitAddressRoutine + 22;//on vmexti ret instruction
			
			break;

		default:
			throw std::runtime_error("lol, all ok ? This are not a Vmprotect 1.X valid version");

		}

		unsigned char oldCode[1];

		ReadProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPVOID>(this->vmpdbg.vmExitAddressRoutine), oldCode, sizeof(oldCode), NULL);

		WriteProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPVOID>(this->vmpdbg.vmExitAddressRoutine), &INT3, sizeof(INT3), NULL);

		ContinueDebugEvent(this->vmpdbg.dbgEvent.dwProcessId, this->vmpdbg.dbgEvent.dwThreadId, DBG_CONTINUE);

		while (true) {

			//Trying to fill debug event struct with information of vmprotect process
			if (!WaitForDebugEvent(&this->vmpdbg.dbgEvent, INFINITE)) {

				std::printf("ERRO ESPERANDO PELO EVENTO DE DEBUGGER !");

				return;
			}

			switch (this->vmpdbg.dbgEvent.dwDebugEventCode) {

				case 1: {

					switch (this->vmpdbg.dbgEvent.u.Exception.ExceptionRecord.ExceptionCode) {

						case 0x80000003L: {

							CONTEXT ctx{ 0 };

							ctx.ContextFlags = CONTEXT_ALL;

							GetThreadContext(vmp->GetVMPP().pi.hThread, &ctx);

							std::printf("________REG'S________\nRAX: %llx\nRBX: %llx\nRCX: %llx\nRDX: %llx\nRSI: %llx\nRDI: %llx\nRIP: %llx\nRSP: %llx\nRBP: %llx\nEFLAGS: %llx\n_____________________\n", ctx.Rip, ctx.Rbx, ctx.Rcx,
								ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rip, ctx.Rsp, ctx.Rbp, ctx.EFlags);

							break;
						}

						default: break;
					}

				}
				case 8: {

					CONTEXT ctx{ 0 };

					ctx.ContextFlags = CONTEXT_ALL;

					GetThreadContext(vmp->GetVMPP().pi.hThread, &ctx);

					std::printf("________REG'S________\nRAX: %llx\nRBX: %llx\nRCX: %llx\nRDX: %llx\nRSI: %llx\nRDI: %llx\nRIP: %llx\nRSP: %llx\nRBP: %llx\nEFLAGS: %llx\n_____________________\n", ctx.Rip, ctx.Rbx, ctx.Rcx,
						ctx.Rdx, ctx.Rsi, ctx.Rdi, ctx.Rip, ctx.Rsp, ctx.Rbp, ctx.EFlags);

					if (ctx.Rip == this->vmpdbg.vmExitAddressRoutine + 1) {
						
						CONTEXT ctx{ 0 };

						ctx.ContextFlags = CONTEXT_ALL;

						GetThreadContext(vmp->GetVMPP().pi.hThread, &ctx);

						uintptr_t entryPoint{ 0 };

						if (vmp->GetVMPP().vmpType == VMPType::VMPROTECT_1_1) {
							
							//Acessing entrypoint from stack to be used on ret, vmprotect use in the lat unpack routine the entrypoint onto stack
							//and use a ret instruct to go to entrypoint. yeah like some hooks do
							ReadProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPCVOID>(ctx.Rbp - 0x10), &entryPoint, sizeof(uintptr_t), NULL);

							if (this->vmpdbg.is32) entryPoint = static_cast<DWORD>(entryPoint);
							std::printf("Entrypoint recovery from vmexit into first position of stack: 0x%llx\n", entryPoint);

						}
						else if (vmp->GetVMPP().vmpType == VMPType::VMPROTECT_1_4 || vmp->GetVMPP().vmpType == VMPType::VMPROTECT_1_54) {

							ReadProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPCVOID>(ctx.Rbp - 0x10), &entryPoint, sizeof(uintptr_t), NULL);

							if (this->vmpdbg.is32) entryPoint = static_cast<DWORD>(entryPoint);
							std::printf("Entrypoint recovery from vmexit into third position of stack: 0x%llx\n", entryPoint);

						} else if (vmp->GetVMPP().vmpType == VMPType::VMPROTECT_1_70_4) {							
						
							while (true) {

								std::printf("TODO UNPACK ROUTINE 1.70.4\n");

								//NEED TO IMPLEMENT DEBUG WALKING ON vmexit routine:
								/*
								* This are the VMP 1.70.4 VMEXIT standard routine.
								* this is called when the packer exit from virtual machine. and need to exchange a context to run again
									.vmp2:0006AFED FC             cld
									.vmp2:0006AFEE FC             cld
									.vmp2:0006AFEF 9C             pushf
									.vmp2:0006AFF0 FF 74 24 18    push    [esp+4+arg_10]
									.vmp2:0006AFF4 9D             popf
									.vmp2:0006AFF5 60             pusha
									.vmp2:0006AFF6 68 62 0F AC 2D push    2DAC0F62h
									.vmp2:0006AFFB 54             push    esp
									.vmp2:0006AFFC 88 04 24       mov     [esp+2Ch+var_2C], al
									.vmp2:0006AFFF FF 74 24 44    push    [esp+2Ch+arg_14]
									.vmp2:0006B003 C2 48 00       retn    48h ; 'H'  						
								*/

							}

						}

						if (entryPoint != NULL) {
						
							unsigned char ucEntryPointOP[20]{ 0 }; // Just 20 bytes of OEP routine

							ReadProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPCVOID>(entryPoint), ucEntryPointOP, 20, NULL);

							VMPDisasm::DisasmAndPrint(this->vmpdbg.AddressOfEntryPointRelative, ucEntryPointOP, 20, this->vmpdbg.is32, "BEGIN ENTRY POINT ROUTINE ASM RECOVERED FROM VMEXIT\n_______\n", "_______\nEND ENTRY POINT ROUTINE ASM RECOVERED FROM VMEXIT\n");

						}

						//TODO: Recreate VB 6.0 vm routine to interpret that opcodes
						std::printf("if you are trying to unpack a VB 6.0 binary protected with VM Protect. remember that the entrypoint is not the entrypoint routine, but the entrypoint of the VB 6.0 opcode that Vmprotect has already resolved the symbol of the DLL(MSVBVM60.DLL) that interprets the opcodes and only makes the call, the stubs are the same, you can solve it manually only with the address I gave you.\n");

						WriteProcessMemory(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPVOID>(this->vmpdbg.vmExitAddressRoutine), oldCode, sizeof(oldCode), NULL);
						
						FlushInstructionCache(vmp->GetVMPP().pi.hProcess, reinterpret_cast<LPVOID>(this->vmpdbg.vmExitAddressRoutine), sizeof(oldCode));
						
						ctx.Rip--;

						ctx.EFlags |= 0x100; // Define o sinalizador de trap, que gera uma exceção de "step over"

						SetThreadContext(vmp->GetVMPP().pi.hThread, &ctx);

						//TODO: DUMP ENTRYPOINT HERE and fix IAT
						std::unique_ptr<VMPFIXEngine> vmpengfix(new VMPFIXEngine());

						vmpengfix->Init(vmp->GetVMPP().pi.hProcess, vmp->GetVMPP().ImageBase, entryPoint);

						ExitProcess(-1);

						//end dump

					}

				}

			}

			ContinueDebugEvent(this->vmpdbg.dbgEvent.dwProcessId, this->vmpdbg.dbgEvent.dwThreadId, DBG_CONTINUE);

		}

		return;
	};

};