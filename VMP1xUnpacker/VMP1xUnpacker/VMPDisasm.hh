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
#include <functional>
#include <memory>
#include "VMPDebugger.hh"
#include "thr3rd/distorm-3.5.2b/include/distorm.h"
#pragma comment(lib, "thr3rd/distorm-3.5.2b/lib/distorm.lib")

namespace VMPDisasm {

	static std::function<void(uintptr_t, unsigned char*, unsigned int, bool, const char*, const char*)> DisasmAndPrint = [&](uintptr_t addy, unsigned char* ucBuff, unsigned int uiLen, bool is32, const char* bannerIn, const char* bannerOut) {

		_DecodedInst decodedInstructions[1000];
		
		_DecodeType dt = is32 ? Decode32Bits : Decode64Bits;

		unsigned int decodedInstructionsCount = 0;
		
		std::printf(bannerIn);

		if (distorm_decode(is32, ucBuff, uiLen, dt, decodedInstructions, 1000, &decodedInstructionsCount) == DECRES_INPUTERR) throw std::runtime_error("Error disassembly of the vmprotector packer entry !");

		for (auto i = 0; i < decodedInstructionsCount; i++) if (is32) std::printf("%llx (%02d) %-24s %s%s%s\n", decodedInstructions[i].offset, decodedInstructions[i].size, reinterpret_cast<char*>(decodedInstructions[i].instructionHex.p), reinterpret_cast<char*>(decodedInstructions[i].mnemonic.p), decodedInstructions[i].operands.length != 0 ? " " : "", reinterpret_cast<char*>(decodedInstructions[i].operands.p)); else std::printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, reinterpret_cast<char*>(decodedInstructions[i].instructionHex.p), reinterpret_cast<char*>(decodedInstructions[i].mnemonic.p), decodedInstructions[i].operands.length != 0 ? " " : "", reinterpret_cast<char*>(decodedInstructions[i].operands.p));

		std::printf(bannerOut);

	};

};