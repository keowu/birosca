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
/*
*	!Attention!
		Some code are based on scylla(IAT, PE FIXER Logic). THE LICENSE USED ARE GNU 3. I just corrected some things to adapt to my project and learned a lot with that.
		Thank you so much for teaching me how to fix IAT and PE Header in depth with your code Mr.NtQuery.
*/
#include <iostream>
#include <functional>
#include "WINPEParser.hh"

class VMPFIXEngine {

public:
	std::function<void(HANDLE, uintptr_t, uintptr_t)> Init = [&](HANDLE hProcess, uintptr_t imagebase, uintptr_t oep) {

		DWORD dwMaxPath = 260;

		char chPath[260]{ 0 };

		QueryFullProcessImageNameA(hProcess, 0, chPath, &dwMaxPath);

		std::unique_ptr<WINPEParser> PeParser(new WINPEParser());

		PeParser->PE(hProcess, imagebase, true);

											  //Out file exemple: executabledir\myvmp.exe.unp.exe
		PeParser->DumpProcess(imagebase, oep, std::string(chPath).append(".unp.exe").c_str()); 
		
	};

};