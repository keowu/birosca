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

class WINPESection {

public:
	IMAGE_SECTION_HEADER imgSec{ 0 };
	unsigned char* data{ 0 };
	uintptr_t uipDataSz{ 0 };
	uintptr_t uipNormalSz{ 0 };

};