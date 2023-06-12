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

//Keowu Tip: For compile this project do this:  Project / Properties / C/C++ / General / SDL Checks -> SET TO (NO).
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

namespace VMPType {

	enum VMPROTECT_VERSION {
		VMPROTECT_1_1,
		VMPROTECT_1_4,
		VMPROTECT_1_54,
		VMPROTECT_1_70_4
	};
	
};