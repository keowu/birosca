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

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>


#include "minhook/include/MinHook.h"

#if _WIN64
#pragma comment(lib, "minhook/lib/Debug/libMinHook.x64.lib")
#else
#pragma comment(lib, "minhook/lib/Debug/libMinHook.x86.lib")
#endif

#pragma comment(lib, "ntdll.lib") //To fix references from ntdll
#include <winternl.h>