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

static unsigned char g_GENERIC_VMINIT[]{ 0x89, 0x67, 0x45, 0x23 };
static unsigned char g_INIT_ASM[]{ 0x56, 0x8B, 0xF4, 0x83, 0xE4 };

static unsigned char g_FLU_KEO_VMP_LOADER[2048] = {
	0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41,
	0x00, 0x00, 0x00, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00,
	0x65, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x64, 0x00,
	0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x4B, 0x45, 0x4F, 0x57, 0x55, 0x20, 0x53, 0x48, 0x45, 0x4C, 0x4C, 0x43,
	0x4F, 0x44, 0x45, 0x20, 0x43, 0x4F, 0x4E, 0x53, 0x54, 0x52, 0x55, 0x49,
	0x44, 0x4F, 0x20, 0x43, 0x4F, 0x4D, 0x20, 0x4D, 0x41, 0x53, 0x4D, 0x20,
	0x50, 0x4F, 0x52, 0x51, 0x55, 0x45, 0x20, 0x53, 0x4F, 0x4D, 0x4F, 0x53,
	0x20, 0x53, 0x45, 0x52, 0x45, 0x53, 0x20, 0x44, 0x45, 0x20, 0x43, 0x55,
	0x4C, 0x54, 0x55, 0x52, 0x41, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x55, 0x6D, 0x61, 0x20, 0x6D, 0x65, 0x6E, 0x73, 0x61, 0x67, 0x65, 0x6D,
	0x20, 0x61, 0x6D, 0x69, 0x67, 0x61, 0x76, 0x65, 0x6C, 0x3A, 0x20, 0x56,
	0x6F, 0x63, 0x65, 0x20, 0x65, 0x20, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x65,
	0x2E, 0x20, 0x6D, 0x61, 0x73, 0x20, 0x6E, 0x61, 0x6F, 0x20, 0x65, 0x20,
	0x64, 0x6F, 0x69, 0x73, 0x2E, 0x20, 0x45, 0x75, 0x20, 0x73, 0x6F, 0x75,
	0x20, 0x62, 0x65, 0x6D, 0x20, 0x70, 0x65, 0x71, 0x75, 0x65, 0x6E, 0x6F,
	0x20, 0x6D, 0x61, 0x73, 0x20, 0x63, 0x6F, 0x6D, 0x20, 0x63, 0x65, 0x72,
	0x74, 0x65, 0x7A, 0x61, 0x20, 0x6E, 0x61, 0x6F, 0x20, 0x73, 0x6F, 0x75,
	0x20, 0x6D, 0x65, 0x74, 0x61, 0x64, 0x65, 0x2E, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x53, 0x65, 0x20, 0x76, 0x6F, 0x63, 0x65, 0x20,
	0x65, 0x73, 0x74, 0x69, 0x76, 0x65, 0x72, 0x20, 0x6C, 0x65, 0x6E, 0x64,
	0x6F, 0x20, 0x69, 0x73, 0x73, 0x6F, 0x2E, 0x20, 0x76, 0x6F, 0x63, 0x65,
	0x20, 0x74, 0x65, 0x76, 0x65, 0x20, 0x6F, 0x20, 0x74, 0x72, 0x61, 0x62,
	0x61, 0x6C, 0x68, 0x6F, 0x20, 0x64, 0x65, 0x20, 0x61, 0x6E, 0x61, 0x6C,
	0x69, 0x73, 0x61, 0x72, 0x20, 0x65, 0x73, 0x73, 0x65, 0x20, 0x73, 0x68,
	0x65, 0x6C, 0x6C, 0x63, 0x6F, 0x64, 0x65, 0x20, 0x65, 0x6D, 0x20, 0x64,
	0x65, 0x74, 0x61, 0x6C, 0x68, 0x65, 0x73, 0x2E, 0x20, 0x64, 0x65, 0x76,
	0x65, 0x72, 0x69, 0x61, 0x20, 0x76, 0x69, 0x72, 0x20, 0x65, 0x73, 0x74,
	0x75, 0x64, 0x61, 0x72, 0x20, 0x63, 0x6F, 0x6D, 0x69, 0x67, 0x6F, 0x2E,
	0x20, 0x65, 0x75, 0x20, 0x66, 0x61, 0x6C, 0x6F, 0x20, 0x69, 0x6E, 0x67,
	0x6C, 0x65, 0x73, 0x20, 0x65, 0x6E, 0x74, 0x61, 0x6F, 0x20, 0x6E, 0x61,
	0x6F, 0x20, 0x73, 0x65, 0x20, 0x70, 0x72, 0x65, 0x6F, 0x63, 0x75, 0x70,
	0x65, 0x2E, 0x20, 0x65, 0x75, 0x20, 0x74, 0x65, 0x6E, 0x68, 0x6F, 0x20,
	0x6D, 0x75, 0x69, 0x74, 0x61, 0x73, 0x20, 0x69, 0x64, 0x65, 0x69, 0x61,
	0x73, 0x20, 0x70, 0x61, 0x72, 0x61, 0x20, 0x63, 0x6F, 0x6C, 0x6F, 0x63,
	0x61, 0x72, 0x20, 0x65, 0x6D, 0x20, 0x70, 0x72, 0x61, 0x74, 0x69, 0x63,
	0x61, 0x20, 0x65, 0x20, 0x62, 0x75, 0x73, 0x63, 0x6F, 0x20, 0x67, 0x65,
	0x6E, 0x74, 0x65, 0x20, 0x6C, 0x65, 0x67, 0x61, 0x6C, 0x20, 0x70, 0x61,
	0x72, 0x61, 0x20, 0x66, 0x61, 0x7A, 0x65, 0x72, 0x20, 0x74, 0x75, 0x64,
	0x6F, 0x20, 0x69, 0x73, 0x73, 0x6F, 0x20, 0x6A, 0x75, 0x6E, 0x74, 0x6F,
	0x2E, 0x20, 0x73, 0x65, 0x20, 0x71, 0x75, 0x69, 0x73, 0x65, 0x72, 0x20,
	0x6D, 0x61, 0x6E, 0x64, 0x65, 0x20, 0x6E, 0x61, 0x20, 0x6D, 0x69, 0x6E,
	0x68, 0x61, 0x20, 0x64, 0x6D, 0x20, 0x64, 0x6F, 0x20, 0x64, 0x69, 0x63,
	0x6F, 0x72, 0x64, 0x3A, 0x20, 0x6B, 0x65, 0x6F, 0x77, 0x75, 0x5F, 0x4F,
	0x57, 0x55, 0x5F, 0x31, 0x32, 0x33, 0x5F, 0x66, 0x6C, 0x61, 0x47, 0x78,
	0x41, 0x00, 0x56, 0x8B, 0xF4, 0x83, 0xE4, 0xF0, 0x83, 0xEC, 0x20, 0xE8,
	0x04, 0x00, 0x00, 0x00, 0x8B, 0xE6, 0x5E, 0xC3, 0x55, 0x8B, 0xEC, 0x83,
	0xEC, 0x70, 0xB8, 0x6B, 0x00, 0x00, 0x00, 0x66, 0x89, 0x45, 0x90, 0xB9,
	0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x4D, 0x92, 0xBA, 0x72, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x55, 0x94, 0xB8, 0x6E, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x45, 0x96, 0xB9, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x4D, 0x98, 0xBA,
	0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x55, 0x9A, 0xB8, 0x33, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x45, 0x9C, 0xB9, 0x32, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x4D, 0x9E, 0xBA, 0x2E, 0x00, 0x00, 0x00, 0x66, 0x89, 0x55, 0xA0, 0xB8,
	0x64, 0x00, 0x00, 0x00, 0x66, 0x89, 0x45, 0xA2, 0xB9, 0x6C, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x4D, 0xA4, 0xBA, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x55, 0xA6, 0x33, 0xC0, 0x66, 0x89, 0x45, 0xA8, 0xC6, 0x45, 0xD0, 0x4C,
	0xC6, 0x45, 0xD1, 0x6F, 0xC6, 0x45, 0xD2, 0x61, 0xC6, 0x45, 0xD3, 0x64,
	0xC6, 0x45, 0xD4, 0x4C, 0xC6, 0x45, 0xD5, 0x69, 0xC6, 0x45, 0xD6, 0x62,
	0xC6, 0x45, 0xD7, 0x72, 0xC6, 0x45, 0xD8, 0x61, 0xC6, 0x45, 0xD9, 0x72,
	0xC6, 0x45, 0xDA, 0x79, 0xC6, 0x45, 0xDB, 0x41, 0xC6, 0x45, 0xDC, 0x00,
	0xC6, 0x45, 0xAC, 0x47, 0xC6, 0x45, 0xAD, 0x65, 0xC6, 0x45, 0xAE, 0x74,
	0xC6, 0x45, 0xAF, 0x4D, 0xC6, 0x45, 0xB0, 0x6F, 0xC6, 0x45, 0xB1, 0x64,
	0xC6, 0x45, 0xB2, 0x75, 0xC6, 0x45, 0xB3, 0x6C, 0xC6, 0x45, 0xB4, 0x65,
	0xC6, 0x45, 0xB5, 0x48, 0xC6, 0x45, 0xB6, 0x61, 0xC6, 0x45, 0xB7, 0x6E,
	0xC6, 0x45, 0xB8, 0x64, 0xC6, 0x45, 0xB9, 0x6C, 0xC6, 0x45, 0xBA, 0x65,
	0xC6, 0x45, 0xBB, 0x41, 0xC6, 0x45, 0xBC, 0x00, 0xC6, 0x45, 0xC0, 0x43,
	0xC6, 0x45, 0xC1, 0x3A, 0xC6, 0x45, 0xC2, 0x5C, 0xC6, 0x45, 0xC3, 0x4B,
	0xC6, 0x45, 0xC4, 0x45, 0xC6, 0x45, 0xC5, 0x4C, 0xC6, 0x45, 0xC6, 0x41,
	0xC6, 0x45, 0xC7, 0x49, 0xC6, 0x45, 0xC8, 0x4E, 0xC6, 0x45, 0xC9, 0x2E,
	0xC6, 0x45, 0xCA, 0x64, 0xC6, 0x45, 0xCB, 0x6C, 0xC6, 0x45, 0xCC, 0x6C,
	0xC6, 0x45, 0xCD, 0x00, 0x8D, 0x4D, 0x90, 0x51, 0xE8, 0xD3, 0x01, 0x00,
	0x00, 0x83, 0xC4, 0x04, 0x89, 0x45, 0xFC, 0x83, 0x7D, 0xFC, 0x00, 0x75,
	0x07, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x62, 0x8D, 0x55, 0xD0, 0x52,
	0x8B, 0x45, 0xFC, 0x50, 0xE8, 0x59, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x08,
	0x89, 0x45, 0xF8, 0x83, 0x7D, 0xF8, 0x00, 0x75, 0x07, 0xB8, 0x02, 0x00,
	0x00, 0x00, 0xEB, 0x42, 0x8B, 0x4D, 0xF8, 0x89, 0x4D, 0xF4, 0x8D, 0x55,
	0xC0, 0x52, 0xFF, 0x55, 0xF4, 0x89, 0x45, 0xE0, 0x8D, 0x45, 0xAC, 0x50,
	0x8B, 0x4D, 0xFC, 0x51, 0xE8, 0x29, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x08,
	0x89, 0x45, 0xF0, 0x8B, 0x55, 0xF0, 0x89, 0x55, 0xEC, 0x6A, 0x00, 0xFF,
	0x55, 0xEC, 0x89, 0x45, 0xE8, 0x8B, 0x45, 0xE8, 0x99, 0x05, 0x89, 0x67,
	0x45, 0x23, 0x89, 0x45, 0xE4, 0xFF, 0x55, 0xE4, 0x33, 0xC0, 0x8B, 0xE5,
	0x5D, 0xC3, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x3C, 0x8B, 0x45, 0x08, 0x89,
	0x45, 0xEC, 0x8B, 0x4D, 0xEC, 0x0F, 0xB7, 0x11, 0x81, 0xFA, 0x4D, 0x5A,
	0x00, 0x00, 0x74, 0x07, 0x33, 0xC0, 0xE9, 0x35, 0x01, 0x00, 0x00, 0x8B,
	0x45, 0xEC, 0x8B, 0x4D, 0x08, 0x03, 0x48, 0x3C, 0x89, 0x4D, 0xE4, 0xBA,
	0x08, 0x00, 0x00, 0x00, 0x6B, 0xC2, 0x00, 0x8B, 0x4D, 0xE4, 0x8D, 0x54,
	0x01, 0x78, 0x89, 0x55, 0xE8, 0x8B, 0x45, 0xE8, 0x83, 0x38, 0x00, 0x75,
	0x07, 0x33, 0xC0, 0xE9, 0x08, 0x01, 0x00, 0x00, 0x8B, 0x4D, 0xE8, 0x8B,
	0x11, 0x89, 0x55, 0xE0, 0x8B, 0x45, 0xE0, 0x03, 0x45, 0x08, 0x89, 0x45,
	0xF4, 0x8B, 0x4D, 0xF4, 0x8B, 0x51, 0x18, 0x89, 0x55, 0xDC, 0x8B, 0x45,
	0xF4, 0x8B, 0x48, 0x1C, 0x89, 0x4D, 0xD0, 0x8B, 0x55, 0xF4, 0x8B, 0x42,
	0x20, 0x89, 0x45, 0xD8, 0x8B, 0x4D, 0xF4, 0x8B, 0x51, 0x24, 0x89, 0x55,
	0xD4, 0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45,
	0xF8, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xF8, 0x8B, 0x4D, 0xF8, 0x3B, 0x4D,
	0xDC, 0x0F, 0x83, 0xB3, 0x00, 0x00, 0x00, 0x8B, 0x55, 0x08, 0x03, 0x55,
	0xD8, 0x8B, 0x45, 0xF8, 0x8D, 0x0C, 0x82, 0x89, 0x4D, 0xC8, 0x8B, 0x55,
	0x08, 0x03, 0x55, 0xD4, 0x8B, 0x45, 0xF8, 0x8D, 0x0C, 0x42, 0x89, 0x4D,
	0xCC, 0x8B, 0x55, 0x08, 0x03, 0x55, 0xD0, 0x8B, 0x45, 0xCC, 0x0F, 0xB7,
	0x08, 0x8D, 0x14, 0x8A, 0x89, 0x55, 0xC4, 0x8B, 0x45, 0xC8, 0x8B, 0x4D,
	0x08, 0x03, 0x08, 0x89, 0x4D, 0xF0, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00,
	0x00, 0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x55,
	0xFC, 0x83, 0xC2, 0x01, 0x89, 0x55, 0xFC, 0x8B, 0x45, 0x0C, 0x03, 0x45,
	0xFC, 0x0F, 0xBE, 0x08, 0x85, 0xC9, 0x74, 0x27, 0x8B, 0x55, 0xF0, 0x03,
	0x55, 0xFC, 0x0F, 0xBE, 0x02, 0x85, 0xC0, 0x74, 0x1A, 0x8B, 0x4D, 0x0C,
	0x03, 0x4D, 0xFC, 0x0F, 0xBE, 0x11, 0x8B, 0x45, 0xF0, 0x03, 0x45, 0xFC,
	0x0F, 0xBE, 0x08, 0x3B, 0xD1, 0x74, 0x02, 0xEB, 0x02, 0xEB, 0xC3, 0x8B,
	0x55, 0x0C, 0x03, 0x55, 0xFC, 0x0F, 0xBE, 0x02, 0x85, 0xC0, 0x75, 0x19,
	0x8B, 0x4D, 0xF0, 0x03, 0x4D, 0xFC, 0x0F, 0xBE, 0x11, 0x85, 0xD2, 0x75,
	0x0C, 0x8B, 0x45, 0xC4, 0x8B, 0x4D, 0x08, 0x03, 0x08, 0x8B, 0xC1, 0xEB,
	0x07, 0xE9, 0x38, 0xFF, 0xFF, 0xFF, 0x33, 0xC0, 0x8B, 0xE5, 0x5D, 0xC3,
	0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x34, 0xC7, 0x45, 0xE4, 0x00, 0x00, 0x00,
	0x00, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x89, 0x45, 0xE4, 0x8B, 0x4D,
	0xE4, 0x8B, 0x51, 0x0C, 0x89, 0x55, 0xD8, 0x8B, 0x45, 0xD8, 0x8B, 0x48,
	0x0C, 0x8B, 0x50, 0x10, 0x89, 0x4D, 0xCC, 0x89, 0x55, 0xD0, 0x8B, 0x45,
	0xCC, 0x89, 0x45, 0xD4, 0x8B, 0x4D, 0xD4, 0x89, 0x4D, 0xE8, 0x83, 0x7D,
	0xE8, 0x00, 0x0F, 0x84, 0x5A, 0x01, 0x00, 0x00, 0x8B, 0x55, 0xE8, 0x83,
	0x7A, 0x18, 0x00, 0x0F, 0x84, 0x4D, 0x01, 0x00, 0x00, 0x8B, 0x45, 0xE8,
	0x83, 0x78, 0x30, 0x00, 0x75, 0x02, 0xEB, 0xDE, 0x8B, 0x4D, 0xE8, 0x8B,
	0x51, 0x30, 0x89, 0x55, 0xEC, 0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00,
	0xC7, 0x45, 0xF0, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x09, 0x8B, 0x45, 0xF0,
	0x83, 0xC0, 0x01, 0x89, 0x45, 0xF0, 0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0x08,
	0x0F, 0xB7, 0x04, 0x4A, 0x85, 0xC0, 0x0F, 0x84, 0xDD, 0x00, 0x00, 0x00,
	0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0xEC, 0x0F, 0xB7, 0x04, 0x4A, 0x85, 0xC0,
	0x0F, 0x84, 0xCB, 0x00, 0x00, 0x00, 0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0x08,
	0x0F, 0xB7, 0x04, 0x4A, 0x83, 0xF8, 0x5A, 0x7F, 0x37, 0x8B, 0x4D, 0xF0,
	0x8B, 0x55, 0x08, 0x0F, 0xB7, 0x04, 0x4A, 0x83, 0xF8, 0x41, 0x7C, 0x28,
	0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0x08, 0x0F, 0xB7, 0x04, 0x4A, 0x83, 0xC0,
	0x20, 0x89, 0x45, 0xE0, 0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0x08, 0x66, 0x8B,
	0x45, 0xE0, 0x66, 0x89, 0x04, 0x4A, 0x66, 0x8B, 0x4D, 0xE0, 0x66, 0x89,
	0x4D, 0xFE, 0xEB, 0x0E, 0x8B, 0x55, 0xF0, 0x8B, 0x45, 0x08, 0x66, 0x8B,
	0x0C, 0x50, 0x66, 0x89, 0x4D, 0xFE, 0x66, 0x8B, 0x55, 0xFE, 0x66, 0x89,
	0x55, 0xF8, 0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xEC, 0x0F, 0xB7, 0x14, 0x41,
	0x83, 0xFA, 0x5A, 0x7F, 0x37, 0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xEC, 0x0F,
	0xB7, 0x14, 0x41, 0x83, 0xFA, 0x41, 0x7C, 0x28, 0x8B, 0x45, 0xF0, 0x8B,
	0x4D, 0xEC, 0x0F, 0xB7, 0x14, 0x41, 0x83, 0xC2, 0x20, 0x89, 0x55, 0xDC,
	0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xEC, 0x66, 0x8B, 0x55, 0xDC, 0x66, 0x89,
	0x14, 0x41, 0x66, 0x8B, 0x45, 0xDC, 0x66, 0x89, 0x45, 0xFC, 0xEB, 0x0E,
	0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0xEC, 0x66, 0x8B, 0x04, 0x4A, 0x66, 0x89,
	0x45, 0xFC, 0x66, 0x8B, 0x4D, 0xFC, 0x66, 0x89, 0x4D, 0xF4, 0x0F, 0xB7,
	0x55, 0xF8, 0x0F, 0xB7, 0x45, 0xF4, 0x3B, 0xD0, 0x74, 0x02, 0xEB, 0x05,
	0xE9, 0x08, 0xFF, 0xFF, 0xFF, 0x8B, 0x4D, 0xF0, 0x8B, 0x55, 0x08, 0x0F,
	0xB7, 0x04, 0x4A, 0x85, 0xC0, 0x75, 0x16, 0x8B, 0x4D, 0xF0, 0x8B, 0x55,
	0xEC, 0x0F, 0xB7, 0x04, 0x4A, 0x85, 0xC0, 0x75, 0x08, 0x8B, 0x4D, 0xE8,
	0x8B, 0x41, 0x18, 0xEB, 0x0F, 0x8B, 0x55, 0xE8, 0x8B, 0x02, 0x89, 0x45,
	0xE8, 0xE9, 0x9C, 0xFE, 0xFF, 0xFF, 0x33, 0xC0, 0x8B, 0xE5, 0x5D, 0xC3,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
