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
*   VMPROTECT < 2.x:
*
    Nessa versão do vmprotect o Ivan programou para procurar debugger e ambientes virtuais usando as seguintes API's:
    Detecta debugger usermode:
        Kernel32.dll!IsDebuggerPresent
        Kernel32.dll!CheckRemoteDebuggerPresent
    Detecta usermode: Kernel32.dll!GetThreadContext
           Kernel32.dll!UnhandledExceptionFilter
           ntdll.dll!ZwQueryInformationProcess
           ntdll.dll!ZwSetInformationThread

    Detecta debugger kernel:
           Kernel32.dll!CreateFileA verificando \\\\.\\SICE
           Kernel32.dll!CreateFileA verificando \\\\.\\SIWVID
           Kernel32.dll!CreateFileA verificando \\\\.\\NTICE
           Kernel32.dll!CreateFileA verificando \\\\.\\ICEEXT
           Kernel32.dll!CreateFileA verificando \\\\.\\SYSERBOOT

    Muda paginação com virtualprotect(quando necessita modificar handler's)

*/
#include "pch.h"
#include <ntstatus.h>
#include <vector>

std::vector<std::string> g_KernelDebuggerCheckVMP {
    "\\\\.\\SICE",
    "\\\\.\\SIWVID",
    "\\\\.\\NTICE",
    "\\\\.\\ICEEXT",
    "\\\\.\\SYSERBOOT"
};

using tpdIsDebuggerPresent = WINBASEAPI BOOL(WINAPI*) (VOID);

static tpdIsDebuggerPresent g_IsDebuggerOr = nullptr;

auto WINAPI dtIsDebuggerPresent(VOID) -> BOOL {

    auto bPresent = g_IsDebuggerOr();

    std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO ISDEBUGGERPRESENT, e o retorno seria: " << bPresent << "\n";

    return FALSE; // vamos ignorar a chamada
}

using tpdCheckRemoteDebuggerPresent = WINBASEAPI BOOL(WINAPI*)(_In_ HANDLE hProcess, _Out_ PBOOL pbDebuggerPresent);

static tpdCheckRemoteDebuggerPresent g_isCheckRemoteDbgOr = nullptr;

auto WINAPI dtCheckRemoteDebuggerPresent(_In_ HANDLE hProcess, _Out_ PBOOL pbDebuggerPresent) -> BOOL {

    auto bPresent = g_isCheckRemoteDbgOr(hProcess, pbDebuggerPresent);

    std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO CheckRemoteDebuggerPresent, e o retorno seria: " << *pbDebuggerPresent << "\n";

    *pbDebuggerPresent = FALSE;

    return FALSE; // vamos ignorar a chamada
}

using tpdNtGetThreadContext = WINBASEAPI NTSTATUS(WINAPI*)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT ThreadContext);

static tpdNtGetThreadContext g_NtGetThreadContext = nullptr;

auto pNtGetThreadContext = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "NtGetContextThread");

#define NtCurrentThread ((HANDLE)(LONG_PTR)-2)

auto WINAPI dtNtGetThreadContext(HANDLE ThreadHandle, PCONTEXT ThreadContext) -> NTSTATUS {

    DWORD dwContextBackup{ 0 };

    BOOLEAN bDebugRegistersRequested{ FALSE };

    if (ThreadContext) {

        dwContextBackup = ThreadContext->ContextFlags;

        ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;

        bDebugRegistersRequested = ThreadContext->ContextFlags != dwContextBackup;

    }

    std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO NtGetThreadContext\n";

    auto nt_status = g_NtGetThreadContext(ThreadHandle, ThreadContext);

    if (dwContextBackup) {

        ThreadContext->ContextFlags = dwContextBackup;

        if (bDebugRegistersRequested) {
            ThreadContext->Dr0 = 0;
            ThreadContext->Dr1 = 0;
            ThreadContext->Dr2 = 0;
            ThreadContext->Dr3 = 0;
            ThreadContext->Dr6 = 0;
            ThreadContext->Dr7 = 0;
            #ifdef _WIN64
            ThreadContext->LastBranchToRip = 0;
            ThreadContext->LastBranchFromRip = 0;
            ThreadContext->LastExceptionToRip = 0;
            ThreadContext->LastExceptionFromRip = 0;
            #endif
        }

    }

    return nt_status;
}

using tpdNtCloseHandle = NTSTATUS ( NTAPI* )( IN HANDLE Handle );

static tpdNtCloseHandle g_NtCloseHandle = nullptr;
 
auto pNtClose = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "NtClose");

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;

auto NTAPI dtNtCloseHandle( HANDLE Handle) -> NTSTATUS {

    std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO NTCLOSE\n";

    OBJECT_HANDLE_FLAG_INFORMATION flags;
                                                //ObjectHandleFlagInformation
    auto nt_sucess = NtQueryObject(Handle, (OBJECT_INFORMATION_CLASS)4, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), NULL);

    if (nt_sucess >= 0) {

        if (flags.ProtectFromClose)
            return 0xC0000235L;

        return g_NtCloseHandle(Handle);
    }

    return STATUS_INVALID_HANDLE;
}

using tpdCreateFileA = HANDLE(WINAPI*)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
static tpdCreateFileA g_CreateFileA = nullptr;

auto WINAPI dtCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) -> HANDLE {

    for (auto& strKernelDbgCheck : g_KernelDebuggerCheckVMP) {

        if (strKernelDbgCheck.find(std::string(lpFileName)) != std::string::npos) {

            std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO CREATEFILE -> " << lpFileName << '\n';

            return INVALID_HANDLE_VALUE;
        }

    }

    return g_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

using tpdNtQueryInformationProcess = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength );
static tpdNtQueryInformationProcess g_NtQueryInformationProcess = nullptr;
auto pNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "NtQueryInformationProcess");

auto NTAPI dtNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) -> NTSTATUS {

    //O Vmprotect vai verificar por debug port. do enum PROCESSINFOCLASS os índices 30 e 34
    if (ProcessInformationClass != 30 && ProcessInformationClass != 34) return g_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

    std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO NtQueryInformationProcess -> ProcessInformationClass -> " << ProcessInformationClass << "\n";

    *(PHANDLE)ProcessInformation = nullptr; // setamos a informação nullptr porque seria equivalente a não conter uma debugger anexado

    return STATUS_PORT_NOT_SET; // e por fim retornamos o status de que a porta de debug não existe
}

using tpdNtSetInformationThread = NTSTATUS (NTAPI*)( HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength );
static tpdNtSetInformationThread g_NtSetInformationThread = nullptr;
auto pNtSetInformationThread = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "NtSetInformationThread");

auto NTAPI dtNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) {

    //O Vm protect tenta criar uma thread para fazer verificações de debugger. caso o identificador do enum seja 17 da enum THREADINFOCLASS. a gente finge que ela foi criada para o protector
    //Não tem como verificar se a thread foi criada. então se retornarmos NT_SUCESS tudo ocorrera bem com a seção de debugger
    if (ThreadInformationClass != 17) return g_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);

    std::cout << "[! LAIN X9] VMPROTECT ESTA CHAMANDO NtSetInformationThread -> ThreadInformationClass -> " << ThreadInformationClass << "\n";

    return STATUS_SUCCESS;
}

using tpdVirtualProtect = BOOL(WINAPI*)( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
static tpdVirtualProtect g_VirtualProtect = nullptr;

auto WINAPI dtVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) -> BOOL {

    std::cout << "[! LAIN DEBUG] VMPROTECT ESTA CHAMANDO -> VirtualProtect: ";
    std::printf(" 0x%llx  0x%llx  0x%llx  0x%llx\n", lpAddress, dwSize, flNewProtect, lpflOldProtect);

    return g_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}


auto APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved ) -> BOOL {

    std::cout << "[!] LAIN ENTRY !\n";

    if (MH_Initialize() != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(&IsDebuggerPresent, &dtIsDebuggerPresent, reinterpret_cast<void**>(&g_IsDebuggerOr)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(&IsDebuggerPresent) != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(&CheckRemoteDebuggerPresent, &dtCheckRemoteDebuggerPresent, reinterpret_cast<void**>(&g_isCheckRemoteDbgOr)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(&CheckRemoteDebuggerPresent) != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(pNtGetThreadContext, &dtNtGetThreadContext, reinterpret_cast<void**>(&g_NtGetThreadContext)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(pNtGetThreadContext) != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(pNtClose, &dtNtCloseHandle, reinterpret_cast<void**>(&g_NtCloseHandle)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(pNtClose) != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(&CreateFileA, &dtCreateFileA, reinterpret_cast<void **>(&g_CreateFileA)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(&CreateFileA) != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(pNtQueryInformationProcess, &dtNtQueryInformationProcess, reinterpret_cast<void**>(&g_NtQueryInformationProcess)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(pNtQueryInformationProcess) != MH_OK) return WN_CANCEL;

    if (MH_CreateHook(pNtSetInformationThread, &dtNtSetInformationThread, reinterpret_cast<void**>(&g_NtSetInformationThread)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(pNtSetInformationThread) != MH_OK) return WN_CANCEL;

    /*if (MH_CreateHook(&VirtualProtect, &dtVirtualProtect, reinterpret_cast<void**>(&g_VirtualProtect)) != MH_OK) return WN_CANCEL;

    if (MH_EnableHook(&VirtualProtect) != MH_OK) return WN_CANCEL;*/

    std::cout << "[!] LAIN HOOK'S OK !\n";

    return TRUE;
}

