#include <General.hpp>

auto IAT::xExitProcess( UINT uExitCode ) -> VOID {
        return ExitThread( uExitCode );
    }

auto IAT::xRtlExitUserProcess( NTSTATUS ExitStatus ) -> VOID {
    return RtlExitUserThread( ExitStatus );
}

auto IAT::xTerminateProcess( HANDLE hProcess, UINT uExitCode ) -> BOOL {
    if ( hProcess != NtCurrentProcess() ) {
        return TerminateProcess( hProcess, uExitCode );
    }

    return TRUE;
}

auto IAT::xNtTerminateProcess( HANDLE hProcess, NTSTATUS uExitCode ) -> NTSTATUS {
    if ( hProcess != NtCurrentProcess() ) {
        return NtTerminateProcess( hProcess, uExitCode );
    }

    return STATUS_SUCCESS;
}

auto IAT::xVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID {  
    return VirtualAlloc( lpAddress, dwSize, flAllocationType, flProtect );
}  

auto IAT::xVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID {  
    return VirtualAllocEx( hProcess, lpAddress, dwSize, flAllocationType, flProtect );
}  

auto IAT::xNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) -> NTSTATUS {  
    return NtAllocateVirtualMemory( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect );
}  

auto IAT::xVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) -> BOOL {  
    return VirtualProtect( lpAddress, dwSize, flNewProtect, lpflOldProtect );
}  

auto IAT::xVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) -> BOOL {  
    return VirtualProtectEx( hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect );
}  

auto IAT::xNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) -> NTSTATUS {  
    return NtProtectVirtualMemory( ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection );
}  

auto IAT::xReadProcessMemory( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead ) -> BOOL {
    return ReadProcessMemory( hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead );
}

auto IAT::xNtReadVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded ) -> NTSTATUS {
    return NtReadVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded );
}

auto IAT::xWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) -> BOOL {  
    return WriteProcessMemory( hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten );
}  

auto IAT::xNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) -> NTSTATUS {  
    return NtWriteVirtualMemory( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten );
}  

auto IAT::xOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) -> HANDLE {  
    return OpenProcess( dwDesiredAccess, bInheritHandle, dwProcessId );
}  

auto IAT::xOpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) -> HANDLE {  
    return OpenThread( dwDesiredAccess, bInheritHandle, dwThreadId );
}  

auto IAT::xDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) -> BOOL {  
    return DuplicateHandle( hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions );
}  

auto IAT::xNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options) -> NTSTATUS {  
    return NtDuplicateObject( SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, Attributes, Options );
}  

auto IAT::xLoadLibraryA(LPCSTR lpLibFileName) -> HMODULE {  
    return LoadLibraryA( lpLibFileName );
}  

auto IAT::xLoadLibraryW(LPCWSTR lpLibFileName) -> HMODULE {  
    return LoadLibraryW( lpLibFileName );
}  

auto IAT::xSetThreadContext(HANDLE hThread, const CONTEXT* lpContext) -> BOOL {  
    return SetThreadContext( hThread, lpContext );
}  

auto IAT::xGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) -> BOOL {  
    return GetThreadContext( hThread, lpContext );
}  

auto IAT::xNtSetContextThread(HANDLE ThreadHandle, CONTEXT* ontext) -> NTSTATUS {  
    return NtSetContextThread( ThreadHandle, ontext );
}  

auto IAT::xNtGetContextThread( HANDLE ThreadHandle, PCONTEXT Context ) -> NTSTATUS {  
    return NtGetContextThread( ThreadHandle, Context );
}  

auto IAT::xGetCommandLineA( VOID ) -> CHAR* {
    return IAT::CmdAnsi;
}

auto IAT::xGetCommandLineW( VOID ) -> WCHAR* {
    return IAT::CmdWide;
}

auto IAT::__p___argv( VOID )  -> CHAR*** {
    return &IAT::PoiArgvA;
}

auto IAT::__p___wargv( VOID ) -> WCHAR*** {
    return &IAT::PoiArgvW;
}

auto IAT::__p___argc( VOID )  -> INT* {
    return &IAT::CmdArgc;
}

auto IAT::__getmainargs( INT* _Argc, CHAR*** _Argv, CHAR*** _Env, INT _Useless_, PVOID _Useless ) -> INT {
    *_Argc = IAT::CmdArgc;
    *_Argv = IAT::PoiArgvA;

    return 0;
}

auto IAT::__wgetmainargs( INT* _Argc, WCHAR*** _Argv, WCHAR*** _Env, INT _Useless_, PVOID _Useless ) -> INT {
    *_Argc = IAT::CmdArgc;
    *_Argv = IAT::PoiArgvW;

    return 0;
}

FILE *__cdecl __acrt_iob_funcs(unsigned index) {
    return (FILE*)&(__iob_func()[index]);
}

#define stdin  (__acrt_iob_funcs(0))
#define stdout (__acrt_iob_funcs(1))
#define stderr (__acrt_iob_funcs(2))