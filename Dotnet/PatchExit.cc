#include <General.hpp>

auto Dotnet::PatchExit(
    _In_ ICorRuntimeHost* IRuntime
) -> HRESULT {
    HRESULT     HResult       = S_OK;

    IAppDomain* AppDomain     = { nullptr };
    IAssembly*  Mscorlib      = { nullptr };
    IUnknown*   AppDomUnknown = { nullptr };

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
    BSTR MHandleBstr  = SysAllocString( L"MethodHandle" );
    BSTR ReflBstr     = SysAllocString( L"System.Reflection.MethodInfo" );
    BSTR GetFncBstr   = SysAllocString( L"GetFunctionPointer" );
    BSTR RtmBstr      = SysAllocString( L"System.RuntimeMethodHandle" );
    BSTR SysEnvBstr   = SysAllocString( L"System.Environment" );
    BSTR ExitBstr     = SysAllocString( L"Exit" );

    HResult = IRuntime->GetDefaultDomain( (IUnknown**)&AppDomUnknown );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = AppDomUnknown->QueryInterface( IID.AppDomain, (PVOID*)&AppDomain );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = Dotnet::GetAssemblyLoaded( AppDomain, L"mscorlib", IID.MscorlibAsm, &Mscorlib );
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

    SafeEmpty = SafeArrayCreateVector( VT_EMPTY, 0, 0 );

    VarMethodPtr.vt      = VT_UNKNOWN;
    VarMethodPtr.punkVal = ExitMethod;

    HResult = MtdHandleProp->GetValue( VarMethodPtr, SafeEmpty, &VarMethodVal );
    if ( FAILED( HResult ) ) goto _BOF_END;

    HResult = GetFncMethod->Invoke_3( VarMethodVal, SafeEmpty, &VarExitPtr );
    if ( FAILED( HResult ) ) goto _BOF_END;

    BeaconPrintf(CALLBACK_OUTPUT, "System.Environment.Exit at %p", VarExitPtr.byref );

_BOF_END:
    if ( MHandleBstr ) SysFreeString( MHandleBstr );
    if ( ReflBstr    ) SysFreeString( ReflBstr );
    if ( GetFncBstr  ) SysFreeString( GetFncBstr );
    if ( RtmBstr     ) SysFreeString( RtmBstr );
    if ( SysEnvBstr  ) SysFreeString( SysEnvBstr );
    if ( ExitBstr    ) SysFreeString( ExitBstr );
    if ( SafeEmpty   ) SafeArrayDestroy( SafeEmpty );

    VariantClear( &VarExitPtr );
    VariantClear( &VarMethodPtr );
    VariantClear( &VarMethodVal );

    if ( MtdHandleProp ) MtdHandleProp->Release();
    if ( SysEnvClass   ) SysEnvClass->Release();
    if ( ReflectClass  ) ReflectClass->Release();
    if ( RtmMethod     ) RtmMethod->Release();
    if ( ExitMethod    ) ExitMethod->Release();
    if ( GetFncMethod  ) GetFncMethod->Release();
    if ( Mscorlib      ) Mscorlib->Release();
    if ( AppDomain     ) AppDomain->Release();
    if ( AppDomUnknown ) AppDomUnknown->Release();

    return HResult;
}
