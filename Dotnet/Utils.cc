#include <General.hpp>

auto Dotnet::CreateVariantCmd(
    WCHAR* Command
) -> VARIANT {
    VARIANT var;
    VariantInit(&var);
    
    var.vt = VT_BSTR;                  
    var.bstrVal = SysAllocString( Command );
    
    return var;
}

auto Dotnet::CreateSafeArray(
    VARIANT* Args, 
    UINT     Argc
) -> SAFEARRAY* {
    if (!Args || Argc == 0) {
        return nullptr;
    }
    SAFEARRAY* SafeArg = SafeArrayCreateVector( VT_VARIANT, 0, Argc );
    if ( !SafeArg ) {
        return nullptr;
    }

    for ( UINT i = 0; i < Argc; i++ ) {
        LONG index = i;
        HRESULT HResult = SafeArrayPutElement( SafeArg, &index, &Args[i] );
        if ( FAILED( HResult ) ) {
            SafeArrayDestroy(SafeArg); return nullptr;
        }
    }

    return SafeArg;
}

auto Dotnet::GetMethodType(
    IBindingFlags  Flags,
    IType*        MType,
    BSTR          MethodInp,
    IMethodInfo** MethodReff
) -> HRESULT {
    HRESULT       HResult     = S_OK;
    SAFEARRAY*    SafeMethods = { nullptr };
    IMethodInfo** MethodsInfo = { nullptr };
    IMethodInfo*  MethodRef   = { nullptr };
    LONG lLower,  lUpper;

    HResult = MType->GetMethods( (IBindingFlags)Flags, &SafeMethods );
    if ( FAILED( HResult ) ) {
        Printf("[x] Failed to get methods: 0x%08X\n", HResult); return HResult;
    }

    SafeArrayGetLBound( SafeMethods, 1, &lLower );
    SafeArrayGetUBound( SafeMethods, 1, &lUpper );
    
    // Printf("[+] Number of methods: %d\n", (lUpper - lLower + 1));

    SafeArrayAccessData( SafeMethods, (PVOID*)&MethodsInfo );

    for ( LONG i = lLower; i <= lUpper; i++ ) {
        BSTR MethodName = nullptr;
        MethodsInfo[i]->get_name( &MethodName );
        // Printf( "[+] Method Name[%d]: %S", i, MethodName );
        if ( MethodName && Str::CompareW( MethodName, MethodInp ) == 0 ) {
            // Printf("[+] Found %S method", MethodName);
            MethodRef = MethodsInfo[i];
            MethodRef->AddRef();
            SysFreeString( MethodName );
            break;
        }
        
        if ( MethodName ) SysFreeString( MethodName );
    }

    *MethodReff = MethodRef;

    return HResult;
}

auto Dotnet::GetAssemblyLoaded(
    _In_  IAppDomain* AppDomain,
    _In_  WCHAR*      AsmName1,
    _In_  GUID        AsmIID, 
    _Out_ IAssembly** Assembly
) -> HRESULT {
    HRESULT    HResult  = S_OK;
    BSTR       AsmName2 = { nullptr };
    IAssembly* AsmTmp   = { nullptr };
    IUnknown** UnkDf    = { nullptr };

    LONG lLower = 0;
    LONG lUpper = 0;

    SAFEARRAY* SafeAsms = { nullptr };

    HResult = AppDomain->GetAssemblies( &SafeAsms );
    if ( FAILED( HResult ) ) return HResult;

    SafeArrayGetLBound( SafeAsms, 1, &lLower );
    SafeArrayGetUBound( SafeAsms, 1, &lUpper );

    SafeArrayAccessData( SafeAsms, (PVOID*)&UnkDf );

    for ( LONG i = lLower; i <= lUpper; i++ ) {
        IUnknown* UnkTmp = UnkDf[i];
        if ( ! UnkTmp ) continue;

        AsmTmp = nullptr;
        HResult  = UnkTmp->QueryInterface( AsmIID, (PVOID*)&AsmTmp );
        if ( SUCCEEDED( HResult ) && AsmTmp ) {
            HResult = AsmTmp->get_ToString( &AsmName2 );
            if ( FAILED( HResult ) ) return HResult;

            // BeaconPrintf(CALLBACK_OUTPUT, "[%d] %S", i, AsmName2 );

            if ( SUCCEEDED( HResult ) && AsmName2 ) {
                if ( Str::StartsWith( (BYTE*)AsmName2, (BYTE*)AsmName1 ) ) {
                    // BeaconPrintf(CALLBACK_OUTPUT, "%S found", AsmName2 ); *Assembly = AsmTmp; break;
                }
            }
            
            SysFreeString( AsmName2 );
        }

        UnkTmp->Release();
    }

    return HResult;
}