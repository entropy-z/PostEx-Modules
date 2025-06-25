#include <General.hpp>

auto Dotnet::VersionList( VOID ) -> VOID {
    HRESULT HResult = S_OK;

    PWCHAR FmVersion = Mem::Alloc<WCHAR*>( MAX_PATH*2 );
    ULONG  FmBuffLen = MAX_PATH*2;

    ICLRRuntimeInfo* RtmInfo     = { 0 };
    IUnknown*        EnumRtm     = { 0 };
    IEnumUnknown*    EnumUkwn    = { 0 };
    ICLRMetaHost*    MetaHost    = { 0 };

    //
    // host clr in the process
    //
    HResult = CLRCreateInstance(
        CLSID.CLRMetaHost, IID.ICLRMetaHost, (PVOID*)&MetaHost
    );
    if ( HResult ) goto _BOF_END;

    //
    //  packet the versions
    //
    HResult = MetaHost->EnumerateInstalledRuntimes( &EnumUkwn );
    if ( HResult ) goto _BOF_END;

    while ( EnumUkwn->Next( 1, &EnumRtm, 0 ) == S_OK) {
        if ( !EnumRtm ) continue;

        if ( SUCCEEDED( EnumRtm->QueryInterface( IID.ICLRRuntimeInfo, (PVOID*)&RtmInfo) ) && RtmInfo ) {

            if ( SUCCEEDED( RtmInfo->GetVersionString( FmVersion, &FmBuffLen ) ) ) {
                BeaconPrintf( CALLBACK_OUTPUT, "[+] Supported Version: %S\n", FmVersion );
            }
        }
    }

_BOF_END:
    if ( MetaHost ) MetaHost->Release();
    if ( EnumUkwn ) EnumUkwn->Release();
    if ( EnumRtm  ) EnumRtm->Release();
    if ( RtmInfo  ) RtmInfo->Release();

    return;
}

