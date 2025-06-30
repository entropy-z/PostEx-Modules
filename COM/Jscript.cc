#include <General.hpp>

// DEFINE_GUID( IAc, BB1A2AE1-A4F9-11CF-8F20-00805F2CD064 );

EXTERN_C
auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };

    BeaconDataParse( &Parser, Args, Argc );

    CHAR* Language = BeaconDataExtract( &Parser, 0 );
    WCHAR wLanguage[MAX_PATH];
    GUID  ScriptCLSID = { 0 };

    Str::CharToWChar( wLanguage, Language, MAX_PATH );

    IActiveScriptParse* ScriptParse  = { 0 };
    IActiveScript*      ScriptEngine = { 0 };

    // CLSIDFromProgID( wLanguage, &ScriptCLSID );

    CoInitializeEx( nullptr, COINIT_MULTITHREADED );

    // CoCreateInstance(
    //     ScriptCLSID, 0, CLSCTX_INPROC_SERVER,
    //     &, (PVOID*)&ScriptEngine
    // );
}