// Declares a reference to a dynamically imported function with a decorated name (e.g., ntdll$NtOpenProcess)
#define DFR(module, function) DECLSPEC_IMPORT decltype(function) module##$##function;

// Macro to place a variable or function in a specific binary section
#define SEC_ATTR(X) [[gnu::section(X)]]

#define NtCurrentThreadID HandleToUlong( NtCurrentTeb()->ClientId.UniqueThread )

#define DEFB( x )  ( * ( BYTE* )  ( x ) )
#define DEF( x )   ( * ( PVOID* )  ( x ) )
#define DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define DEF16( x ) ( * ( UINT16* ) ( x ) )
#define DEF32( x ) ( * ( UINT32* ) ( x ) )
#define DEF64( x ) ( * ( UINT64* ) ( x ) )