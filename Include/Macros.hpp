// Declares a reference to a dynamically imported function with a decorated name (e.g., ntdll$NtOpenProcess)
#define DFR(module, function) DECLSPEC_IMPORT decltype(function) module##$##function;

// Macro to place a variable or function in a specific binary section
#define SEC_ATTR(X) [[gnu::section(X)]]