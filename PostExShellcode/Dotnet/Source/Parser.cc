#include <General.hpp>

auto DECLFN Parser::New( 
    _In_ PARSER* parser, 
    _In_ PVOID   Buffer
) -> VOID {
    G_INSTANCE

    if ( parser == NULL )
        return;

    ULONG Size = *(ULONG*)( Buffer );

    parser->Original = Heap::Alloc<CHAR*>( Size );
    Mem::Copy( parser->Original, (BYTE*)( Buffer ) + 4, Size );
    parser->Buffer   = parser->Original;
    parser->Length   = Size;
    parser->Size     = Size;

    Instance->Pipe.Fork = Parser::Int32( parser );

    if ( Instance->Pipe.Fork ) {
        Instance->Pipe.Name = Parser::Str( parser, 0 );
    }
}

auto DECLFN Parser::Pad(
    _In_  PARSER* parser,
    _Out_ ULONG size
) -> BYTE* {
    if (!parser)
        return NULL;

    if (parser->Length < size)
        return NULL;

    BYTE* padData = (BYTE*)(parser->Buffer);

    parser->Buffer += size;
    parser->Length -= size;

    return padData;
}

auto DECLFN Parser::Int32( 
    _In_ PARSER* parser 
) -> INT32 {
    G_INSTANCE

    INT32 intBytes = 0;

    // if ( parser->Length < 4 )
        // return 0;

    Mem::Copy( &intBytes, parser->Buffer, 4 );

    Dbg2("int32 %d", intBytes);

    parser->Buffer += 4;
    parser->Length -= 4;

    // if ( ! Parser::Endian )
    //     return ( INT ) intBytes;
    // else
    return ( INT ) ( intBytes );
}

auto DECLFN Parser::Bytes( 
    _In_ PARSER* parser, 
    _In_ ULONG*  size 
) -> BYTE* {
    UINT32  Length  = 0;
    BYTE*   outdata = NULL;

    if ( parser->Length < 4 || !parser->Buffer )
        return NULL;

    Mem::Copy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    // if ( this->Endian )
    Length = ( Length );

    outdata = (BYTE*)( parser->Buffer );
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

auto DECLFN Parser::Destroy( 
    _In_ PARSER* Parser 
) -> BOOL {
    if ( ! Parser ) return FALSE;

    BOOL Success = TRUE;

    if ( Parser->Original ) {
        Success = Heap::Free( Parser->Original );
        Parser->Original = nullptr;
        Parser->Length   = 0;
    }

    if ( Parser ) {
        Success = Heap::Free( Parser );
        Parser = nullptr;
    }

    return Success;
}

auto DECLFN Parser::Str( 
    _In_ PARSER* parser, 
    _In_ ULONG* size 
) -> PCHAR {
    return ( PCHAR ) Parser::Bytes( parser, size );
}

auto DECLFN Parser::Wstr( 
    _In_ PARSER* parser, 
    _In_ ULONG*  size 
) -> PWCHAR {
     return ( PWCHAR )Parser::Bytes( parser, size );
}
auto DECLFN Parser::Int16( 
    _In_ PARSER* parser
) -> INT16 {
    INT16 intBytes = 0;

    if ( parser->Length < 2 )
        return 0;

    Mem::Copy( &intBytes, parser->Buffer, 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

    // if ( !this->Endian ) 
    //     return intBytes;
    // else 
    return __builtin_bswap16( intBytes ) ;
}

auto DECLFN Parser::Int64( 
    _In_ PARSER* parser 
) -> INT64 {
    INT64 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    Mem::Copy( &intBytes, parser->Buffer, 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

    // if ( !this->Endian )
    //     return ( INT64 ) intBytes;
    // else
    return ( INT64 ) __builtin_bswap64( intBytes );
}

auto DECLFN Parser::Byte( 
    _In_ PARSER* parser 
) -> BYTE {
    BYTE intBytes = 0;

    if ( parser->Length < 1 )
        return 0;

    Mem::Copy( &intBytes, parser->Buffer, 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intBytes;
}