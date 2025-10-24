#include <windows.h>
#include <Native.hpp>

namespace Str {
    auto StartsWith(
        BYTE* Str, 
        BYTE* Prefix
    ) -> BOOL {
        if (!Str || !Prefix) {
            return FALSE;
        }

        while (*Prefix) {
            if (*Str != *Prefix) {
                return FALSE; 
            }
            ++Str;
            ++Prefix;
        }
        return TRUE;
    }
    
    auto WCharToChar( 
        PCHAR  Dest, 
        PWCHAR Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T {
        SIZE_T Length = MaxAllowed;
        while (--Length > 0) {
            if (!(*Dest++ = static_cast<CHAR>(*Src++))) {
                return MaxAllowed - Length - 1;
            }
        }
        return MaxAllowed - Length;
    }

    auto CharToWChar( 
        PWCHAR Dest, 
        PCHAR  Src, 
        SIZE_T MaxAllowed 
    ) -> SIZE_T {
        SIZE_T Length = MaxAllowed;
        while ( --Length > 0 ) {
            if ( !( *Dest++ = static_cast<WCHAR>( *Src++ ) ) ) {
                return MaxAllowed - Length - 1;
            }
        }
        return MaxAllowed - Length;
    }

    auto LengthA( 
        LPCSTR String 
    ) -> SIZE_T {
        LPCSTR End = String;
        while (*End) ++End;
        return End - String;
    }

    auto LengthW( 
        LPCWSTR String 
    ) -> SIZE_T {
        LPCWSTR End = String;
        while (*End) ++End;
        return End - String;
    }

    auto CompareCountA( 
        PCSTR Str1, 
        PCSTR Str2, 
        INT16 Count 
    ) -> INT {
        INT16 Idx = 0;

        while (*Str1 && (*Str1 == *Str2) && Idx == Count ) {
            ++Str1;
            ++Str2;

            Idx++;
        }
        return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
    }

    auto CompareA( 
        LPCSTR Str1, 
        LPCSTR Str2 
    ) -> INT {
        while (*Str1 && (*Str1 == *Str2)) {
            ++Str1;
            ++Str2;
        }
        return static_cast<INT>(*Str1) - static_cast<INT>(*Str2);
    }

    auto CompareW( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> INT {
        while ( *Str1 && ( *Str1 == *Str2 ) ) {
            ++Str1;
            ++Str2;
        }
        return static_cast<INT>( *Str1 ) - static_cast<INT>( *Str2 );
    }

    auto ToUpperChar(
        char* str
    ) -> VOID {
        while (*str) {
            if (*str >= 'a' && *str <= 'z') {
                *str = *str - ('a' - 'A');
            }
            str++;
        }
    }

    auto ToLowerChar( 
        PCHAR Str
    ) -> VOID {
        while (*Str) {
            if (*Str >= 'A' && *Str <= 'Z') {
                *Str += ('a' - 'A');
            }
            ++Str;
        }
    }

    auto ToLowerWchar( 
        WCHAR Ch 
    ) -> WCHAR {
        return (Ch >= L'A' && Ch <= L'Z') ? Ch + (L'a' - L'A') : Ch;
    }

    auto CopyA( 
        PCHAR  Dest, 
        LPCSTR Src 
    ) -> PCHAR {
        PCHAR p = Dest;
        while ((*p++ = *Src++));
        return Dest;
    }

    auto CopyW( 
        PWCHAR  Dest, 
        LPCWSTR Src 
    ) -> PWCHAR {
        PWCHAR p = Dest;
        while ( ( *p++ = *Src++ ) );
        return Dest;
    }

    auto ConcatA( 
        PCHAR  Dest, 
        LPCSTR Src 
    ) -> PCHAR {
        CopyA( Dest + LengthA(Dest), Src );
    }

    auto ConcatW( 
        PWCHAR  Dest, 
        LPCWSTR Src 
    ) -> PWCHAR {
        CopyW( Dest + LengthW(Dest), Src );
    }

    auto IsEqual( 
        LPCWSTR Str1, 
        LPCWSTR Str2 
    ) -> BOOL {
        WCHAR TempStr1[MAX_PATH], TempStr2[MAX_PATH];
        SIZE_T Length1 = LengthW( Str1 );
        SIZE_T Length2 = LengthW( Str2 );

        if ( Length1 >= MAX_PATH || Length2 >= MAX_PATH ) return FALSE;

        for (SIZE_T i = 0; i < Length1; ++i) {
            TempStr1[i] = ToLowerWchar( Str1[i] );
        }
        TempStr1[Length1] = L'\0';

        for (SIZE_T j = 0; j < Length2; ++j) {
            TempStr2[j] = ToLowerWchar( Str2[j] );
        }
        TempStr2[Length2] = L'\0';

        return CompareW( TempStr1, TempStr2 ) == 0;
    }

    auto InitUnicode( 
        PUNICODE_STRING UnicodeString, 
        PWSTR           Buffer 
    ) -> VOID {
        if (Buffer) {
            SIZE_T Length = LengthW(Buffer) * sizeof(WCHAR);
            if (Length > 0xFFFC) Length = 0xFFFC;

            UnicodeString->Buffer = const_cast<PWSTR>(Buffer);
            UnicodeString->Length = static_cast<USHORT>(Length);
            UnicodeString->MaximumLength = static_cast<USHORT>(Length + sizeof(WCHAR));
        } else {
            UnicodeString->Buffer = nullptr;
            UnicodeString->Length = 0;
            UnicodeString->MaximumLength = 0;
        }
    }
}