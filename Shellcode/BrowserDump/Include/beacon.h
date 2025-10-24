#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

// Beacon callback types
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

// Data parser structure
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

// Beacon API declarations
DECLSPEC_IMPORT void BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char* BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char* data, int len);

// WinAPI function pointers (avoid direct imports)
DECLSPEC_IMPORT WINBASEAPI void* __cdecl MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT WINBASEAPI void __cdecl MSVCRT$free(void* ptr);
DECLSPEC_IMPORT WINBASEAPI void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t n);
DECLSPEC_IMPORT WINBASEAPI void* __cdecl MSVCRT$memset(void* s, int c, size_t n);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$memcmp(const void* s1, const void* s2, size_t n);
DECLSPEC_IMPORT WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT WINBASEAPI char* __cdecl MSVCRT$strstr(const char* haystack, const char* needle);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$snprintf(char* buf, size_t size, const char* fmt, ...);
DECLSPEC_IMPORT WINBASEAPI int __cdecl MSVCRT$_stricmp(const char* s1, const char* s2);

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE);

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

#endif // BEACON_H