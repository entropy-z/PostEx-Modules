#pragma once

#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <wsmandisp.h>
#include <netfw.h>
#include <Beacon.hpp>
#include <combaseapi.h>
#include <Native.hpp>

#define DFR(module, function) DECLSPEC_IMPORT decltype(function) module##$##function;

EXTERN_C DECLSPEC_IMPORT INT WINAPI DNSAPI$DnsGetCacheDataTable(PVOID Data);
EXTERN_C {
    DFR(KERNEL32, VirtualAlloc)
    DFR(KERNEL32, LoadLibraryW)
    DFR(KERNEL32, VirtualProtect)
    DFR(KERNEL32, GetEnvironmentStringsW)
    DFR(KERNEL32, GetModuleFileNameW)
    DFR(KERNEL32, FreeEnvironmentStringsW)
    DFR(KERNEL32, GetLastError)
    DFR(KERNEL32, GetProcessHeap)
    DFR(KERNEL32, HeapAlloc)
    DFR(KERNEL32, HeapFree)
    DFR(KERNEL32, WideCharToMultiByte)
    DFR(KERNEL32, OpenProcess)
    DFR(KERNEL32, CreateFileA)
    DFR(KERNEL32, WriteFile)
    DFR(KERNEL32, CreateFileW)
    DFR(KERNEL32, HeapReAlloc)
    DFR(KERNEL32, QueryFullProcessImageNameA)
    DFR(KERNEL32, CloseHandle)
    DFR(KERNEL32, SetFileInformationByHandle)
    
    DFR(IPHLPAPI, GetNetworkParams)
    DFR(IPHLPAPI, GetAdaptersInfo)
    DFR(IPHLPAPI, GetIpForwardTable)
    DFR(IPHLPAPI, GetNetworkParams)
    DFR(IPHLPAPI, GetAdaptersInfo)
    DFR(IPHLPAPI, GetIpForwardTable)

    DFR(WS2_32, inet_ntoa)
    
    DFR(MSVCRT, wcscpy)
    DFR(MSVCRT, wcscat)
    DFR(MSVCRT, printf)
    DFR(MSVCRT, wprintf)
    DFR(MSVCRT, wcslen)
    DFR(MSVCRT, vsnprintf)
    DFR(MSVCRT, wcscmp)

    DFR(NETAPI32, NetUserAdd)

    DFR(ADVAPI32, OpenSCManagerA);
    DFR(ADVAPI32, CreateServiceA);
    DFR(ADVAPI32, StartServiceA);
    DFR(ADVAPI32, CloseServiceHandle);
    DFR(ADVAPI32, RegOpenKeyExA);
    DFR(ADVAPI32, RegSetValueExA);

    DFR(NTDLL, NtOpenSection)
    DFR(NTDLL, NtCreateSection)
    DFR(NTDLL, NtMapViewOfSection)
    DFR(NTDLL, NtUnmapViewOfSection)
    DFR(NTDLL, NtQueryInformationFile)
    DFR(NTDLL, NtSetInformationProcess)
    DFR(NTDLL, NtQueryInformationProcess)

    DFR(OLE32, CoCreateInstance)
    DFR(OLE32, CoInitializeEx)
    DFR(OLE32, CoUninitialize)
    DFR(OLE32, CLSIDFromString)
    DFR(OLE32, IIDFromString)
    DFR(OLE32, CoSetProxyBlanket)
    DFR(OLE32, VariantInit)
    DFR(OLE32, VariantClear)
    DFR(OLE32, SysFreeString)
    DFR(OLE32, SysAllocString)

    DFR(USER32, GetDC)
    DFR(USER32, GetSystemMetrics)

    DFR(GDI32, BitBlt)
    DFR(GDI32, SelectObject)
    DFR(GDI32, CreateDIBSection)
    DFR(GDI32, CreateCompatibleDC)
    DFR(GDI32, GetObjectW)
    DFR(GDI32, GetCurrentObject)
}

#define GetNetworkParams           IPHLPAPI$GetNetworkParams
#define GetAdaptersInfo            IPHLPAPI$GetAdaptersInfo
#define GetIpForwardTable          IPHLPAPI$GetIpForwardTable
#define DnsGetCacheDataTable       DNSAPI$DnsGetCacheDataTable

#define inet_ntoa                  WS2_32$inet_ntoa

#define VirtualProtect             KERNEL32$VirtualProtect
#define LoadLibraryW               KERNEL32$LoadLibraryW
#define VirtualAlloc               KERNEL32$VirtualAlloc
#define GetEnvironmentStringsW     KERNEL32$GetEnvironmentStringsW
#define GetModuleFileNameW         KERNEL32$GetModuleFileNameW
#define FreeEnvironmentStringsW    KERNEL32$FreeEnvironmentStringsW         
#define GetLastError               KERNEL32$GetLastError
#define GetProcessHeap             KERNEL32$GetProcessHeap
#define HeapAlloc                  KERNEL32$HeapAlloc 
#define HeapFree                   KERNEL32$HeapFree
#define WideCharToMultiByte        KERNEL32$WideCharToMultiByte
#define OpenProcess                KERNEL32$OpenProcess
#define CreateFileA                KERNEL32$CreateFileA
#define WriteFile                  KERNEL32$WriteFile
#define CreateFileW                KERNEL32$CreateFileW
#define HeapReAlloc                KERNEL32$HeapReAlloc
#define QueryFullProcessImageNameA KERNEL32$QueryFullProcessImageNameA
#define CloseHandle                KERNEL32$CloseHandle
#define SetFileInformationByHandle KERNEL32$SetFileInformationByHandle

#define OpenSCManagerA             ADVAPI32$OpenSCManagerA   
#define CreateServiceA             ADVAPI32$CreateServiceA
#define StartServiceA              ADVAPI32$StartServiceA
#define CloseServiceHandle         ADVAPI32$CloseServiceHandle
#define RegOpenKeyExA              ADVAPI32$RegOpenKeyExA
#define RegSetValueExA             ADVAPI32$RegSetValueExA

#define wcscat                     MSVCRT$wcscat
#define wcscpy                     MSVCRT$wcscpy
#define wcscmp                     MSVCRT$wcscmp
#define printf                     MSVCRT$printf
#define wprintf                    MSVCRT$wprintf
#define wcslen                     MSVCRT$wcslen
#define vsnprintf                  MSVCRT$vsnprintf
#define NetUserAdd                 NETAPI32$NetUserAdd

#define NtOpenSection              NTDLL$NtOpenSection
#define NtCreateSection            NTDLL$NtCreateSection
#define NtMapViewOfSection         NTDLL$NtMapViewOfSection
#define NtUnmapViewOfSection       NTDLL$NtUnmapViewOfSection
#define NtQueryInformationFile     NTDLL$NtQueryInformationFile
#define NtQueryInformationProcess  NTDLL$NtQueryInformationProcess
#define NtSetInformationProcess    NTDLL$NtSetInformationProcess

#define GetDC                      USER32$GetDC
#define GetSystemMetrics           USER32$GetSystemMetrics

#define BitBlt                     GDI32$BitBlt
#define SelectObject               GDI32$SelectObject
#define CreateDIBSection           GDI32$CreateDIBSection
#define CreateCompatibleDC         GDI32$CreateCompatibleDC
#define GetObjectW                 GDI32$GetObjectW
#define GetCurrentObject           GDI32$GetCurrentObject

#define CoCreateInstance           OLE32$CoCreateInstance
#define CoInitializeEx             OLE32$CoInitializeEx
#define CoUninitialize             OLE32$CoUninitialize
#define CLSIDFromString            OLE32$CLSIDFromString
#define IIDFromString              OLE32$IIDFromString
#define CoSetProxyBlanket          OLE32$CoSetProxyBlanket
#define VariantInit                OLE32$VariantInit
#define VariantClear               OLE32$VariantClear
#define SysFreeString              OLE32$SysFreeString
#define SysAllocString             OLE32$SysAllocString