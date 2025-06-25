#pragma once

#include <windows.h>
#include <Macros.hpp>
#include <iphlpapi.h>
#include <stdio.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <wsmandisp.h>
#include <CLR.hpp>
#include <guiddef.h>
#include <netfw.h>
#include <ktmw32.h>
#include <aclapi.h>
#include <combaseapi.h>
#include <Native.hpp>
#include <ntstatus.h>

EXTERN_C DECLSPEC_IMPORT INT WINAPI DNSAPI$DnsGetCacheDataTable(PVOID Data);
EXTERN_C {
    DFR(KERNEL32, ExitThread)
    DFR(KERNEL32, ReadProcessMemory)
    DFR(KERNEL32, DuplicateHandle)
    DFR(KERNEL32, GetThreadContext)
    DFR(KERNEL32, SetThreadContext)
    DFR(KERNEL32, ResumeThread)
    DFR(KERNEL32, OpenThread)
    DFR(KERNEL32, VirtualAlloc)
    DFR(KERNEL32, VirtualAllocEx)
    DFR(KERNEL32, LoadLibraryW)
    DFR(KERNEL32, VirtualProtect)
    DFR(KERNEL32, VirtualProtectEx)
    DFR(KERNEL32, WriteProcessMemory)
    DFR(KERNEL32, CreateRemoteThread)
    DFR(KERNEL32, CreateThread)
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
    DFR(KERNEL32, CreateFileW)
    DFR(KERNEL32, HeapReAlloc)
    DFR(KERNEL32, QueryFullProcessImageNameA)
    DFR(KERNEL32, CloseHandle)
    DFR(KERNEL32, SetFileInformationByHandle)
    DFR(KERNEL32, TerminateProcess)
    
    DFR(IPHLPAPI, GetNetworkParams)
    DFR(IPHLPAPI, GetAdaptersInfo)
    DFR(IPHLPAPI, GetIpForwardTable)
    DFR(IPHLPAPI, GetNetworkParams)
    DFR(IPHLPAPI, GetAdaptersInfo)
    DFR(IPHLPAPI, GetIpForwardTable)

    DFR(WS2_32, inet_ntoa)
    
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
    
    DFR(NTDLL, RtlExitUserThread)
    DFR(NTDLL, NtDuplicateObject)
    DFR(NTDLL, NtWriteVirtualMemory)
    DFR(NTDLL, NtAllocateVirtualMemory)
    DFR(NTDLL, NtReadVirtualMemory)
    DFR(NTDLL, NtProtectVirtualMemory)
    DFR(NTDLL, NtTerminateProcess) 
    DFR(NTDLL, RtlAddFunctionTable)
    DFR(NTDLL, LdrGetProcedureAddress)
    DFR(NTDLL, RtlAddVectoredExceptionHandler)
    DFR(NTDLL, RtlRemoveVectoredExceptionHandler)
    DFR(NTDLL, RtlEnterCriticalSection)
    DFR(NTDLL, RtlDeleteCriticalSection)
    DFR(NTDLL, RtlEnterCriticalSection)
    DFR(NTDLL, RtlInitializeCriticalSection)
    DFR(NTDLL, RtlLeaveCriticalSection)
    DFR(NTDLL, NtContinue)
    DFR(NTDLL, NtGetContextThread)
    DFR(NTDLL, NtSetContextThread)
    DFR(NTDLL, NtOpenSection)
    DFR(NTDLL, NtCreateSection)
    DFR(NTDLL, NtMapViewOfSection)
    DFR(NTDLL, NtUnmapViewOfSection)
    DFR(NTDLL, NtQuerySystemInformation)
    DFR(NTDLL, NtQueryInformationFile)
    DFR(NTDLL, NtSetInformationProcess)
    DFR(NTDLL, NtQueryInformationProcess)
    DFR(NTDLL, RtlCreateTimer)

    DFR(OLE32, CoCreateInstance)
    DFR(OLE32, CoInitializeEx)
    DFR(OLE32, CoUninitialize)
    DFR(OLE32, CLSIDFromString)
    DFR(OLE32, IIDFromString)
    DFR(OLE32, CoSetProxyBlanket)
    DFR(OLE32, VariantInit)
    DFR(OLE32, VariantClear)
    DFR(OLE32, SafeArrayCreateVector)
    DFR(OLE32, SafeArrayDestroy)
    DFR(OLE32, SafeArrayPutElement)
    DFR(OLE32, SafeArrayAccessData)
    DFR(OLE32, SafeArrayGetLBound)
    DFR(OLE32, SafeArrayGetUBound)
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

    DFR(MSCOREE, CLRCreateInstance)
}

#define GetNetworkParams           IPHLPAPI$GetNetworkParams
#define GetAdaptersInfo            IPHLPAPI$GetAdaptersInfo
#define GetIpForwardTable          IPHLPAPI$GetIpForwardTable
#define DnsGetCacheDataTable       DNSAPI$DnsGetCacheDataTable

#define inet_ntoa                  WS2_32$inet_ntoa

#define ExitThread                 KERNEL32$ExitThread
#define ReadProcessMemory          KERNEL32$ReadProcessMemory
#define DuplicateHandle            KERNEL32$DuplicateHandle
#define SetThreadContext           KERNEL32$SetThreadContext
#define GetThreadContext           KERNEL32$GetThreadContext
#define TerminateProcess           KERNEL32$TerminateProcess
#define ResumeThread               KERNEL32$ResumeThread
#define OpenThread                 KERNEL32$OpenThread
#define VirtualProtect             KERNEL32$VirtualProtect
#define VirtualProtectEx           KERNEL32$VirtualProtectEx
#define VirtualAlloc               KERNEL32$VirtualAlloc
#define VirtualAllocEx             KERNEL32$VirtualAllocEx
#define WriteProcessMemory         KERNEL32$WriteProcessMemory
#define GetEnvironmentStringsW     KERNEL32$GetEnvironmentStringsW
#define GetModuleFileNameW         KERNEL32$GetModuleFileNameW
#define FreeEnvironmentStringsW    KERNEL32$FreeEnvironmentStringsW         
#define GetLastError               KERNEL32$GetLastError
#define GetProcessHeap             KERNEL32$GetProcessHeap
#define HeapAlloc                  KERNEL32$HeapAlloc 
#define HeapFree                   KERNEL32$HeapFree
#define WideCharToMultiByte        KERNEL32$WideCharToMultiByte
#define OpenProcess                KERNEL32$OpenProcess
#define CreateRemoteThread         KERNEL32$CreateRemoteThread
#define CreateThread               KERNEL32$CreateThread
#define CreateFileA                KERNEL32$CreateFileA
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

#define wcscmp                     MSVCRT$wcscmp
#define printf                     MSVCRT$printf
#define wprintf                    MSVCRT$wprintf
#define wcslen                     MSVCRT$wcslen
#define vsnprintf                  MSVCRT$vsnprintf
#define NetUserAdd                 NETAPI32$NetUserAdd

#define RtlExitUserThread                 NTDLL$RtlExitUserThread
#define NtAllocateVirtualMemory           NTDLL$NtAllocateVirtualMemory
#define NtReadVirtualMemory               NTDLL$NtReadVirtualMemory
#define NtProtectVirtualMemory            NTDLL$NtProtectVirtualMemory
#define NtWriteVirtualMemory              NTDLL$NtWriteVirtualMemory
#define NtDuplicateObject                 NTDLL$NtDuplicateObject
#define NtTerminateProcess                NTDLL$NtTerminateProcess
#define RtlAddFunctionTable               NTDLL$RtlAddFunctionTable
#define LdrGetProcedureAddress            NTDLL$LdrGetProcedureAddress
#define RtlDeleteCriticalSection          NTDLL$RtlDeleteCriticalSection
#define RtlRemoveVectoredExceptionHandler NTDLL$RtlRemoveVectoredExceptionHandler
#define RtlAddVectoredExceptionHandler    NTDLL$RtlAddVectoredExceptionHandler
#define RtlInitializeCriticalSection      NTDLL$RtlInitializeCriticalSection
#define RtlEnterCriticalSection           NTDLL$RtlEnterCriticalSection
#define RtlLeaveCriticalSection           NTDLL$RtlLeaveCriticalSection
#define NtContinue                        NTDLL$NtContinue
#define NtGetContextThread                NTDLL$NtGetContextThread
#define NtSetContextThread                NTDLL$NtSetContextThread
#define NtOpenSection                     NTDLL$NtOpenSection
#define NtCreateSection                   NTDLL$NtCreateSection
#define NtMapViewOfSection                NTDLL$NtMapViewOfSection
#define NtUnmapViewOfSection              NTDLL$NtUnmapViewOfSection
#define NtQueryInformationFile            NTDLL$NtQueryInformationFile
#define NtQuerySystemInformation          NTDLL$NtQuerySystemInformation
#define NtQueryInformationProcess         NTDLL$NtQueryInformationProcess
#define NtSetInformationProcess           NTDLL$NtSetInformationProcess
#define RtlCreateTimer                    NTDLL$RtlCreateTimer

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
#define CLSIDFromString            OLE32$CLSIDFromString
#define IIDFromString              OLE32$IIDFromString
#define CoSetProxyBlanket          OLE32$CoSetProxyBlanket
#define VariantInit                OLE32$VariantInit
#define VariantClear               OLE32$VariantClear
#define SafeArrayCreateVector      OLE32$SafeArrayCreateVector
#define SafeArrayDestroy           OLE32$SafeArrayDestroy
#define SafeArrayPutElement        OLE32$SafeArrayPutElement
#define SafeArrayAccessData        OLE32$SafeArrayAccessData
#define SafeArrayGetLBound         OLE32$SafeArrayGetLBound
#define SafeArrayGetUBound         OLE32$SafeArrayGetUBound
#define SysFreeString              OLE32$SysFreeString
#define SysAllocString             OLE32$SysAllocString

#define CLRCreateInstance          MSCOREE$CLRCreateInstance