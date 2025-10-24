#pragma once

#include <windows.h>
#include <Externs.hpp>
#include <Beacon.hpp>

#define BUFFER_SIZE  8192
#define print(...) Printf(__VA_ARGS__)
SEC_ATTR(".data") CHAR* Output = 0;
SEC_ATTR(".data") WORD  CurrentBufferSize = 0;

// Macro to cast a value to a generic pointer
template<typename T>
constexpr auto PTR(T v) -> PVOID {
    return reinterpret_cast<PVOID>(v);
}

// Macro to cast a value to an unsigned pointer-sized integer
template<typename T>
constexpr auto U_PTR(T v) -> ULONG_PTR {
    return reinterpret_cast<ULONG_PTR>(v);
}

// Macro to cast a value to pointer to bytes
template<typename T>
constexpr auto B_PTR(T v) -> PBYTE {
    return reinterpret_cast<PBYTE>(v);
}

// Macro to check if a pointer or value is NULL
template<typename T>
constexpr auto IS_NULL(T* v) -> BOOL {
    return v == nullptr;
}

/**
 * @brief Represents a type that can be dereferenced using the '*' operator.
 *
 * This typically includes raw pointers (e.g., T*) and types that overload operator*.
 * Use this to constrain templates to pointer-like behavior without relying on the STL.
 */
template<typename T>
concept Ptr = requires(T a) {
    reinterpret_cast<void*>(a);
};

/**
 * @brief Ensures the type is a complete object type with a defined size.
 *
 * This concept is satisfied only when the type `T` can be dereferenced and its size is known at compile time,
 * which implies `T` must be a complete type (i.e., not forward-declared).
 *
 * Useful for memory allocation templates that require a known object layout.
 */
template<typename T>
concept Sized = requires {
    sizeof(*static_cast<T*>(nullptr));
};

namespace Mem {
    /**
     * @brief Copies data from a source to a destination in memory.
     *
     * @param Dest Pointer to the destination location.
     * @param Src Pointer to the source data.
     * @param Size Size in bytes to be copied.
     *
     * @return S Returns the destination pointer.
    */
    template<typename S>
    requires Ptr<S>
    auto Copy(S Dest, const S Src, SIZE_T Size) -> S {
        return static_cast<S>( __builtin_memcpy( Dest, Src, Size ) );
    }

    /**
     * @brief Defines a specific value for a memory block.
     *
     * @param Dst Pointer to the destination memory block.
     * @param Value Value to be set in each byte of the memory block.
     * @param Size Size in bytes of the memory block.
     *
     * @return S Returns the destination pointer.
     */
    template<typename S>
    requires Ptr<S>
    auto Set(S Dst, const INT Value, const SIZE_T Size) -> void {
        __stosb( reinterpret_cast<PUCHAR>( Dst ), Value, Size );
    }

    /**
     * @brief Allocates a block of memory from the heap.
     *
     * @param Size The size of the memory block to allocate (in bytes).
     *
     * @return S Pointer to the allocated memory block, or NULL if allocation fails.
     */
    template<typename S>
    requires Sized<S>
    auto Alloc(const SIZE_T Size) -> S {
        return static_cast<S>( HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, Size ) );
    }

    /**
     * @brief Reallocates a block of memory to a new size.
     *
     * @tparam S The type of the pointer to be reallocated.
     * @param Ptr Pointer to the memory block to be reallocated.
     * @param NewSize The new size of the memory block (in bytes).
     *
     * @return S Pointer to the reallocated memory block, or NULL if reallocation fails.
     */
    template<typename S>
    requires Ptr<S>
    auto ReAlloc(S Ptr, const SIZE_T NewSize) -> S {
        return static_cast<S>( HeapReAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, Ptr, NewSize ) );
    }

    /**
     * @brief Frees a block of memory previously allocated with `Alloc`.
     *
     * @param Ptr Pointer to the memory block to be freed.
     *
     * @return Returns TRUE if the memory was successfully freed, FALSE otherwise.
     */
    inline auto Free(PVOID Ptr) -> BOOL {
        return HeapFree( GetProcessHeap(), 0x00, Ptr );
    }
};

/**
 * @brief Initializes the output buffer.
 * 
 * Allocates memory for the global output buffer and initializes `CurrentBufferSize` to 0.
 * 
 * @return INT Returns EXIT_SUCCESS on success.
 */
auto Start() -> INT {
    Output = Mem::Alloc<PCHAR>( BUFFER_SIZE );
    CurrentBufferSize = 0;
    return EXIT_SUCCESS; 
}

/**
 * @brief Sends the current contents of the output buffer to the beacon output.
 * 
 * @param Done If TRUE, the buffer is freed after sending its contents.
 */
auto PrintOutput(BOOL Done) -> void {
    if ( CurrentBufferSize > 0 ) {
        BeaconOutput( 0, Output, CurrentBufferSize );
        CurrentBufferSize = 0;
        Mem::Set( Output, 0, BUFFER_SIZE );
    }

    if ( Done ) {
        Mem::Free( Output );
    }
}

/**
 * @brief Writes a formatted string to the output buffer.
 * 
 * If the buffer is full, it automatically flushes the current contents before continuing.
 * 
 * @param Format The format string (similar to printf).
 * @param ... Arguments matching the placeholders in the format string.
 */
auto Printf(const char* Format, ...) -> void {
    va_list Args;
    va_start( Args, Format );

    while ( TRUE ) {
        INT Written = vsnprintf( Output + CurrentBufferSize, BUFFER_SIZE - CurrentBufferSize, Format, Args );

        if ( Written < 0 ) { 
            va_end( Args ); 
            return;
        }

        if ( ( SIZE_T )Written + CurrentBufferSize >= BUFFER_SIZE ) {
            PrintOutput( FALSE );
        } else {
            CurrentBufferSize += Written;
            break;
        }
    }

    va_end(Args);
}

/**
 * @brief Converts a UTF-16 string (wchar_t*) to a UTF-8 string (char*).
 *
 * @param Input Pointer to the wide string (UTF-16) to be converted.
 *
 * @return Pointer to the newly allocated UTF-8 string, or NULL on failure.
 */
inline auto WideToUtf8(const PWCHAR Input) -> PCHAR {
    if (IS_NULL(Input)) return nullptr;

    //
    // Determine the required size for the UTF-8 string
    //
    const auto Size = WideCharToMultiByte(
        CP_UTF8, 0, Input, -1, nullptr, 0, nullptr, nullptr
    );

    if (Size <= 0) return nullptr;

    //
    // Allocate memory for the UTF-8 string
    //
    const auto Str = static_cast<PCHAR>( Mem::Alloc<PCHAR>( Size ) );
    if (IS_NULL(Str)) return nullptr;

    //
    // Perform the UTF-16 to UTF-8 conversion
    //
    const auto Result = WideCharToMultiByte(
        CP_UTF8, 0, Input, -1, Str, Size, nullptr, nullptr
    );

    if (Result <= 0) {
        //
        // Free allocated memory on failure
        //
        Mem::Free(Str);
        return nullptr;
    }

    return Str;
}