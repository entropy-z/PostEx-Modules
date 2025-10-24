#ifndef GENERAL_HPP
#define GENERAL_HPP

#include <Externs.hpp>
#include <Common.hpp>
#include <Strings.hpp>

typedef struct {
    UPTR  Size;
    ULONG Protect;
    ULONG Type;
    PVOID Offset;
    ULONG State;
} MEMORY_INFORMATION, *PMEMORY_INFORMATION;

#endif // GENERAL_HPP