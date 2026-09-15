#pragma once
#include <windows.h>
#include <span>
#include <vector>
#include <string>

namespace Heuristics {
    struct Finding {
        uintptr_t Address = 0;
        size_t Size = 0;
        std::string Description;
    };

    bool IsUnbackedExecutable(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi);
    bool ContainsHiddenPEHeader(std::span<const uint8_t> buffer);
    std::vector<Finding> DetectNtdllHooks(HANDLE hProcess);
}