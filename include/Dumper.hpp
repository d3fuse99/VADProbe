#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>

namespace Core {
    class Dumper {
    public:
        explicit Dumper(std::filesystem::path outputDir = "dumps");
        bool DumpRegion(DWORD pid, uintptr_t baseAddress, const std::vector<uint8_t>& data, const std::string& tag) const;

    private:
        std::filesystem::path m_outputDir;
    };
}