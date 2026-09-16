#pragma once
#include "Dumper.hpp"
#include <windows.h>
#include <vector>
#include <string>

namespace Engine {
    struct ScanConfig {
        DWORD TargetPid = 0;
        std::wstring TargetName;
        bool SkipJit = false;
        bool AutoDump = true;
    };

    struct ProcessTarget {
        DWORD Pid = 0;
        std::wstring Name;
    };

    class MemoryScanner {
    public:
        explicit MemoryScanner(ScanConfig config);
        void Execute();

    private:
        std::vector<ProcessTarget> EnumerateProcesses() const;
        void ScanProcess(DWORD pid, const std::wstring& name);
        bool ShouldSkipProcess(const std::wstring& name) const;

        ScanConfig m_config;
        Core::Dumper m_dumper;
    };
}