#pragma once
#include "Dumper.hpp"
#include <windows.h>
#include <vector>
#include <string>

namespace Engine {
    struct ProcessTarget {
        DWORD Pid = 0;
        std::wstring Name;
    };

    class MemoryScanner {
    public:
        explicit MemoryScanner(bool autoDump = true);
        void ScanAll();
        void ScanProcess(DWORD pid, const std::wstring& name);

    private:
        std::vector<ProcessTarget> EnumerateProcesses() const;
        Core::Dumper m_dumper;
        bool m_autoDump;
    };
}