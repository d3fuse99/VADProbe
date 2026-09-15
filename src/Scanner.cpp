#include "Scanner.hpp"
#include "ScopedHandle.hpp"
#include "Heuristics.hpp"
#include <tlhelp32.h>
#include <iostream>
#include <format>
#include <algorithm>

namespace Engine {

    MemoryScanner::MemoryScanner(bool autoDump) 
        : m_dumper("dumps"), m_autoDump(autoDump) {}

    std::vector<ProcessTarget> MemoryScanner::EnumerateProcesses() const {
        std::vector<ProcessTarget> targets;
        ScopedHandle snapshot = MakeScopedHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snapshot.get() == INVALID_HANDLE_VALUE) return targets;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (::Process32FirstW(snapshot.get(), &pe)) {
            do {
                if (pe.th32ProcessID != 0 && pe.th32ProcessID != ::GetCurrentProcessId()) {
                    targets.push_back({ pe.th32ProcessID, pe.szExeFile });
                }
            } while (::Process32NextW(snapshot.get(), &pe));
        }

        return targets;
    }

    void MemoryScanner::ScanProcess(DWORD pid, const std::wstring& name) {
        ScopedHandle hProcess = MakeScopedHandle(::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
            FALSE, 
            pid
        ));

        if (!hProcess) return;

        auto hooks = Heuristics::DetectNtdllHooks(hProcess.get());
        for (const auto& hook : hooks) {
            std::cout << std::format("[!] [PID: {} | {:<18}] {}\n", pid, std::string(name.begin(), name.end()), hook.Description);
            if (m_autoDump) {
                std::vector<uint8_t> buf(hook.Size);
                SIZE_T read = 0;
                if (::ReadProcessMemory(hProcess.get(), reinterpret_cast<LPCVOID>(hook.Address), buf.data(), hook.Size, &read)) {
                    m_dumper.DumpRegion(pid, hook.Address, buf, "HOOK");
                }
            }
        }

        uintptr_t currentAddress = 0;
        MEMORY_BASIC_INFORMATION mbi{};

        while (::VirtualQueryEx(hProcess.get(), reinterpret_cast<LPCVOID>(currentAddress), &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (Heuristics::IsUnbackedExecutable(hProcess.get(), mbi)) {
                const size_t bytesToRead = std::min<size_t>(mbi.RegionSize, 50 * 1024 * 1024);
                std::vector<uint8_t> buffer(bytesToRead);
                SIZE_T bytesRead = 0;

                if (::ReadProcessMemory(hProcess.get(), mbi.BaseAddress, buffer.data(), bytesToRead, &bytesRead)) {
                    buffer.resize(bytesRead);
                    const bool isPE = Heuristics::ContainsHiddenPEHeader(buffer);
                    const std::string tag = isPE ? "INJECTED_PE" : "SHELLCODE";

                    std::cout << std::format("[ALERT] [PID: {} | {:<18}] 0x{:016X} (Size: 0x{:X}) -> {}\n",
                        pid,
                        std::string(name.begin(), name.end()),
                        reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                        mbi.RegionSize,
                        tag
                    );

                    if (m_autoDump) {
                        m_dumper.DumpRegion(pid, reinterpret_cast<uintptr_t>(mbi.BaseAddress), buffer, tag);
                    }
                }
            }

            const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= currentAddress) break;
            currentAddress = next;
        }
    }

    void MemoryScanner::ScanAll() {
        const auto targets = EnumerateProcesses();
        std::cout << std::format("[*] Scanning {} processes...\n", targets.size());

        for (const auto& target : targets) {
            ScanProcess(target.Pid, target.Name);
        }

        std::cout << "[+] Done.\n";
    }
}