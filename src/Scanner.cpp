#include "Scanner.hpp"
#include "ScopedHandle.hpp"
#include "Heuristics.hpp"
#include <tlhelp32.h>
#include <iostream>
#include <format>
#include <algorithm>
#include <unordered_set>

namespace Engine {

    MemoryScanner::MemoryScanner(ScanConfig config) 
        : m_config(std::move(config)), m_dumper("dumps") {}

    bool MemoryScanner::ShouldSkipProcess(const std::wstring& name) const {
        if (!m_config.SkipJit) return false;

        static const std::unordered_set<std::wstring> jitList = {
            L"Code.exe", L"firefox.exe", L"msedge.exe", L"chrome.exe",
            L"powershell.exe", L"pwsh.exe", L"devenv.exe", L"vctip.exe",
            L"Discord.exe", L"Spotify.exe", L"Steam.exe"
        };
        return jitList.contains(name);
    }

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
        if (ShouldSkipProcess(name)) return;

        ScopedHandle hProcess = MakeScopedHandle(::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
            FALSE, 
            pid
        ));

        if (!hProcess) return;

        const std::string procNameStr(name.begin(), name.end());

        // 1. Проверка Process Hollowing
        if (auto hollowAlert = Heuristics::DetectProcessHollowing(hProcess.get())) {
            std::cout << std::format("[CRITICAL] [PID: {} | {:<16}] {}\n", pid, procNameStr, hollowAlert->Description);
        }

        // 2. Проверка NTDLL хуков с резолвом назначения
        auto hooks = Heuristics::DetectNtdllHooks(hProcess.get());
        for (const auto& hook : hooks) {
            const std::string tag = hook.IsCritical ? "[MALICIOUS HOOK]" : "[MODULE HOOK]   ";
            std::cout << std::format("{} [PID: {} | {:<16}] {}\n", tag, pid, procNameStr, hook.Description);

            if (hook.IsCritical && m_config.AutoDump) {
                std::vector<uint8_t> buf(hook.Size);
                SIZE_T read = 0;
                if (::ReadProcessMemory(hProcess.get(), reinterpret_cast<LPCVOID>(hook.Address), buf.data(), hook.Size, &read)) {
                    m_dumper.DumpRegion(pid, hook.Address, buf, "HOOK");
                }
            }
        }

        // 3. Сканирование VAD регионов на Unbacked память
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

                    std::cout << std::format("[ALERT]          [PID: {} | {:<16}] 0x{:016X} (Size: 0x{:X}) -> {}\n",
                        pid,
                        procNameStr,
                        reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                        mbi.RegionSize,
                        tag
                    );

                    if (m_config.AutoDump) {
                        m_dumper.DumpRegion(pid, reinterpret_cast<uintptr_t>(mbi.BaseAddress), buffer, tag);
                    }
                }
            }

            const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= currentAddress) break;
            currentAddress = next;
        }
    }

    void MemoryScanner::Execute() {
        if (m_config.TargetPid != 0) {
            std::cout << std::format("[*] Scanning single PID: {}\n", m_config.TargetPid);
            ScanProcess(m_config.TargetPid, L"TargetPID");
            std::cout << "[+] Done.\n";
            return;
        }

        const auto targets = EnumerateProcesses();
        std::cout << std::format("[*] Scanning processes (Total: {})...\n", targets.size());

        for (const auto& target : targets) {
            if (!m_config.TargetName.empty() && target.Name != m_config.TargetName) {
                continue;
            }
            ScanProcess(target.Pid, target.Name);
        }

        std::cout << "[+] Done.\n";
    }
}