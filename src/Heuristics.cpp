#include "Heuristics.hpp"
#include <psapi.h>
#include <array>
#include <format>

namespace Heuristics {

    bool IsUnbackedExecutable(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi) {
        if (mbi.State != MEM_COMMIT) return false;

        const bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                                 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        if (!isExecutable) return false;

        if (mbi.Type == MEM_PRIVATE) {
            return true;
        }

        if (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE) {
            wchar_t mappedPath[MAX_PATH] = { 0 };
            const DWORD res = ::GetMappedFileNameW(hProcess, mbi.BaseAddress, mappedPath, MAX_PATH);
            if (res == 0) {
                return true;
            }
        }

        return false;
    }

    bool ContainsHiddenPEHeader(std::span<const uint8_t> buffer) {
        if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > buffer.size()) {
            return false;
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer.data() + dos->e_lfanew);
        return nt->Signature == IMAGE_NT_SIGNATURE;
    }

    std::vector<Finding> DetectNtdllHooks(HANDLE hProcess) {
        std::vector<Finding> findings;
        static const std::array<const char*, 6> syscalls = {
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "NtQueueApcThread",
            "NtMapViewOfSection"
        };

        const HMODULE localNtdll = ::GetModuleHandleW(L"ntdll.dll");
        if (!localNtdll) return findings;

        for (const char* funcName : syscalls) {
            FARPROC localProc = ::GetProcAddress(localNtdll, funcName);
            if (!localProc) continue;

            const uintptr_t targetAddr = reinterpret_cast<uintptr_t>(localProc);
            std::array<uint8_t, 16> prologue = { 0 };
            SIZE_T bytesRead = 0;

            if (!::ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(targetAddr), prologue.data(), prologue.size(), &bytesRead) || bytesRead < 8) {
                continue;
            }

            bool hooked = false;
            std::string reason;

            if (prologue[0] == 0xE9) {
                hooked = true;
                reason = "JMP relative (0xE9)";
            } else if (prologue[0] == 0xFF && prologue[1] == 0x25) {
                hooked = true;
                reason = "Indirect JMP (0xFF 0x25)";
            } else if (prologue[0] == 0x48 && prologue[1] == 0xB8) {
                hooked = true;
                reason = "MOV RAX + JMP";
            } else if (prologue[0] != 0x4C || prologue[1] != 0x8B || prologue[2] != 0xD1) {
                hooked = true;
                reason = "Modified Syscall Prologue";
            }

            if (hooked) {
                findings.push_back(Finding{
                    .Address = targetAddr,
                    .Size = 16,
                    .Description = std::format("Hook in [{}] -> {}", funcName, reason)
                });
            }
        }

        return findings;
    }
}