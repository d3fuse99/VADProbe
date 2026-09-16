#include "Heuristics.hpp"
#include <psapi.h>
#include <array>
#include <format>
#include <filesystem>

namespace Heuristics {

    static std::pair<std::string, bool> ResolveAddressOwner(HANDLE hProcess, uintptr_t targetAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(targetAddr), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            return { "Inaccessible / Unallocated Memory", true };
        }

        if (mbi.Type == MEM_PRIVATE) {
            return { std::format("0x{:X} -> UNBACKED (MEM_PRIVATE) [MALICIOUS]", targetAddr), true };
        }

        wchar_t mappedPath[MAX_PATH] = { 0 };
        if (::GetMappedFileNameW(hProcess, mbi.BaseAddress, mappedPath, MAX_PATH) > 0) {
            std::filesystem::path p(mappedPath);
            return { std::format("0x{:X} -> Module [{}]", targetAddr, p.filename().string()), false };
        }

        return { std::format("0x{:X} -> Mapped memory (No file)", targetAddr), true };
    }

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

            const uintptr_t funcAddr = reinterpret_cast<uintptr_t>(localProc);
            std::array<uint8_t, 16> prologue = { 0 };
            SIZE_T bytesRead = 0;

            if (!::ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(funcAddr), prologue.data(), prologue.size(), &bytesRead) || bytesRead < 8) {
                continue;
            }

            bool hooked = false;
            uintptr_t destAddress = 0;
            std::string hookType;

            if (prologue[0] == 0xE9) {
                hooked = true;
                hookType = "JMP rel32 (0xE9)";
                const int32_t relOffset = *reinterpret_cast<const int32_t*>(prologue.data() + 1);
                destAddress = funcAddr + 5 + relOffset;
            } else if (prologue[0] == 0xFF && prologue[1] == 0x25) {
                hooked = true;
                hookType = "Indirect JMP (0xFF 0x25)";
                const int32_t relOffset = *reinterpret_cast<const int32_t*>(prologue.data() + 2);
                const uintptr_t targetPtr = funcAddr + 6 + relOffset;
                ::ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(targetPtr), &destAddress, sizeof(destAddress), nullptr);
            } else if (prologue[0] == 0x48 && prologue[1] == 0xB8) {
                hooked = true;
                hookType = "MOV RAX + JMP";
                destAddress = *reinterpret_cast<const uintptr_t*>(prologue.data() + 2);
            } else if (prologue[0] != 0x4C || prologue[1] != 0x8B || prologue[2] != 0xD1) {
                hooked = true;
                hookType = "Modified Syscall Prologue";
            }

            if (hooked) {
                std::string targetDescription;
                bool isMalicious = false;

                if (destAddress != 0) {
                    auto [owner, malicious] = ResolveAddressOwner(hProcess, destAddress);
                    targetDescription = owner;
                    isMalicious = malicious;
                } else {
                    targetDescription = "Unknown inline alteration";
                    isMalicious = true;
                }

                findings.push_back(Finding{
                    .Address = funcAddr,
                    .Size = 16,
                    .Description = std::format("[{}] Hook via {} -> {}", funcName, hookType, targetDescription),
                    .IsCritical = isMalicious
                });
            }
        }

        return findings;
    }

    std::optional<Finding> DetectProcessHollowing(HANDLE hProcess) {
        HMODULE hMod = nullptr;
        DWORD cbNeeded = 0;
        if (!::EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded) || !hMod) {
            return std::nullopt;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQueryEx(hProcess, hMod, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            return std::nullopt;
        }

        if (mbi.Type != MEM_IMAGE) {
            return Finding{
                .Address = reinterpret_cast<uintptr_t>(hMod),
                .Size = mbi.RegionSize,
                .Description = "Process Hollowing: Main module memory is not MEM_IMAGE (Allocated as Private/Mapped)",
                .IsCritical = true
            };
        }

        IMAGE_DOS_HEADER dosHeader{};
        SIZE_T read = 0;
        if (::ReadProcessMemory(hProcess, hMod, &dosHeader, sizeof(dosHeader), &read) && read == sizeof(dosHeader)) {
            if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
                return Finding{
                    .Address = reinterpret_cast<uintptr_t>(hMod),
                    .Size = sizeof(dosHeader),
                    .Description = "Process Hollowing: MZ signature wiped in main module base address",
                    .IsCritical = true
                };
            }
        }

        return std::nullopt;
    }
}