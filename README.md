# VADProbe

**VADProbe** is a high-performance native Windows x64 in-memory threat hunting and injection scanner written in modern C++20. It inspects process virtual address descriptors (VAD) and user-mode memory spaces to identify unbacked executable code, reflective DLLs, inline syscall hooks, and process hollowing.

---

## Key Features

* **Unbacked Executable Memory Scanner:** Scans process address space for committed pages with execute permissions (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ`) that are `MEM_PRIVATE` or unassociated with any on-disk module (`GetMappedFileNameW`).
* **Hidden PE Header Detection:** Analyzes suspicious executable blocks for injected PE structures (`IMAGE_DOS_HEADER` / `IMAGE_NT_HEADERS`), detecting reflective DLL loaders and manually mapped binaries.
* **Smart Hook Destination Resolver:** Disassembles critical NTDLL Native API syscall stubs (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, etc.) to detect `0xE9 JMP`, `0xFF 0x25`, and `MOV RAX + JMP` trampolines. Resolves destination addresses to distinguish between security software (`[MODULE HOOK]`) and unbacked shellcode (`[MALICIOUS HOOK]`).
* **Process Hollowing Detector:** Validates the primary module base of running processes to ensure integrity, checking for unmapped `MEM_IMAGE` sections and zeroed-out DOS headers.
* **Targeted Scanning & Noise Filtering:** Fast CLI supporting PID filtering, process targeting, and built-in filtering for JIT-heavy engines (Chromium, Firefox, .NET).
* **Artifact Dumping:** Safely dumps detected anomalous memory regions into `.bin` files ready for analysis in Ghidra, IDA Pro, or x64dbg.
* **Strict RAII:** Custom resource wrappers (`ScopedHandle`) guarantee safe handle cleanup with zero handle leaks.

---

## Project Structure

```
VADProbe/
├── include/
│   ├── ScopedHandle.hpp   # RAII Windows handle wrapper
│   ├── Privileges.hpp     # Token privilege management (SeDebugPrivilege)
│   ├── Dumper.hpp         # Raw memory dumper (.bin)
│   ├── Heuristics.hpp     # Detection heuristics (Hooks, PE, Unbacked VAD)
│   └── Scanner.hpp        # Process iterator & inspection engine
├── src/
│   ├── Privileges.cpp
│   ├── Dumper.cpp
│   ├── Heuristics.cpp
│   ├── Scanner.cpp
│   └── main.cpp           # CLI and entry point
└── CMakeLists.txt
```

---

## Building

### Requirements
* Windows 10 / 11 x64
* MSVC C++20 compiler (Visual Studio 2022 or Build Tools)

### Build via MSVC CLI:
Open **x64 Native Tools Command Prompt for VS 2022**:

```cmd
cd /d D:\project\VADProbe
cl /std:c++20 /O2 /EHsc /Iinclude src\*.cpp /link psapi.lib advapi32.lib /OUT:VADProbe.exe
```

### Build via CMake:
```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

---

## Usage

> **Note:** VADProbe requires **Administrator** privileges to enable `SeDebugPrivilege` and inspect protected process memory.

```cmd
VADProbe.exe [options]
```

### CLI Options

| Option | Description |
| :--- | :--- |
| `--pid <PID>` | Scan a specific process by its PID |
| `--name <Process.exe>` | Scan processes matching a specific executable name |
| `--no-jit` | Filter out noisy JIT processes (browsers, Discord, VS Code) |
| `--no-dump` | Audit only: disable saving `.bin` files to disk |
| `--help`, `-h` | Display available command-line options |

### Examples

**Scan the entire system while filtering browser and JIT noise:**
```cmd
VADProbe.exe --no-jit
```

**Target a specific suspicious process without dumping files:**
```cmd
VADProbe.exe --name explorer.exe --no-dump
```

**Investigate a single PID:**
```cmd
VADProbe.exe --pid 1337
```