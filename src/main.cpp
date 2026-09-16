#include "Privileges.hpp"
#include "Scanner.hpp"
#include <iostream>
#include <string_view>

static void PrintHelp() {
    std::cout << "VADProbe - Advanced Memory Injection & Hook Scanner\n"
              << "Usage: VADProbe.exe [options]\n\n"
              << "Options:\n"
              << "  --pid <PID>         Scan specific process ID only\n"
              << "  --name <Process>    Scan process by executable name (e.g. explorer.exe)\n"
              << "  --no-jit            Filter out JIT-heavy apps (browsers, VS Code, etc.)\n"
              << "  --no-dump           Disable automatic memory dumping to disk\n"
              << "  --help, -h          Show help message\n";
}

int main(int argc, char* argv[]) {
    std::cout << ">>> VADProbe v2.0 Memory Scanner <<<\n\n";

    Engine::ScanConfig config;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            PrintHelp();
            return 0;
        } else if (arg == "--pid" && i + 1 < argc) {
            config.TargetPid = static_cast<DWORD>(std::stoul(argv[++i]));
        } else if (arg == "--name" && i + 1 < argc) {
            std::string nameStr = argv[++i];
            config.TargetName = std::wstring(nameStr.begin(), nameStr.end());
        } else if (arg == "--no-jit") {
            config.SkipJit = true;
        } else if (arg == "--no-dump") {
            config.AutoDump = false;
        }
    }

    if (!Core::EnableDebugPrivilege()) {
        std::cout << "[-] Warning: SeDebugPrivilege failed (run as Administrator)\n";
    } else {
        std::cout << "[+] SeDebugPrivilege enabled\n";
    }

    Engine::MemoryScanner scanner(config);
    scanner.Execute();

    return 0;
}