#include "Privileges.hpp"
#include "Scanner.hpp"
#include <iostream>

int main() {
    std::cout << ">>> VADProbe Memory Scanner <<<\n\n";

    if (!Core::EnableDebugPrivilege()) {
        std::cout << "[-] Warning: SeDebugPrivilege failed (run as Administrator)\n";
    } else {
        std::cout << "[+] SeDebugPrivilege enabled\n";
    }

    Engine::MemoryScanner scanner(true);
    scanner.ScanAll();

    std::cout << "\n";
    system("pause");
    return 0;
}