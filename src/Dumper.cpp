#include "Dumper.hpp"
#include <fstream>
#include <format>

namespace Core {

Dumper::Dumper(std::filesystem::path outputDir) : m_outputDir(std::move(outputDir)) {
    std::error_code ec;
    std::filesystem::create_directories(m_outputDir, ec);
}

bool Dumper::DumpRegion(DWORD pid, uintptr_t baseAddress, const std::vector<uint8_t>& data, const std::string& tag) const {
    if (data.empty()) return false;

    const std::string filename = std::format("PID_{}_{}_ADDR_0x{:X}.bin", pid, tag, baseAddress);
    const std::filesystem::path fullPath = m_outputDir / filename;

    std::ofstream file(fullPath, std::ios::binary);
    if (!file.is_open()) return false;

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

}