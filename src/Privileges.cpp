#include "Privileges.hpp"
#include "ScopedHandle.hpp"

namespace Core {
    bool EnableDebugPrivilege() noexcept {
        HANDLE rawToken = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
            return false;
        }
        ScopedHandle token = MakeScopedHandle(rawToken);

        TOKEN_PRIVILEGES tp{};
        LUID luid{};

        if (!::LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        return ::AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) &&
               (::GetLastError() == ERROR_SUCCESS);
    }
}