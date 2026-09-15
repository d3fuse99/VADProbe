#pragma once
#include <windows.h>
#include <memory>

struct HandleCloser {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) {
            ::CloseHandle(h);
        }
    }
};

using ScopedHandle = std::unique_ptr<void, HandleCloser>;

inline ScopedHandle MakeScopedHandle(HANDLE h) noexcept {
    return ScopedHandle(h);
}