#define UNICODE
#include <windows.h>

size_t GetWindowsErrorMessage(LPWSTR buf)
{
    DWORD err = GetLastError();
    return FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 1000, NULL);
}
