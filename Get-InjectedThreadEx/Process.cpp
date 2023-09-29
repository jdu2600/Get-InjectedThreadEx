#include "Get-InjectedThreadEx.h"

BOOL IsElevated()
{
    BOOL bIsElevated = FALSE;

    DWORD dwSize;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) &&
        GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize) &&
        sizeof(elevation) == dwSize)
    {
        bIsElevated = elevation.TokenIsElevated;
    }

    if (hToken) {
        (void)CloseHandle(hToken);
    }

    return bIsElevated;
}

BOOL GetProcessPath(HANDLE hProcess, std::wstring& buffer) {
    buffer.clear();

    buffer.resize(MAX_PATH);
    DWORD size = (DWORD)buffer.size();
    if (!QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &size)) {
        buffer.resize(MAX_LONG_PATH);
        size = (DWORD)buffer.size();
        if (!QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &size)) {
            buffer.clear();
            return FALSE;
        }
    }

    buffer.resize(size);
        return TRUE;
}

BOOL IsDotNet(HANDLE hProcess) {
    std::wstring executable;
    if (!GetProcessPath(hProcess, executable))
        return FALSE;

    // Map the executable's PE headers.
    constexpr auto FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    auto hFile = CreateFileW(executable.c_str(), GENERIC_READ, FILE_SHARE_ALL, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    auto hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    auto pMapping = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0x1000);
    
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
    // The last directory is actually the CLR Runtime Header - not the "COM Descriptor".
    // If it exists, then the PE file is a CLR assembly - aka .NET
    ULONG size = 0;
    BOOL bIsDotNet = NULL != ImageDirectoryEntryToData(pMapping, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &size);

    if (pMapping)
        (void)UnmapViewOfFile(pMapping);
    if (hMapping)
        (void)CloseHandle(hMapping);
    if (hFile)
        (void)CloseHandle(hFile);

    return bIsDotNet;
}
