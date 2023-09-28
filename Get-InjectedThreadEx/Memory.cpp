#include "Get-InjectedThreadEx.h"

BOOL IsExecutable(const MEMORY_BASIC_INFORMATION& mbi) {
    constexpr auto PAGE_EXECUTE_ANY = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return MEM_COMMIT == mbi.State && 0 != (mbi.Protect & PAGE_EXECUTE_ANY);
}

BOOL ReadProcessMemorySafely(HANDLE hProcess, PVOID address, std::string& buffer, const MEMORY_BASIC_INFORMATION& mbi) {
    if (MEM_COMMIT != mbi.State || 0 != (mbi.Protect & PAGE_GUARD))
        return FALSE;
    // TODO(jdu) NEXT handle reads split over multiple regions
    return ReadProcessMemory(hProcess, address, buffer.data(), buffer.size(), NULL);
}

BOOL ReadProcessMemorySafely(HANDLE hProcess, PVOID address, std::string& buffer) {
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
        return FALSE;
    return ReadProcessMemorySafely(hProcess, address, buffer, mbi);
}

BOOL ReadProcessMemorySafely(HANDLE hProcess, PVOID address, PDWORD64 buffer) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
        return FALSE;
    auto b = MEM_COMMIT != mbi.State;
    auto b2 = 0 != (mbi.Protect & PAGE_GUARD);
    auto b3 = (MEM_COMMIT != mbi.State || 0 != (mbi.Protect & PAGE_GUARD));
    if (MEM_COMMIT != mbi.State || 0 != (mbi.Protect & PAGE_GUARD))
        return FALSE;
    return ReadProcessMemory(hProcess, address, buffer, sizeof(DWORD64), NULL);
}

BOOL GetMappedFileNameAsDosPath(HANDLE hProcess, PVOID address, std::wstring& buffer) {

    // Cache #1 - the mapping of shared image allocations to DOS paths
    const auto bIsSharedDll = InSystemImageRange(address);
    const auto allocationBase = (ULONG_PTR)address & ~0xFFFFull;
    static std::unordered_map<ULONG_PTR, std::wstring> s_DosPathCache;
    if (bIsSharedDll) {
        const auto it = s_DosPathCache.find(allocationBase);
        if (it != s_DosPathCache.end()) {
            buffer = it->second;
            return TRUE;
        }
    }

    // Cache #2 - the mapping from Device prefixes to Dos prefixes
    static std::unordered_map<std::wstring, std::wstring> s_Device2DosPrefixMap;
    if (s_Device2DosPrefixMap.empty()) {
        wchar_t drive[3] = L"A:";
        for (drive[0] = L'A'; drive[0] <= L'Z'; drive[0]++) {
            std::wstring deviceName;
            deviceName.resize(MAX_PATH);
            if (!QueryDosDeviceW(drive, deviceName.data(), (DWORD)deviceName.size())) {
                const auto dwError = GetLastError();
                if (ERROR_FILE_NOT_FOUND != dwError)
                    LogError("QueryDosDeviceW(%S) failed with %d\n", drive, dwError);
                continue;
            }
            deviceName.resize(wcslen(deviceName.c_str()));
            s_Device2DosPrefixMap.insert(std::make_pair(deviceName, std::wstring(drive)));
        }
    }

    buffer.clear();
    buffer.resize(MAX_PATH);

    // Note - K32GetMappedFileName returns the device path such as \Device\Harddisk0\Windows\System32\ntdll.dll
    auto nBytesReturned = K32GetMappedFileNameW(hProcess, address, buffer.data(), (DWORD)buffer.size());
    if (MAX_PATH == nBytesReturned) {
        buffer.resize(MAX_LONG_PATH);
        nBytesReturned = K32GetMappedFileNameW(hProcess, address, buffer.data(), (DWORD)buffer.size());
        if (MAX_LONG_PATH == nBytesReturned)
            LogError("K32GetMappedFileNameW(%p) exceeded maximum long path - %S\n", address, buffer.substr(0, MAX_PATH).c_str());
    }

    if (0 == nBytesReturned)
        return FALSE;

    // We have a device path - now convert it to a DOS path
    constexpr auto DEVICE_PREFIX = L"\\Device\\";
    if (buffer.length() < sizeof(DEVICE_PREFIX) || 0 != _wcsnicmp(buffer.c_str(), DEVICE_PREFIX, sizeof(DEVICE_PREFIX))) {
        LogError("K32GetMappedFileNameW(%p) did not return device path - %S\n", address, buffer.substr(0, MAX_PATH).c_str());
        return TRUE;  // best effort - return what we have
    }

    // Loopkup DOS prefix of "\device\<name>" component in our cached mapping
    const auto pos = buffer.find(L'\\', std::char_traits<WCHAR>::length(DEVICE_PREFIX));
    const auto devicePrefixLength = (std::wstring::npos == pos) ? buffer.length() : pos;
    const auto device2DosPrefixMapping = s_Device2DosPrefixMap.find(buffer.substr(0, devicePrefixLength));
    if (s_Device2DosPrefixMap.end() == device2DosPrefixMapping) {
        LogError("Could not resolve device prefix to DOS drive letter - %S\n", buffer.substr(0, MAX_PATH).c_str());
        return TRUE;  // best effort - return what we have
    }

    buffer = device2DosPrefixMapping->second + buffer.substr(devicePrefixLength);
    buffer.resize(wcslen(buffer.c_str()));

    // Update our path cache
    if (nBytesReturned && bIsSharedDll)
        s_DosPathCache.insert(std::make_pair(allocationBase, buffer));

    return TRUE;
}

std::string ToHex(std::string bytes) {
    std::stringstream hexBytes;
    hexBytes << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes.length(); i++) {
        hexBytes << std::setw(2) << (DWORD)(BYTE)bytes[i];
    }
    return hexBytes.str();
}