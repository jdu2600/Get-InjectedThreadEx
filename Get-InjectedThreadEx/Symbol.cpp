#include "Get-InjectedThreadEx.h"

typedef struct _SYMBOL_INFO_FULL : SYMBOL_INFO {
    CHAR NameBuffer[MAX_SYM_NAME - 1];
} SYMBOL_INFO_FULL;
#define INIT_FAILED ((HANDLE)-3)

constexpr auto SYMOPTS = SYMOPT_UNDNAME | SYMOPT_CASE_INSENSITIVE | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_INCLUDE_32BIT_MODULES;

constexpr auto MicrosoftPublicSymbols = L"srv**https://msdl.microsoft.com/download/symbols";

static HANDLE GetUniqueIdForSymbols() {
    // Initialise once - note we're only resolving symbols locally.
    static HANDLE s_hUniqueId = NULL;  // INVALID_HANDLE_VALUE == GetCurrentProcess()!
    if (NULL == s_hUniqueId) {
        if (!SymSetOptions(SymGetOptions() | SYMOPTS))
            LogError("SymSetOptions() failed with 0x%x", GetLastError());
        s_hUniqueId = GetCurrentProcess();
        if (!SymInitializeW(s_hUniqueId, MicrosoftPublicSymbols, FALSE)) {
            LogError("SymInitialize() failed with 0x%x", GetLastError());
            s_hUniqueId = INIT_FAILED;
        }
        else
        {
            // Check that we're using public symbols - not just exports
            auto hNtdll = GetModuleHandleW(L"ntdll.dll");
            std::wstring ntdllPath;
            if (!GetMappedFileNameAsDosPath(GetCurrentProcess(), hNtdll, ntdllPath))
                LogError("GetMappedFilename(ntdll) failed");
            if(!SymLoadModuleExW(s_hUniqueId, NULL, ntdllPath.c_str(), NULL, (DWORD64)hNtdll, 0, NULL, 0))
                LogError("SymLoadModule(ntdll) failed");
            if (!GetSymbolAddress("ntdll!TppWorkerThread"))
                LogError("WARNING Symbols not found - falling back to exports");
            
            auto hKernel32 = GetModuleHandleW(L"kernel32.dll");
            std::wstring kernel32Path;
            if (!GetMappedFileNameAsDosPath(GetCurrentProcess(), hKernel32, kernel32Path))
                LogError("GetMappedFilename(kernel32) failed");
            if (!SymLoadModuleExW(s_hUniqueId, NULL, kernel32Path.c_str(), NULL, (DWORD64)hKernel32, 0, NULL, 0))
                LogError("SymLoadModule(kernel32) failed");
        }
    }
    return s_hUniqueId;
}

PVOID GetSymbolAddress(const char symbol[]) {
    const auto hUniqueId = GetUniqueIdForSymbols();
    if (INIT_FAILED == hUniqueId)
        return NULL;

    SYMBOL_INFO_FULL symbolInfo{};
    symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.MaxNameLen = MAX_SYM_NAME;
    if (!SymFromName(hUniqueId, symbol, &symbolInfo))
        return NULL;

    return (PVOID)symbolInfo.Address;
}


// pretty print <module>!<symbol>[+<displacement>]
void GetPrettySymbol(HANDLE hProcess, PVOID address, std::wstring& modulePath, std::string& symbol, bool bIncludeDisplacement) {
    symbol.resize(128);
    symbol = std::filesystem::path(modulePath).filename().string();

    SYMBOL_INFO_FULL symbolInfo{};
    symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.MaxNameLen = MAX_SYM_NAME;
    DWORD64 displacement = 0;
    if (SymFromAddr(hProcess, (DWORD64)address, &displacement, &symbolInfo)) {
        symbol += "!" + std::string(symbolInfo.Name);
    }
    else if (bIncludeDisplacement) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)))
            displacement = (DWORD64)address - (DWORD64)mbi.AllocationBase;
    }

    if (bIncludeDisplacement && displacement) {
        char buffer[_MAX_U64TOSTR_BASE16_COUNT];
        _ui64toa_s(displacement, buffer, sizeof(buffer), 16);
        symbol += "+0x" + std::string(buffer);
    }

    symbol.resize(strlen(symbol.c_str()));
}

BOOL GetNearestSymbolWithPdb(HANDLE hProcess, PVOID address, std::string& symbol, bool bIncludeDisplacement) {
    if (!SymSetOptions(SymGetOptions() | SYMOPTS))
        LogError("SymSetOptions() failed with 0x%x", GetLastError());
    
    if (!SymInitializeW(hProcess, MicrosoftPublicSymbols, FALSE)) {
        LogError("SymInitialize() failed with 0x%x", GetLastError());
        return FALSE;
    }

    std::wstring modulePath;
    if (!GetMappedFileNameAsDosPath(hProcess, address, modulePath)) {
        if (symbol.empty()) {
            char buffer[_MAX_U64TOSTR_BASE16_COUNT];
            _ui64toa_s((DWORD64)address, buffer, sizeof(buffer), 16);
            symbol = "0x" + std::string(buffer);
        }
        (void)SymCleanup(hProcess);
        return TRUE;
    }
    
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) ||
        !SymLoadModuleExW(hProcess, NULL, modulePath.c_str(), NULL, (DWORD64)mbi.AllocationBase, 0, NULL, 0))
    {
        (void)SymCleanup(hProcess);
        // fallback to best-effort
        const auto hUniqueId = GetUniqueIdForSymbols();
        GetPrettySymbol(hUniqueId, address, modulePath, symbol, bIncludeDisplacement);
        return FALSE;
    }

    GetPrettySymbol(hProcess, address, modulePath, symbol, bIncludeDisplacement);

    (void)SymCleanup(hProcess);
    return TRUE;
}


BOOL GetNearestSymbol(HANDLE hProcess, PVOID address, std::string& symbol, bool bIncludeDisplacement) {
    const auto hUniqueId = GetUniqueIdForSymbols();
    if (INIT_FAILED == hUniqueId)
        return FALSE;

    // Maintain a cache of symbols in shared image allocations
    static std::unordered_map<PVOID, std::string> s_SymbolCache;
    const auto it = s_SymbolCache.find(address);
    if (it != s_SymbolCache.end()) {
        symbol = it->second;
        return TRUE;
    }

    // module name (from remote process)
    std::wstring modulePath;
    if (!GetMappedFileNameAsDosPath(hProcess, address, modulePath)) {
        char buffer[_MAX_U64TOSTR_BASE16_COUNT];
        _ui64toa_s((DWORD64)address, buffer, sizeof(buffer), 16);
        symbol = "0x" + std::string(buffer);
        return TRUE;
    }

    GetPrettySymbol(hUniqueId, address, modulePath, symbol, bIncludeDisplacement);

    if (InSystemImageRange(address))
        s_SymbolCache.insert(std::make_pair(address, symbol));

    return TRUE;
}
