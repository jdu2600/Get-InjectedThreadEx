#include "Get-InjectedThreadEx.h"

BOOL InSystemImageRange(PVOID Address) {
    return Address >= (PVOID)0x7FF800000000 && Address < (PVOID)0x7FFFFFFF0000;
}

constexpr UINT64 XFG_MASK_UNSET = ~0xFFFDBFFF7EDFFB71; // mask of unset bits
constexpr UINT64 XFG_MASK_SET = 0x8000060010500070; // mask of set bits
constexpr UINT64 XFG_MASK_ALL = XFG_MASK_UNSET | XFG_MASK_SET;
BOOL IsValidXfgHash(UINT64 xfgHash) {
    return XFG_MASK_SET == (xfgHash & XFG_MASK_ALL);
}

static PULONG_PTR FindCfgBitMap() {
    // Find non-exported ntdll!LdrSystemDllInitBlock.CfgBitMap by looking at the first instruction of LdrControlFlowGuardEnforced
    // 48833d [80be1400], 00    CMP qword ptr[LdrSystemDllInitBlock.CfgBitMap], 0x0
#pragma warning(suppress: 6387)  // ntdll is always loaded
    auto pLdrControlFlowGuardEnforced = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrControlFlowGuardEnforced");
    if (NULL == pLdrControlFlowGuardEnforced)
        return NULL;

    auto ppCfgBitMap = (PULONG_PTR*)((ULONG_PTR)pLdrControlFlowGuardEnforced + 8 + *(DWORD*)((ULONG_PTR)pLdrControlFlowGuardEnforced + 3));

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(*ppCfgBitMap, &mbi, sizeof(mbi)) || MEM_MAPPED != mbi.Type || *ppCfgBitMap != mbi.AllocationBase) {
        LogError("FATAL: ntdll!LdrSystemDllInitBlock.CfgBitMap not found\n");
        ExitProcess(1);
    }

    return *ppCfgBitMap;
}

constexpr auto CFG_INVALID = 0b00;  // no address in this range is a valid target
constexpr auto CFG_ALL_VALID = 0b11;  // all addresses in this range are valid.
constexpr auto CFG_ALIGNED_VALID = 0b01;  // the only valid target is 16-byte aligned
constexpr auto CFG_EXPORT_SUPPRESSED = 0b10;  // this range contains an export-suppressed target

BOOL GetCfgBitsForAddress(PVOID address, PULONG pCfgBits) {
    static auto pCfgBitMap = FindCfgBitMap();
    const PULONG_PTR pLocalEntry = pCfgBitMap + ((ULONG_PTR)address >> 9);
    const ULONG cfgOffset = (((ULONG_PTR)(address)) >> 3) & 0x3E;
    ULONG_PTR localEntry;
    // We use ReadProcessMemory to safely read the volatile CfgBitMap.
    if (ReadProcessMemory(GetCurrentProcess(), pLocalEntry, &localEntry, sizeof(localEntry), NULL)) {
        *pCfgBits = (localEntry >> cfgOffset) & 0b11;
        return TRUE;
    }
    return FALSE;
}
