// Reference:
// https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
//
// Other useful references:
// https://codemachine.com/articles/x64_deep_dive.html
// http://www.uninformed.org/?v=4&a=1 Improving Automated Analysis of Windows x64 Binaries
// http://www.nynaeve.net/?p=113 Programming against the x64 exception handling support
// https://www.sciencedirect.com/science/article/pii/S1742287618300458 Building stack traces from memory dump of Windows x64
// https://github.com/reactos/reactos/blob/master/sdk/lib/rtl/amd64/unwind.c
// https://auscitte.github.io/posts/Exception-Directory-pefile Boots for Walking Backwards: Teaching pefile How to Understand SEH-Related Data in 64-bit PE Files
// https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs

#include "Get-InjectedThreadEx.h"

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_EPILOG,          /* added in v2. UNDOCUMENTED. */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no dwError-code, 1: dwError-code */
} UNWIND_CODE_OPS;

// from ehdata.h
#pragma warning (push)
#pragma warning (disable: 4201)
typedef union _UNWIND_CODE {
    struct {
        unsigned char CodeOffset;
        unsigned char UnwindOp : 4;
        unsigned char OpInfo : 4;
    };
    unsigned short FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;
typedef struct _UNWIND_INFO {
    unsigned char Version : 3;
    unsigned char Flags : 5;
    unsigned char SizeOfProlog;
    unsigned char CountOfCodes;
    unsigned char FrameRegister : 4;
    unsigned char FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes+1)&~1)-1];
     *  union {
     *      OPTIONAL unsigned long ExceptionHandler;
     *      OPTIONAL unsigned long FunctionEntry;
     *  };
     *  OPTIONAL unsigned long ExceptionData[];
     */
} UNWIND_INFO, * PUNWIND_INFO;
#pragma warning (pop)

constexpr auto W_FPREG = 1;  // WARNING - frame pointer in use;
static HRESULT CalculateFrameSize_Internal(const PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase, const DWORD rva, PDWORD pFrameSize)
{
    HRESULT status = S_OK;

    const auto pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindInfoAddress + ImageBase);
    if (!pUnwindInfo || pUnwindInfo->Version > 2) {
        LogError("UNWIND_INFO v%d not supported", pUnwindInfo->Version);
        return E_NOTIMPL;
    }

    const auto codeOffset = rva - pRuntimeFunction->BeginAddress;

    // Loop over unwind codes and calculate total stack space used by target function.
    BYTE i = 0;
    while (i < pUnwindInfo->CountOfCodes)
    {
        // Warning: This implementation is not complete and may not work for some edge cases.
        // For example, it does not handle handle RIP pointing into an epilog.
        // But that should be rare for our early frames use case.

        const auto unwindOperation = pUnwindInfo->UnwindCode[i].UnwindOp;
        const auto operationInfo = pUnwindInfo->UnwindCode[i].OpInfo;
        const auto bApplyOperation = codeOffset > pUnwindInfo->UnwindCode[i].CodeOffset;

        i++;
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            if (bApplyOperation)
                (*pFrameSize)++;
            break;
        case UWOP_ALLOC_LARGE:
            switch (operationInfo) {
            case 0:
                if (bApplyOperation)
                    *pFrameSize += pUnwindInfo->UnwindCode[i].FrameOffset;
                i++;
                break;
            case 1:
                if (bApplyOperation)
                    *pFrameSize += *(DWORD*)(&pUnwindInfo->UnwindCode[i]) / sizeof(PVOID);
                i += 3;
                break;
            default:
                LogError("UWOP_ALLOC_LARGE operationInfo is invalid: (%d)", operationInfo);
                return E_INVALIDARG;
            }
            break;
        case UWOP_ALLOC_SMALL:
            if (bApplyOperation)
                *pFrameSize += operationInfo + 1;
            break;
        case UWOP_SET_FPREG:
            if (bApplyOperation) {
                // Frame pointer in use. Our frame size calculation is inaccurate if alloca() was used.
                // https://learn.microsoft.com/en-us/cpp/build/stack-usage
                // > If space is dynamically allocated (alloca) in a function, then a
                // > nonvolatile register must be used as a frame pointer to mark the
                // > base of the fixed part of the stack and that register must be saved
                // > and initialized in the prolog.
                *pFrameSize = pUnwindInfo->FrameOffset * 2;
                status = W_FPREG;  // This is a WARNING code - not an ERROR
            }
            break;
        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:
        case UWOP_EPILOG:
            i++;
            break;
        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR:
            i += 2;
            break;
        case UWOP_PUSH_MACHFRAME:
            if (bApplyOperation) {
                *pFrameSize += 5 + operationInfo;
            }
            break;
        default:
            if (bApplyOperation) {
                LogError("UNWIND_INFO operation is not implemented: %d", unwindOperation);
                return E_INVALIDARG;
            }
        }
    }

    if (0 != (UNW_FLAG_CHAININFO & pUnwindInfo->Flags)) {
        const auto pPrimaryUwindInfo = (PRUNTIME_FUNCTION) & (pUnwindInfo->UnwindCode[(pUnwindInfo->CountOfCodes + 1) & ~1]);
        return CalculateFrameSize_Internal(pPrimaryUwindInfo, ImageBase, rva, pFrameSize);
    }

    // Add the size of the return address.
    *pFrameSize += 1;

    return status;
}

static_assert(!IS_ERROR(W_FPREG));
static_assert(!FAILED(W_FPREG));
// Calculates the total stack space (in PVOIDs) used by the stack frame.
HRESULT CalculateFrameSize(PVOID returnAddress, PDWORD pFrameSize, const std::wstring& filepath, PVOID remoteBase)
{
    // Check a cache of UNWIND_INFO lookups first.
    static std::unordered_map<PVOID, DWORD> frameSizes;
    const auto it = frameSizes.find(returnAddress);
    if (it != frameSizes.end()) {
        *pFrameSize = it->second;
        return S_OK;
    }

    const DWORD rva = (DWORD)((ULONG_PTR)returnAddress - (ULONG_PTR)remoteBase);
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 localBase;

    auto hModule = GetModuleHandleW(filepath.c_str());
    if (hModule == remoteBase) {
        // Image is already loaded in our process - lock it in memory now.
        hModule = LoadLibraryW(filepath.c_str());
        if (NULL == hModule) {
            LogError("LoadLibrary(%S) failed", filepath.c_str());
            return E_UNEXPECTED;

        }

        pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)returnAddress, &localBase, NULL);
        if (NULL == pRuntimeFunction)
            return E_FAIL;
    }
    else {
        // Image is not loaded - so load it now.
        // We don't want to execute anything malicious in our process - so map it now as a read-only resource.
        hModule = LoadLibraryExW(filepath.c_str(), NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
        if (NULL == hModule) {
            LogDebug("LoadLibraryEx(%S, AS_IMAGE_RESOURCE) failed", filepath.c_str());
            return E_UNEXPECTED;
        }
        localBase = (DWORD64)hModule & ~0xFFFF;  // The lower bits of resource-only module handles are used as flags.

        // Being resource-only means that we can't use the usual APIs.
        // Instead, manually walk the UNWIND_INFO in the exception directory of the image.
        ULONG indexLo = 0;
        ULONG indexHi;
        auto pTable = (PRUNTIME_FUNCTION)ImageDirectoryEntryToData((PVOID)localBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &indexHi);
        if (!pTable) {
            (void)FreeLibrary(hModule);
            const auto error = GetLastError();
            if (ERROR_SUCCESS != error)
                LogError("ImageDirectoryEntryToData(%S) failed with %d", filepath.c_str(), error);
            else
                LogDebug("ImageDirectoryEntryToData(%S) - Exception Directory not found");
            return E_FAIL;
        }

        indexHi = indexHi / sizeof(RUNTIME_FUNCTION);
        while (indexHi > indexLo) {
            const ULONG indexMid = (indexLo + indexHi) / 2;
            pRuntimeFunction = &pTable[indexMid];
            if (rva < pRuntimeFunction->BeginAddress) {
                indexHi = indexMid;  // search lower
                pRuntimeFunction = NULL;
                continue;
            }
            if (rva >= pRuntimeFunction->EndAddress) {
                indexLo = indexMid + 1;  // search higher
                pRuntimeFunction = NULL;
                continue;
            }
            break;  // found
        }
    }

    if (!pRuntimeFunction) {
        (void)FreeLibrary(hModule);
        return E_FAIL;  // leaf functions can't call further functions
    }

    *pFrameSize = 0;
    auto status = CalculateFrameSize_Internal(pRuntimeFunction, localBase, rva, pFrameSize);
    if (S_OK == status)
        frameSizes.insert(std::make_pair(returnAddress, *pFrameSize));

    if (!FreeLibrary(hModule))
        LogError("FreeLibrary(%S) failed", filepath.c_str());

    return status;
}

BOOL IsValidCallSite(
    HANDLE hProcess,
    bool bIsWow64,
    const MEMORY_BASIC_INFORMATION& mbi,
    PVOID callsite,
    bool* bCallFound)
{
    // Check a cache of valid callsites first
    static std::unordered_set<PVOID> validCallSites;
    if (validCallSites.contains(callsite)) {
        *bCallFound = true;
        return TRUE;
    }

    // Otherwise read the preceding bytes and check for a valid call instruction
    std::string precedingBytes{};
    precedingBytes.resize(std::min(11ull, (ULONG_PTR)callsite - (ULONG_PTR)mbi.BaseAddress));
    if(!ReadProcessMemorySafely(hProcess, (PVOID)((ULONG_PTR)callsite - precedingBytes.size()), precedingBytes, mbi))
        return FALSE;

    ZydisDecoder decoder;
    if (bIsWow64)
        (void)ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    else
        (void)ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    *bCallFound = false;
    ZydisDecodedInstruction instruction;
    // call instructions are 2-11 bytes, but check some common lengths first
    static const std::array<int, 10> callLengthSearchOrder = { 5, 6, 7, 2, 3, 4, 8, 9, 10, 11 };
    for (const auto& lengthToCheck : callLengthSearchOrder) {
        if (lengthToCheck <= precedingBytes.size() &&
            ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr, precedingBytes.data() + precedingBytes.size() - lengthToCheck, lengthToCheck, &instruction)) &&
            lengthToCheck == instruction.length &&
            ZYDIS_MNEMONIC_CALL == instruction.mnemonic)
        {
            *bCallFound = true;
            // Note - For direct calls, we could (attempt to) improve this check by validating
            // that the call target matches the return address.
            // Though we would need to handle an Tail Call Optimised (TCO) functions...
            //
            // In practice this additional validation isn't required for our use case.
            // False positivies are rare in early stack frames.

            // Cache the result
            if (MEM_IMAGE == mbi.Type && InSystemImageRange(callsite))
                validCallSites.insert(callsite);
            break;
        }
    }

    return TRUE;
}