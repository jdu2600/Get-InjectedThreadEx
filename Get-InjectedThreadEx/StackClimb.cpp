#include "Get-InjectedThreadEx.h"


void SymboliseCallStack(HANDLE hProcess, const std::vector<PVOID> returnAddresses, const std::string last, std::vector<std::string> &callStackFrames) {
    for (const auto address : returnAddresses) {
        std::string frameSymbol;
        if (!GetNearestSymbolWithPdb(hProcess, address, frameSymbol))
            frameSymbol = "<ERROR>";
        callStackFrames.push_back(frameSymbol);
    }
    callStackFrames.push_back(last);
}

BOOL StackClimb64(const HANDLE hProcess,
    const PVOID stackBuffer[],
    const size_t stackBufferCount,
    std::vector<std::string>& callStackFrames,
    bool* pbDetection,
    int offset)
{
    std::vector<PVOID> returnAddresses;

    // Query SystemInfo for the usermode address bounds
    static SYSTEM_INFO s_si{};
    if (!s_si.lpMaximumApplicationAddress) {
        GetSystemInfo(&s_si);
        if (0 == s_si.lpMaximumApplicationAddress) {
            LogError("GetSystemInfo() failed");
            return FALSE;
        }

        // Note - My code makes some assumptions about page and allocation sizes.
        if (0x1000 != s_si.dwPageSize || 0x10000 != s_si.dwAllocationGranularity) {
            LogError("System not supported. PageSize=0x%x AllocationGranularity=0x%x", s_si.dwPageSize, s_si.dwAllocationGranularity);
            return FALSE;
        }
    }

    auto lastRspOffset = 0u;
    const auto StackBufferLast = &stackBuffer[stackBufferCount - 1];
    for (auto i = offset; !*pbDetection && (i < stackBufferCount) && (returnAddresses.size() < MIN_FRAMES); i += 2) {
        const PVOID candidateRip = StackBufferLast[-i];

        // Skip any invalid usermode addresses
        if (candidateRip < s_si.lpMinimumApplicationAddress || candidateRip >= s_si.lpMaximumApplicationAddress)
            continue;

        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProcess, candidateRip, &mbi, sizeof(mbi)))
            return FALSE;

        // Return address must be executable
        if (!IsExecutable(mbi))
            continue;

        // We can't read this executable page due to the Guard - so just alert.
        if (0 != (mbi.State & PAGE_GUARD)) {
            SymboliseCallStack(hProcess, returnAddresses, "GUARD", callStackFrames);
            *pbDetection = true;
            return TRUE;
        }

        bool bValidCallsite;
        if (MEM_IMAGE != mbi.Type) {
            if (IsValidCallSite(hProcess, false, mbi, candidateRip, &bValidCallsite) && bValidCallsite) {
                // A suspicious frame was found!
                SymboliseCallStack(hProcess, returnAddresses, "PRIVATE", callStackFrames);
                *pbDetection = true;
                return TRUE;
            }
            continue; // Not a return address - keep searching
        }

        std::wstring candidateRipMappedPath;
        if (!GetMappedFileNameAsDosPath(hProcess, candidateRip, candidateRipMappedPath))
            return FALSE;

        DWORD frameSize = 0;
        if (0 != lastRspOffset) {
            auto status = CalculateFrameSize(candidateRip, &frameSize, candidateRipMappedPath, mbi.AllocationBase);
            if (S_OK == status && (i - lastRspOffset) != frameSize)
                continue; // Invalid frame size - keep searching

            if (IS_ERROR(status))  // but not WARNINGs
                continue;

            // We could not calculate exact frame size - but do have a lowerbound.
            // TODO(jdu) We could scan ahead one (or more) frames here to see if we recover?
            if (S_OK != status && (i - lastRspOffset) < frameSize)
                continue; // Frame too small - keep searching     
        }

        if (!IsValidCallSite(hProcess, false, mbi, candidateRip, &bValidCallsite) && !bValidCallsite)
            continue; // Not a return address - keep searching

        auto status = CalculateFrameSize(candidateRip, &frameSize, candidateRipMappedPath, mbi.AllocationBase);
        // LogDebug("     %03i: %p %s valid=%d frameSize=%d FP=%d", i, candidateRip, frameSymbol.c_str(), bValidCallsite, frameSize, S_OK != status);
        returnAddresses.push_back(candidateRip);

        lastRspOffset = i;

        // Frames must be at least 0x20 bytes due to fastcall parameter shadow space
        i += 4;
    }

    // Just use exports if nothing suspicious was found
    // TODO(jdu) We only need to return this at all so that we know if a 2nd pass is required.
    // Perhaps move 2nd pass and RIP logic here.
    if (callStackFrames.empty()) {
        for (const auto address : returnAddresses) {
            std::string frameSymbol;
            (void)GetNearestSymbol(hProcess, address, frameSymbol);
            callStackFrames.push_back(frameSymbol);
        }
    }

    return TRUE;
}