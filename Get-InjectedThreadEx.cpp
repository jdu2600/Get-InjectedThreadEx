//    Get-InjectedThreadEx.cpp : A C++ implementation of Get-InjectedThreadEx.ps1
//
//    .SYNOPSIS 
//    
//    Looks for threads that were created as a result of code injection.
//    
//    .DESCRIPTION
//    
//    Memory resident malware (fileless malware) often uses a form of memory injection to get code execution.
//    Get-InjectedThreadEx looks at each running thread to determine if it is the result of memory injection.
// 
//    Win32StartAddress
//
//    original
//     - not MEM_IMAGE
//    new
//     - MEM_IMAGE and Win32StartAddress is on a private (modified) page
//     - MEM_IMAGE and x64 dll and Win32StartAddress is CFG violation or suppressed export
//     - MEM_IMAGE and Win32StartAddress is in a suspicious module
//     - MEM_IMAGE and x64 and Win32StartAddress is unexpected prolog
//     - MEM_IMAGE and Win32StartAddress is preceded by unexpected bytes
//     - MEM_IMAGE and x64 and Win32StartAddress wraps non-MEM_IMAGE start address
//    
//    KNOWN LIMITATIONS:
//    - Only detects suspicious thread creations - not hijacks of existing threads.
//    - Some WoW64 support not implemented.

#include "Get-InjectedThreadEx/Get-InjectedThreadEx.h"

BOOL ScanThread(HANDLE hProcess, BOOL bIsDotNet, PSS_THREAD_ENTRY& thread, std::string& symbol, std::vector<std::string>& detections) {
    if (thread.Flags & PSS_THREAD_FLAGS_TERMINATED)
        return FALSE;

    if (!GetNearestSymbol(hProcess, thread.Win32StartAddress, symbol, true))
        return FALSE;

    if (thread.ContextRecord && thread.ContextRecord->Dr6)
        detections.push_back("hw_breakpoint");

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(hProcess, thread.Win32StartAddress, &mbi, sizeof(mbi)))
        return FALSE;

    if (MEM_IMAGE != mbi.Type && MEM_COMMIT == mbi.State) {
        detections.push_back("PRIVATE");
        return TRUE;
    }

    // Has our MEM_IMAGE Win32StartAddress been (naively) hooked?
    // https://blog.redbluepurple.io/offensive-research/bypassing-injection-detection//creating-the-thread
    // Note - checking against bytes on disk after the fact won't help with false positives
    // as the hook can easily be removed after thread start.
    // Detection gap - the hook could easily be deeper, potentially even in a subsequent call. :-(
    // Microsoft-Windows-Threat-Intelligence ETW events should detect this more robustly.
    PSAPI_WORKING_SET_EX_INFORMATION pwsei{};
    pwsei.VirtualAddress = thread.Win32StartAddress;
    if (K32QueryWorkingSetEx(hProcess, &pwsei, sizeof(pwsei)) && !pwsei.VirtualAttributes.Shared) {
        // I'm slightly worried about security vendor hooks landing on the same page
        // as ntdll!TppWorkerThread and causing a false positive flood.
        // So ignore ntdll modifications if we've been hooked too.
        static bool s_edrFalsePositive = symbol.starts_with("ntdll.dll!") &&
            K32QueryWorkingSetEx(GetCurrentProcess(), &pwsei, sizeof(pwsei)) && !pwsei.VirtualAttributes.Shared;
        if(!s_edrFalsePositive)
            detections.push_back("private_image");
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Check for suspcious CFG BitMap states in our local pristine copy of the x64 bitmap
    // Notes - executable CFG bitmaps are not shared - only library (dll) ones.
    //       - only 16-bytes aligned addresses, as this is a SetProcessValidCallTargets() requirement.
    ULONG cfgBits;
    if (InSystemImageRange(thread.Win32StartAddress) && 0 == ((ULONG_PTR)thread.Win32StartAddress & 0xF) &&
        GetCfgBitsForAddress(thread.Win32StartAddress, &cfgBits) && 0 == cfgBits)
    {
        detections.push_back("cfg_invalid");
    }


    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Suspicious start modules

    std::wstring mappedPath;
    // The file path assocated with Win32StartAddressModule
    if (!GetMappedFileNameAsDosPath(hProcess, thread.Win32StartAddress, mappedPath))
        return FALSE;

    // There are no valid thread entry points (that I know of) in many Win32 modules.
    const std::array<std::string, 11> modulesWithoutThreadEntrypoints = {
        "kernel32", "kernelbase", "user32", "advapi32",
        "psapi", "dbghelp", "imagehlp", "powrprof",
        "verifier", "setupapi", "rpcrt4" }; // ...and many more
    const auto startModule = std::filesystem::path(mappedPath).stem().string();
    for (const auto& module : modulesWithoutThreadEntrypoints)
        if (startModule == module) {
            (void)GetNearestSymbolWithPdb(hProcess, thread.Win32StartAddress, symbol);
            detections.push_back("unexpected(" + startModule + ")");
        }

    // kernel32!LoadLibrary
    // And, even if there are, LoadLibrary is always a suspicious start address.
    static auto hKernel32 = GetModuleHandleW(L"kernel32.dll");
    static auto pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    static auto pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA == thread.Win32StartAddress || pLoadLibraryW == thread.Win32StartAddress)
        detections.push_back("unexpected(" + symbol + ")");

    // ntdll.dll but not a known entrypoint.
    // These are the only valid thread entry points in ntdll that I know of.   
    static const std::array<PVOID, 4> ntdllThreadEntryPoints = {
        GetSymbolAddress("ntdll!TppWorkerThread"),
        GetSymbolAddress("ntdll!EtwpLogger"),
        GetSymbolAddress("ntdll!DbgUiRemoteBreakin"),
        GetSymbolAddress("ntdll!RtlpQueryProcessDebugInformationRemote")
    };

    if (mappedPath.ends_with(L"\\System32\\ntdll.dll")) {
        auto bValidNtdllEntry = false;
        for (const auto& address : ntdllThreadEntryPoints)
            bValidNtdllEntry |= address == thread.Win32StartAddress;

        if (!bValidNtdllEntry) {
            detections.push_back("unexpected(" + symbol + ")");
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Common setup for the disassembler
    constexpr auto MAX_INSN_LENGTH = 11ull;  // theoretically 15, but empirically lower
    ZydisDecoder decoder;
    ZydisDecodedInstruction instruction;
    // WoW64 can be inferred from the TEB address.
    const bool bIsWow64 = (ULONG_PTR)thread.TebBaseAddress < 0x80000000;
    if (bIsWow64)
        (void)ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    else
        (void)ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Check the bytes immmediately after Win32StartAddress
    // They must be a function entrypoint.
    // ... but almost anything is a valid entrypoint!
    // x64 prologs have more structure (albiet mostly by convention) - so we'll stick to those.
    // See https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog
    // 
    // Note - the loader ignores AddressOfEntry in CLR assemblies so we need to ignore them too.
    auto bIsDotNetProcessEntrypoint = bIsDotNet && mappedPath.ends_with(L".exe");

    if (!bIsWow64 && !bIsDotNetProcessEntrypoint) {
        std::string startBytes;
        constexpr auto MAX_PROLOG_SIZE = 64;
        startBytes.resize(MAX_PROLOG_SIZE);
        if (!ReadProcessMemorySafely(hProcess, thread.Win32StartAddress, startBytes, mbi))
            return FALSE;

        auto i = 0;
        bool bValidInstruction = true;
        ZyanU64 instructionPointer = (ZyanU64)thread.Win32StartAddress;  // track this to calculate relative targets
        auto framePointer = ZYDIS_REGISTER_RSP;
        ZydisDecoderContext ctx{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisRegisterContext registers{};
        std::string originalBytes; // if we follow a jump keep original bytes

        const auto IsStackOperation = [&]() -> bool {
            return ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT)) &&
                ZYDIS_OPERAND_TYPE_REGISTER == operands[0].type && ZYDIS_REGISTER_RSP == operands[0].reg.value;

        };

        const auto IsSaveRegisterOperation = [&]() -> bool {
            return ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT)) &&
                ZYDIS_OPERAND_TYPE_MEMORY == operands[0].type && (ZYDIS_REGISTER_RSP == operands[0].mem.base || framePointer == operands[0].mem.base) &&
                ZYDIS_OPERAND_TYPE_REGISTER == operands[1].type;
        };

        const auto IsFramePointerOperation = [&]() {
            const auto bIsFP = ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT)) &&
                ZYDIS_OPERAND_TYPE_REGISTER == operands[0].type &&
                ((ZYDIS_OPERAND_TYPE_REGISTER == operands[1].type && (ZYDIS_REGISTER_RSP == operands[1].reg.value || framePointer == operands[1].reg.value)) ||
                    (ZYDIS_OPERAND_TYPE_MEMORY == operands[1].type && (ZYDIS_REGISTER_RSP == operands[1].mem.base || framePointer == operands[1].mem.base)));
            if (bIsFP)
                framePointer = operands[0].reg.value;
            return bIsFP;
        };

        const auto IsRegDestination = [&](ZydisRegister reg) -> bool {
            return ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT)) &&
                ZYDIS_OPERAND_TYPE_REGISTER == operands[0].type && reg == operands[0].reg.value;
        };

        const auto IsRegSource = [&](ZydisRegister reg) -> bool {
            return ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT)) &&
                ((ZYDIS_OPERAND_TYPE_REGISTER == operands[1].type && reg == operands[1].reg.value) ||
                    (ZYDIS_OPERAND_TYPE_MEMORY == operands[1].type && reg == operands[1].mem.base));
        };

        const auto SaveRegister = [&](ZydisRegister reg) -> void {
            ZyanU64 regValue = 0;
            registers.values[reg] = 0;
            // Note - assumes prior call to IsRegDestination
            if (ZYDIS_OPERAND_TYPE_REGISTER == operands[0].type && reg == operands[0].reg.value &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[1], instructionPointer, &regValue)))
            {
                registers.values[reg] = regValue;
            }
        };

        bool bThreadParameterInRax = false;
        bool bCallThreadParameter = false;
        bool bRaxSetLastInstruction = false;
        int nFollowedJumps = 0;
        constexpr auto MAX_JUMPS = 3;
        const auto FollowJump = [&]() -> bool {
            ZyanU64 jmpTarget = 0;
            if (nFollowedJumps < MAX_JUMPS &&
                ZYAN_SUCCESS(ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT)) &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&instruction, &operands[0], instructionPointer, &registers, &jmpTarget)) &&
                0 != jmpTarget)
            {
                // If the jump target isn't an immediate then we need to read it from the calculated address.
                if ((ZYDIS_OPERAND_TYPE_MEMORY == operands[0].type && ZYDIS_REGISTER_RIP == operands[0].mem.base))
                {
                    // If RCX has been mixed into RAX then we can't follow the jump.
                    // Such start addresses are useful proxy call functions for adversaries.
                    if (bRaxSetLastInstruction && bThreadParameterInRax) {
                        bCallThreadParameter = true;
                        return FALSE;
                    }

                    // This looks like a CFG check.
                    // mov RAX, indirect-call
                    // jmp __guard_dispatch_icall_fptr
                    // The CFG thunk will transfer execution to RAX on success - so just jump to RAX now.
                    if (bRaxSetLastInstruction && InSystemImageRange((PVOID)jmpTarget))
                        jmpTarget = registers.values[ZYDIS_REGISTER_RAX];

                    // Read the jump target
                    if (!ReadProcessMemorySafely(hProcess, (PVOID)jmpTarget, &jmpTarget))
                        return FALSE;
                }

                std::string jmpBytes = std::move(startBytes);
                startBytes.resize(MAX_PROLOG_SIZE);
                if (ReadProcessMemorySafely(hProcess, (PVOID)jmpTarget, startBytes)) {

                    jmpBytes.resize(i + instruction.length);
                    originalBytes += ToHex(jmpBytes) + "|";

                    // reset loop for new bytes
                    instructionPointer = jmpTarget;
                    instruction.length = 0;
                    i = 0;
                    return TRUE;
                }
                startBytes = std::move(originalBytes);
            }
            return FALSE;
        };

        bool bPrologStarted = false;
        bool bPrologFinished = false;
        bool bRaxSet = false;
        bool bTestRcx = false;
        for (i = 0; bValidInstruction && !bPrologFinished && i <= startBytes.size() - MAX_INSN_LENGTH; i += instruction.length) {
            bValidInstruction = ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &ctx, startBytes.data() + i, startBytes.length() - i, &instruction));
            bRaxSetLastInstruction = bRaxSet;
            bRaxSet = false;
            switch (instruction.mnemonic) {
            case ZYDIS_MNEMONIC_PUSH:
                // push nonvolatile
                bPrologStarted = true;
                break;
            case ZYDIS_MNEMONIC_MOV:
                // mov [RSP+n], nonvolatile
                if (IsSaveRegisterOperation())
                    bPrologStarted = true;
                // mov frame-pointer, RSP
                else if (IsFramePointerOperation())
                    bPrologStarted = true;
                // mov RAX, fixed-allocation-size                
                // mov RAX, indirect-call-target
                else if (IsRegDestination(ZYDIS_REGISTER_RAX)) {
                    SaveRegister(ZYDIS_REGISTER_RAX);
                    bRaxSet = true;
                    bThreadParameterInRax |= IsRegSource(ZYDIS_REGISTER_RCX);
                }
                else if (IsRegDestination(ZYDIS_REGISTER_EAX))
                    bRaxSet = true;
                // sometimes stub functions reorder parameters or set static values
                // mov FastcallParamReg, *
                else
                    bValidInstruction = IsRegDestination(ZYDIS_REGISTER_RCX) || IsRegDestination(ZYDIS_REGISTER_RDX) || IsRegDestination(ZYDIS_REGISTER_R8) || IsRegDestination(ZYDIS_REGISTER_R9);
                break;
            case ZYDIS_MNEMONIC_CALL:
                // call __chkstk() is the only call allowed in a prolog
                // It uses a special calling convention.
                bValidInstruction = bRaxSetLastInstruction;
                break;
            case ZYDIS_MNEMONIC_LEA:
                // lea frame-pointer, [RSP-n]
                if (IsFramePointerOperation())
                    bValidInstruction = true;
                // lea RAX,[RIP+n]
                else if (IsRegDestination(ZYDIS_REGISTER_RAX)) {
                    SaveRegister(ZYDIS_REGISTER_RAX);
                    bRaxSet = true;
                }
                // Some "functions" are just stubs around other functions with
                // one (or more) fixed parameters.
                // lea RCX, [n] - set first parameter.
                else
                    bValidInstruction = IsRegDestination(ZYDIS_REGISTER_RCX);
                break;
            case ZYDIS_MNEMONIC_SUB:  // prolog delimiter
                bPrologFinished = IsStackOperation();
                break;
            case ZYDIS_MNEMONIC_TEST:
                // test RCX, RCX - is the first parameter NULL?
                // Checking for a non-NULL parameter and bailing early is
                // a common optimisation.
                bTestRcx = IsRegSource(ZYDIS_REGISTER_RCX) && IsRegDestination(ZYDIS_REGISTER_RCX);
                break;
            case ZYDIS_MNEMONIC_JZ:
                // test RCX, RCX
                // jz early-exit - don't follow
                bValidInstruction = bTestRcx;
                break;
            case ZYDIS_MNEMONIC_JNZ:
                // test RCX, RCX
                // jnz true-entry-point - follow
                bValidInstruction = bTestRcx;
                if (!FollowJump())
                    bPrologFinished = bTestRcx;
                break;
            case ZYDIS_MNEMONIC_JMP:
                // Some functions start with a short jmp to provide hotpatch space.
                // jmp n - follow
                bPrologFinished = FollowJump();
                break;
            default:
                bValidInstruction = false;
            }
            instructionPointer += instruction.length;
        }
        startBytes.resize(i);
        if (bCallThreadParameter)
            detections.push_back(std::string("proxy_call(" + originalBytes + ToHex(startBytes) + ")"));
        else if (!bPrologFinished)
            detections.push_back(std::string("prolog(" + originalBytes + ToHex(startBytes) + ")"));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Check the bytes immmediately before Win32StartAddress
    // The byte preceding a function prolog is typically a return, or filler byte.
    // False positives can occur if data was included in a code section. This was
    // common in older compilers...
    std::string tailBytes;
    tailBytes.resize(std::min(MAX_INSN_LENGTH, (ULONG_PTR)thread.Win32StartAddress - (ULONG_PTR)mbi.AllocationBase));
    if (!ReadProcessMemorySafely(hProcess, (PVOID)((ULONG_PTR)thread.Win32StartAddress - tailBytes.size()), tailBytes))
        return FALSE;


    // False positives can occur if data was included in a code section. This was common in older compilers...
    // ...and also in new compilers that support XFG. In this case, the 8-byte XFG hash is immediately before.
    // https://blog.quarkslab.com/how-the-msvc-compiler-generates-xfg-function-prototype-hashes.html
    const auto& tailbytesEnd = tailBytes.data() + tailBytes.size();
    auto bIsValidTail = tailBytes.size() >= sizeof(UINT64) && 
        IsValidXfgHash(*(UINT64*)(tailbytesEnd - sizeof(UINT64)));

    // The byte preceding a function prolog is typically a return, or filler byte.
    bIsValidTail |= tailBytes.empty() || '\x00' == tailBytes.back(); // NUL filled.
    for (auto i = 1; !bIsValidTail && i <= tailBytes.size(); i++) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, NULL, tailbytesEnd - i, i, &instruction)) || instruction.length != i)
            continue;
        switch (instruction.mnemonic) {
            // valid basic block end instructions
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_RET:
            // valid alignment filler instructions
        case ZYDIS_MNEMONIC_NOP:
        case ZYDIS_MNEMONIC_INT3:
            bIsValidTail = true;;
        }
    }

    if (!bIsValidTail)
        detections.push_back(std::string("tail(" + ToHex(tailBytes) + ")"));

    //////////////////////////////////////////////////////////////////////////////////////////////////
    // Check for suspicious call stacks
    // [expected] ntdll!RtlUserThreadStart -> kernel32!BaseThreadInitThunk -> Win32StartAddress
    // https://www.trustedsec.com/blog/avoiding-get-injectedthread-for-internal-thread-creation/
    //

    if (bIsWow64)
        return TRUE;  // TODO(jdu) Implement x86 stack climbing?

    // The TIB is the first element of the TEB. Read the TIB to determine the stack limits.
    NT_TIB64 tib;
    if (!ReadProcessMemory(hProcess, thread.TebBaseAddress, &tib, sizeof(tib), NULL))
        return FALSE;

    // Determine the consumed stack size (and check for stack pivoting such as ROP).
    const auto stackPointer = thread.ContextRecord ? thread.ContextRecord->Rsp : tib.StackLimit;
    if (stackPointer > tib.StackBase || stackPointer < tib.StackLimit) {
        detections.push_back("stack_pivot");
        return TRUE;
    }

    // Read the (partial) base of stack contents - 1.5 pages seems sufficient given current stack randomisation
    PVOID stackBuffer[0x1800 / sizeof(PVOID)];
    const auto stackReadLength = std::min(sizeof(stackBuffer), (tib.StackBase - stackPointer) & ~0xF);
    if (!ReadProcessMemory(hProcess, (PVOID)(tib.StackBase - stackReadLength), stackBuffer, stackReadLength, NULL))
        return FALSE;


    // Search the stack bottom up for the (probable) initial return addresses of the first 3+2 frames.
    // Note - x64 stack frames are 16-byte aligned.
    std::vector<std::string> callStackFrames;
    bool bCallStackDetection = false;
    const auto stackBufferCount = stackReadLength / sizeof(PVOID);
    if (!StackClimb64(hProcess, stackBuffer, stackBufferCount, callStackFrames, &bCallStackDetection))
        return FALSE;

    // If the thread has been hijacked, then the return address alignment might be off.
    // Search the skipped offsets this time.
    if(0 == callStackFrames.size() && !StackClimb64(hProcess, stackBuffer, stackBufferCount, callStackFrames, &bCallStackDetection, 1))
        return FALSE;

    // Not enough stack frames discovered yet - append RIP
    if (!bCallStackDetection && thread.ContextRecord && callStackFrames.size() < MIN_FRAMES) {

        if (!VirtualQueryEx(hProcess, (PVOID)thread.ContextRecord->Rip, &mbi, sizeof(mbi)))
            return FALSE;

        if (!IsExecutable(mbi))
            LogError("pid:%d, tid:%d RIP:%llx is not executable", thread.ProcessId, thread.ThreadId, thread.ContextRecord->Rip);

        if (MEM_IMAGE != mbi.Type) {
            callStackFrames.push_back("PRIVATE");
            bCallStackDetection = true;
        }
    }

    std::string callStackSummary;
    callStackSummary.reserve(callStackFrames.size() * 16);
    for (const auto& entry : callStackFrames) {
        if (entry == "ntdll.dll!RtlUserThreadStart" || entry == "kernel32.dll!BaseThreadInitThunk")
            continue; // skip common frames
        if (!callStackSummary.empty())
            callStackSummary += "|";
        callStackSummary += entry.substr(0, entry.find_first_of('<')); // trim type information
    }

    if (bCallStackDetection)
        if(callStackFrames.size() < 4)
            detections.push_back("spoof(" + callStackSummary + ")");
        else
            detections.push_back("wrapper(" + callStackSummary + ")");

    return TRUE;
}

struct FalsePositive {
    const std::wstring ProcessName;
    const std::string Symbol;
    const size_t Count;
};

BOOL IsKnownFalsePositive(const HANDLE hProcess, const PROCESSENTRY32 &processEntry, const PSS_THREAD_ENTRY thread, std::string &symbol, const std::vector<std::string> &detections) {

    static const std::array<FalsePositive, 2> falsePositives = { {
        { L"dwm.exe", "dwmcore.dll!CMit::RunInputThreadStatic", 1 },
        { L"vctip.exe", "vctip.exe!CorExeMain", 1 }
    } };

    (void)GetNearestSymbolWithPdb(hProcess, thread.Win32StartAddress, symbol);

    BOOL bIsFalsePositive = FALSE;
    for (const auto &fp : falsePositives)
        bIsFalsePositive |= processEntry.szExeFile == fp.ProcessName && symbol == fp.Symbol && detections.size() == fp.Count;

    return bIsFalsePositive;
}

int main(int, char* []) {
    if (!IsElevated())
        LogError("WARNING Not running as Administrator");
    
    BOOLEAN _;
    if(!NT_SUCCESS(RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &_)))
        LogError("WARNING RtlAdjustPrivilege(DEBUG) failed");

    const auto tsScanStarted = GetTickCount64();
    UINT32 nProcessesTotal = 0;
    UINT32 nProcessesScanned = 0;
    UINT32 nThreadsScanned = 0;

    ////////////////////////////////////////////////////////////////////////////////
    // Scan each process
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
        LogError("CreateToolhelp32Snapshot(PROCESS) failed. LastError:%d", GetLastError());
        return 0;
    }

    PROCESSENTRY32 processEntry{};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnapshot, &processEntry)) {
        LogError("Process32First failed. LastError:%d", GetLastError());
        return 0;
    }

    do {
        if (processEntry.th32ProcessID <= 4)
            continue;  // skip Idle and System

        nProcessesTotal++;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
        if (NULL == hProcess)
            continue;  // skip process - Access is Denied, or process stopped

        auto bIsDotNet = IsDotNet(hProcess);

        //////////////////////////////////////////////////////////////////////////////////////////
        // Scan all threads in the process
        HPSS hThreadSnapshot = NULL;
        HPSSWALK hWalk = NULL;
        const auto captureFlags = PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT;
        const auto contextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        if (S_OK == PssCaptureSnapshot(hProcess, captureFlags, contextFlags, &hThreadSnapshot) && S_OK == PssWalkMarkerCreate(NULL, &hWalk)) {
            nProcessesScanned++;
            PSS_THREAD_ENTRY thread;
            while (S_OK == PssWalkSnapshot(hThreadSnapshot, PSS_WALK_THREADS, hWalk, &thread, sizeof(thread))) {
                std::string symbol;
                std::vector<std::string> detections;
                (void)ScanThread(hProcess, bIsDotNet, thread, symbol, detections);
                nThreadsScanned++;

                if (detections.size() > 0 && !IsKnownFalsePositive(hProcess, processEntry, thread, symbol, detections)) {
                    (void)GetNearestSymbolWithPdb(hProcess, thread.Win32StartAddress, symbol, true);
                    Log("ProcessName       : %S", processEntry.szExeFile);
                    Log("pid:tid           : %d:%d", thread.ProcessId, thread.ThreadId);
                    Log("Win32StartAddress : %s", symbol.c_str());
                    Log("Detections        :");
                    for (const auto& detection : detections)
                        Log(" - %s", detection.c_str());
                    Log("");
                }
            }
        }

        if (NULL != hProcess)
            (void)CloseHandle(hProcess);
        if (NULL != hThreadSnapshot)
            (void)PssFreeSnapshot(GetCurrentProcess(), hThreadSnapshot);
        if (NULL != hWalk)
            (void)PssWalkMarkerFree(hWalk);
    } while (Process32Next(hProcessSnapshot, &processEntry));

    if (INVALID_HANDLE_VALUE != hProcessSnapshot)
        (void)CloseHandle(hProcessSnapshot);

    Log("Scanned %d threads in %d (of %d) processes in %.2f seconds", nThreadsScanned, nProcessesScanned, nProcessesTotal, (GetTickCount64() - tsScanStarted) / 1000.0);

    return 0;
}
