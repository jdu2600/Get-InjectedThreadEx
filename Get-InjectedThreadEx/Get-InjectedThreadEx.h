#pragma once

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Zydis.lib")

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <dbghelp.h>
//#include <ehdata.h>
#include <processsnapshot.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// x86/x86-64 disassembler
// https://github.com/zyantific/zydis - MIT
#define ZYDIS_STATIC_BUILD
#include <Zydis/Zydis.h>

// https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
constexpr auto MAX_LONG_PATH = 0x7FFF;

////////////////////////////////////////////////////////////////////////////////////////////////////
// Logging
#define Log(_fmt_, ...) printf(_fmt_ "\n", ##__VA_ARGS__)
#define LogError(_fmt_, ...) fprintf(stderr, "[!] " _fmt_ "\n", ##__VA_ARGS__)
#if _DEBUG
#define LogDebug(_fmt_, ...) printf("[#] " _fmt_ "\n", ##__VA_ARGS__)
#else
#define LogDebug(...)
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////
// Native API
#define SE_DEBUG_PRIVILEGE (20L)
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((Status) >= 0)
extern "C" {
    NTSTATUS RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
// CfgBitMap.cpp
BOOL GetCfgBitsForAddress(PVOID address, PULONG pCfgBits);
BOOL IsValidXfgHash(UINT64 xfgHash);

////////////////////////////////////////////////////////////////////////////////////////////////////
// Memory.cpp
std::string ToHex(std::string bytes);
BOOL IsExecutable(const MEMORY_BASIC_INFORMATION& mbi);
BOOL InSystemImageRange(PVOID Address);
BOOL ReadProcessMemorySafely(HANDLE hProcess, PVOID address, PDWORD64 buffer);
BOOL ReadProcessMemorySafely(HANDLE hProcess, PVOID address, std::string& buffer);
BOOL ReadProcessMemorySafely(HANDLE hProcess, PVOID address, std::string& buffer, const MEMORY_BASIC_INFORMATION& mbi);
BOOL GetMappedFileNameAsDosPath(HANDLE hProcess, PVOID address, std::wstring& buffer);

////////////////////////////////////////////////////////////////////////////////////////////////////
// Process.cpp
BOOL IsElevated();
BOOL IsDotNet(HANDLE hProcess);

////////////////////////////////////////////////////////////////////////////////////////////////////
// StackClimb.cpp
constexpr auto MIN_FRAMES = 5;
BOOL StackClimb64(const HANDLE hProcess, const PVOID stackBuffer[], const size_t stackBufferCount, std::vector<std::string>& callStackFrames, bool* pbDetection, int offset = 0);

////////////////////////////////////////////////////////////////////////////////////////////////////
// Symbol.cpp
BOOL GetNearestSymbol(HANDLE hProcess, PVOID address, std::string& symbol, bool bIncludeDisplacement = false);
BOOL GetNearestSymbolWithPdb(HANDLE hProcess, PVOID address, std::string& symbol, bool bIncludeDisplacement = false);
PVOID GetSymbolAddress(const char symbol[]);

////////////////////////////////////////////////////////////////////////////////////////////////////
// Unwind.cpp
HRESULT CalculateFrameSize(PVOID returnAddress, PDWORD pFrameSize, const std::wstring& filepath, PVOID remoteBase);
BOOL IsValidCallSite(HANDLE hProcess, bool bIsWow64, const MEMORY_BASIC_INFORMATION& mbi, PVOID callsite, bool* bCallFound);

int main(int, char* []);
