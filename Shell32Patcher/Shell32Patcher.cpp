#include <iostream>
#include <windows.h>
#include <Dbghelp.h>
#include <wtsapi32.h>
#include <psapi.h>
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Wtsapi32.lib")

#ifndef _CONSOLE
#define printf(...) {}
#endif

HMODULE GetModule(HANDLE hProcess, LPCWSTR target)
{
    DWORD cb, cbNeeded;
    WCHAR szModName[MAX_PATH];
    EnumProcessModulesEx(hProcess, NULL, 0, &cb, LIST_MODULES_64BIT);
    auto hMods = (HMODULE*)LocalAlloc(NONZEROLPTR, cb);
    if (!hMods) return NULL;
    EnumProcessModulesEx(hProcess, hMods, cb, &cbNeeded, LIST_MODULES_64BIT);
    if (cbNeeded < cb) cb = cbNeeded;

    HMODULE hMod = NULL;
    for (DWORD i = 0; i < cb / sizeof(HMODULE); i++) {
        if (!GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) continue;
        if (!lstrcmpiW(szModName, target)) {
            hMod = hMods[i];
            break;
        }
    }
    LocalFree(hMods);
    return hMod;
}

int main()
{
    auto hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_DEBUG | SYMOPT_UNDNAME);
    LPCWSTR symPath = NULL;
    GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = L"cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitializeW(hProcess, symPath, FALSE)) return -1;

    WCHAR szShell32[MAX_PATH];
    lstrcpyW(szShell32 + GetSystemDirectoryW(szShell32, sizeof(szShell32) / sizeof(WCHAR)), L"\\shell32.dll");
    if (!SymLoadModuleExW(hProcess, NULL, szShell32, NULL, 0, 0, NULL, 0)) return -2;

    SYMBOL_INFOW symbol;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol.MaxNameLen = 0;
    if (!SymFromNameW(hProcess, L"CDefView::TryGetContextMenuPresenter", &symbol)) return -3;
    printf("Found offset %llX\n", symbol.Address - symbol.ModBase);

    PWTS_PROCESS_INFOW processList;
    DWORD processCount = 0, pLevel = 0;
    if(!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &pLevel, WTS_CURRENT_SESSION, (LPWSTR *)&processList, &processCount))
    	return -4;

    for (DWORD i = 0; i < processCount; i++) {
        if (!lstrcmpiW(processList[i].pProcessName, L"explorer.exe")) {
            printf("Found explorer PID:%u\n", processList[i].ProcessId);
            auto hExplorer = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, TRUE, processList[i].ProcessId);
            if (!hExplorer) continue;

            auto hModShell32 = GetModule(hExplorer, szShell32);
            if (!hModShell32) continue;

            // and qword ptr [rdx], 0
            // and rax, 0
            // retn
            const char patched[] = "\x48\x83\x22\x00\x48\x83\xE0\x00\xC3\x90";
            size_t written = 0;
            WriteProcessMemory(hExplorer, (void*)((size_t)hModShell32 + symbol.Address - symbol.ModBase), patched, sizeof(patched) - 1, &written);
            printf("WriteProcessMemory() wrote %llu\n", written);
        }
    }
    return 0;
}
