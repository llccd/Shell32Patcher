#include <iostream>
#include <windows.h>
#include <Dbghelp.h>
#include <wtsapi32.h>
#include <psapi.h>

#ifndef _CONSOLE
#define printf(...) {}
#endif

int main()
{
    HANDLE hProcess = GetCurrentProcess();
    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_DEBUG | SYMOPT_UNDNAME);
    const char* symPath = NULL;
    GetEnvironmentVariableA("_NT_SYMBOL_PATH", NULL, 0);
    if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) symPath = "cache*;srv*https://msdl.microsoft.com/download/symbols";
    if (!SymInitialize(hProcess, symPath, FALSE)) return -1;

    WCHAR szShell32[MAX_PATH];
    lstrcpyW(szShell32 + GetSystemDirectoryW(szShell32, sizeof(szShell32) / sizeof(WCHAR)), L"\\shell32.dll");
    if (!SymLoadModuleExW(hProcess, NULL, szShell32, NULL, 0, 0, NULL, 0)) return -2;

    SYMBOL_INFO symbol;
    symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol.MaxNameLen = 0;
    if (!SymFromName(hProcess, "CDefView::TryGetContextMenuPresenter", &symbol)) return -3;
    printf("Found offset %llX\n", symbol.Address - symbol.ModBase);

    PWTS_PROCESS_INFOW processList;
    DWORD processCount = 0, pLevel = 0;
    WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &pLevel, WTS_CURRENT_SESSION, (LPWSTR *)&processList, &processCount);

    for (DWORD i = 0; i < processCount; i++) {
        if (!lstrcmpiW(processList[i].pProcessName, L"explorer.exe")) {
            printf("Found explorer PID:%u\n", processList[i].ProcessId);
            HANDLE hExplorer = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, TRUE, processList[i].ProcessId);
            if (!hExplorer) continue;

            DWORD cb, cbNeeded;
            WCHAR szModName[MAX_PATH];
            EnumProcessModulesEx(hExplorer, NULL, 0, &cb, LIST_MODULES_64BIT);
            auto hMods = (HMODULE *)LocalAlloc(NONZEROLPTR, cb);
            if (!hMods) continue;
            EnumProcessModulesEx(hExplorer, hMods, cb, &cbNeeded, LIST_MODULES_64BIT);
            if (cbNeeded < cb) cb = cbNeeded;

            HANDLE hModShell32 = INVALID_HANDLE_VALUE;
            for (DWORD i = 0; i < cb / sizeof(HMODULE); i++) {
                if (!GetModuleFileNameExW(hExplorer, hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) continue;
                if (!lstrcmpiW(szModName, szShell32)) {
                    hModShell32 = hMods[i];
                    break;
                }
            }
            LocalFree(hMods);
            if (hModShell32 == INVALID_HANDLE_VALUE) continue;

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
