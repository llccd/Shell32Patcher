#include <iostream>
#include "ntdll.h"
#include <Zydis/Zydis.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <psapi.h>

#ifndef _CONSOLE
#define printf(...) {}
#define EXIT(msg, x) {ExitProcess(x);}
#else
#define EXIT(msg, x) {puts(msg); return x;}
#endif

static HANDLE heap = 0;

static WCHAR szShell32[MAX_PATH];

// xor rdi, rdi
// nop
static const char patchData[] = "\x48\x31\xFF\x0F\x18\x24\x00";

constexpr const char guid[] = "\xB1\xC5\x06\xB3\xF2\xB4\x3C\x47\xB6\xFF\x70\x1B\x24\x6C\xE2\xD2";

PIMAGE_SECTION_HEADER findSection(PIMAGE_NT_HEADERS64 pNT, const char* str)
{
	auto pSection = IMAGE_FIRST_SECTION(pNT);

	for (DWORD64 i = 0; i < pNT->FileHeader.NumberOfSections; i++)
		if (CSTR_EQUAL == CompareStringA(LOCALE_INVARIANT, 0, (char*)pSection[i].Name, -1, str, -1))
			return pSection + i;

	return NULL;
}

DWORD64 pattenMatch(DWORD64 base, PIMAGE_SECTION_HEADER pSection, const void* str, DWORD64 size)
{
	auto rdata = base + pSection->VirtualAddress;

	for (DWORD64 i = 0; i < pSection->SizeOfRawData; i += 4)
		if (!memcmp((void*)(rdata + i), str, size)) return pSection->VirtualAddress + i;

	return -1;
}

DWORD64 searchXref(ZydisDecoder* decoder, DWORD64 base, PRUNTIME_FUNCTION func, DWORD64 target)
{
	auto IP = base + func->BeginAddress;
	auto length = (ZyanUSize)func->EndAddress - func->BeginAddress;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

	while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, (void*)IP, length, &instruction, operands)))
	{
		IP += instruction.length;
		length -= instruction.length;
		if (instruction.operand_count == 2 &&
			instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			operands[1].mem.base == ZYDIS_REGISTER_RIP &&
			operands[1].mem.disp.value + IP == target + base &&
			operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
			return IP - base;
	}

	return 0;
}

HMODULE GetModule(HANDLE hProcess, LPCWSTR target)
{
	DWORD cb, cbNeeded;
	WCHAR szModName[MAX_PATH];
	EnumProcessModulesEx(hProcess, NULL, 0, &cb, LIST_MODULES_64BIT);
	if (GetLastError() != ERROR_ACCESS_DENIED) return NULL;
	auto hMods = (HMODULE*)HeapAlloc(heap, 0, cb);
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
	HeapFree(heap, 0, hMods);
	return hMod;
}

LPVOID get_token_info(HANDLE token, const TOKEN_INFORMATION_CLASS& type)
{
	DWORD length;
	void* buf = NULL;
	GetTokenInformation(token, type, NULL, 0, &length);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		buf = (void*)HeapAlloc(heap, 0, length);
		GetTokenInformation(token, type, buf, length, &length);
	}
	return buf;
}

void enable_all_privileges(HANDLE token)
{
	auto privileges = (PTOKEN_PRIVILEGES)get_token_info(token, TokenPrivileges);
	if (privileges)
	{
		for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
			privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(token, false, privileges, 0, NULL, NULL);
		HeapFree(heap, 0, privileges);
	}
}

BOOL get_token_pid(const DWORD& ProcessId, PHANDLE TokenHandle)
{
	auto process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (GetLastError() == ERROR_ACCESS_DENIED) process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
	if (!process) return false;

	const auto ret = OpenProcessToken(process, MAXIMUM_ALLOWED, TokenHandle);

	CloseHandle(process);
	return ret;
}

DWORD get_lsass_pid()
{
	const auto scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scm) return -1;

	const auto service = OpenServiceW(scm, L"SamSs", SERVICE_QUERY_STATUS);
	if (!service)
	{
		CloseServiceHandle(scm);
		return -1;
	}

	SERVICE_STATUS_PROCESS status;
	DWORD bytes_needed = sizeof(status);
	DWORD pid = -1;
	if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytes_needed))
		if (SERVICE_STOPPED != status.dwCurrentState) pid = status.dwProcessId;

	CloseServiceHandle(service);
	CloseServiceHandle(scm);
	return pid;
}

HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname)
{
	UNICODE_STRING name, target;
	HANDLE hLink;

	RtlInitUnicodeString(&name, linkname);
	RtlInitUnicodeString(&target, targetname);
	OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL};

	if (NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target))
		return NULL;

	return hLink;
}

HANDLE ObjectManagerCreateDirectory(LPCWSTR dirname)
{
	UNICODE_STRING name;
	HANDLE hDirectory;

	RtlInitUnicodeString(&name, dirname);
	OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL };

	if (NtCreateDirectoryObjectEx(&hDirectory, DIRECTORY_ALL_ACCESS, &oa, NULL, FALSE))
		return NULL;

	return hDirectory;
}

_Success_(return) BOOL MapDll(_In_ LPCWSTR sectionName, _In_ HANDLE file, _Out_ PHANDLE section, _In_ DWORD flags)
{
	UNICODE_STRING name;

	RtlInitUnicodeString(&name, sectionName);
	OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE | flags, NULL, NULL };

	if (flags & OBJ_PERMANENT && !NtOpenSection(section, DELETE, &oa))
	{
		NtMakeTemporaryObject(*section);
		NtClose(*section);
	}

	if (NtCreateSection(section, SECTION_ALL_ACCESS, &oa, NULL, PAGE_READONLY, SEC_IMAGE, file))
		return FALSE;

	return TRUE;
}

_Success_(return) BOOL CreateProtectedProcessAsUser(_In_ HANDLE token, _In_ LPWSTR cmdline, _Out_ PHANDLE phProcess)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	si.cb = sizeof(STARTUPINFOW);
	si.cbReserved2 = 0;
	si.lpDesktop = NULL;
	si.lpTitle = NULL;
	si.lpReserved = NULL;
	si.lpReserved2 = NULL;
	si.dwFlags = 0;

	if (!CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, FALSE, CREATE_PROTECTED_PROCESS | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
		return FALSE;

	*phProcess = pi.hProcess;
	CloseHandle(pi.hThread);

	return TRUE;
}

DWORD64 getPatchOffset(DWORD64 base, DWORD64 target, PRUNTIME_FUNCTION funcTable, DWORD64 funcTableSize)
{
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	for (DWORD i = 0; i < funcTableSize; i++) {
		DWORD64 RVA = searchXref(&decoder, base, funcTable + i, target);
		if (!RVA) continue;

		auto IP = base + RVA;
		auto length = (funcTable + i)->EndAddress - RVA;
		ZydisDecodedInstruction instruction;

		while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, (ZydisDecoderContext *)0, (void*)IP, length, &instruction)))
		{
			if (instruction.length == 7 &&
				instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
				return IP - base;
			IP += instruction.length;
			length -= instruction.length;
		}
	}

	return 0;
}

HANDLE patch(DWORD64 offset)
{
	WCHAR szTemp[MAX_PATH];
	lstrcpyW(szTemp + GetTempPathW(sizeof(szTemp) / sizeof(WCHAR), szTemp), L"shell32.dll");
	CopyFileW(szShell32, szTemp, FALSE);

	auto hFile = CreateFileW(szTemp, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, 7, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return hFile;

	DWORD written = 0;
	if(SetFilePointerEx(hFile, *(LARGE_INTEGER*)&offset, NULL, FILE_BEGIN))
		WriteFile(hFile, patchData, sizeof(patchData) - 1, &written, NULL);
	printf("Write() wrote %d\n", written);

	return hFile;
}

int patchProcess(DWORD64 RVA, DWORD session, bool patchAll)
{
	PWTS_PROCESS_INFOW processList;
	DWORD processCount = 0, pLevel = 0;
	if (!WTSEnumerateProcessesExW(WTS_CURRENT_SERVER_HANDLE, &pLevel, session, (LPWSTR*)&processList, &processCount))
		EXIT("Cannot enumerate process", -25);

	for (DWORD i = 0; i < processCount; i++) {
		if (!patchAll && lstrcmpiW(processList[i].pProcessName, L"explorer.exe")) continue;
		auto hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, TRUE, processList[i].ProcessId);
		if (!hProcess) continue;

		auto hModShell32 = GetModule(hProcess, szShell32);
		if (hModShell32)
		{
			printf("Patching PID:%u\n", processList[i].ProcessId);
			size_t written = 0;
			WriteProcessMemory(hProcess, (void*)((size_t)hModShell32 + RVA), patchData, sizeof(patchData) - 1, &written);
			printf("WriteProcessMemory() wrote %llu\n", written);
		}
		CloseHandle(hProcess);
	}
	EXIT("Patch finished", 0);
}

int main()
{
	heap = GetProcessHeap();
	if (!heap) EXIT("GetProcessHeap() Failed", -1);

	int argc;
	const auto current_cmdline = GetCommandLineW();
	const auto argv = CommandLineToArgvW(current_cmdline, &argc);
	if (!argv) EXIT("CommandLineToArgv() Failed", 0x101);

	bool persist = false;
	bool patchAll = false;
	for (int i = 1; i < argc; ++i) {
		if (!lstrcmpiW(argv[i], L"-p"))
			persist = true;
		else if (!lstrcmpiW(argv[i], L"-a"))
			patchAll = true;
	}
	LocalFree(argv);

	lstrcpyW(szShell32 + GetSystemDirectoryW(szShell32, sizeof(szShell32) / sizeof(WCHAR)), L"\\shell32.dll");

	auto base = (size_t)LoadLibraryExW(szShell32, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!base) EXIT("Load shell32.dll Failed", -2);
	auto pNT = (PIMAGE_NT_HEADERS64)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);

	auto pSection = findSection(pNT, ".rdata");
	if (!pSection) EXIT("Cannot find .rdata", -3);

	auto ContextMenuPresenter = pattenMatch(base, pSection, guid, sizeof(guid) - 1);
	if (ContextMenuPresenter == -1) EXIT("GUID patten not found", -4);

	auto pExceptionDirectory = pNT->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXCEPTION;
	auto funcTable = (PRUNTIME_FUNCTION)(base + pExceptionDirectory->VirtualAddress);
	auto funcTableSize = pExceptionDirectory->Size / (DWORD)sizeof(RUNTIME_FUNCTION);
	if (!funcTableSize) EXIT("Exception directory not found", -5);

	DWORD64 RVA = getPatchOffset(base, ContextMenuPresenter, funcTable, funcTableSize);
	if (!RVA) EXIT("Patch patten not found, already patched?", -6);
	printf("Found offset %llX\n", RVA);

	pSection = IMAGE_FIRST_SECTION(pNT);
	auto rawOffset = RVA + pSection->PointerToRawData - pSection->VirtualAddress;

	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token)) EXIT("Open token of CurrentProcess failed", -7);
	enable_all_privileges(token);
	CloseHandle(token);

	if (!persist) return patchProcess(RVA, WTS_CURRENT_SESSION, patchAll);

	if (!ObjectManagerCreateSymlink(L"\\??\\GLOBALROOT", L"\\GLOBAL??")) EXIT("Create GLOBALROOT symlink failed", -8);

	if (!get_token_pid(get_lsass_pid(), &token)) EXIT("Open token of lsass.exe failed", -9);
	HANDLE dup_token;
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &dup_token)) EXIT("Duplicate impersonation token of lsass.exe failed", -10);
	CloseHandle(token);
	enable_all_privileges(dup_token);

	if (!DuplicateTokenEx(dup_token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &token)) EXIT("Duplicate primary token of lsass.exe failed", -11);
	if (!(SetThreadToken(NULL, dup_token) || ImpersonateLoggedOnUser(dup_token))) EXIT("Impersonate SYSTEM failed", -12);

	if (!ObjectManagerCreateDirectory(L"\\GLOBAL??\\KnownDlls")) EXIT("Create KnownDlls directory failed", -13);
	if (!ObjectManagerCreateSymlink(L"\\GLOBAL??\\KnownDlls\\EventAggregation.dll", L"CreazyUniverse")) EXIT("Create EventAggregation symlink failed", -14);

	if (!RevertToSelf()) EXIT("RevertToSelf() failed", -15);

	if (!DefineDosDevice(DDD_NO_BROADCAST_SYSTEM | DDD_RAW_TARGET_PATH, L"GLOBALROOT\\KnownDlls\\EventAggregation.dll", L"\\BaseNamedObjects\\EventAggregation.dll"))
		if(GetLastError() != ERROR_ALREADY_EXISTS) EXIT("DefineDosDevice() failed", -16);

	if (!(SetThreadToken(NULL, dup_token) || ImpersonateLoggedOnUser(dup_token))) EXIT("Impersonate SYSTEM failed", -17);

	auto hFile = CreateFileW(L"FakeDLL.dll", GENERIC_READ, 7, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) EXIT("Cannot open FakeDLL.dll", -18);
	HANDLE hDllSection;
	if (!MapDll(L"\\BaseNamedObjects\\EventAggregation.dll", hFile, &hDllSection, 0)) EXIT("Cannot create EventAggregation.dll section", -19);
	CloseHandle(hFile);

	hFile = patch(rawOffset);
	if (hFile == INVALID_HANDLE_VALUE) EXIT("Cannot copy and patch shell32.dll", -20);
	if (!MapDll(L"\\BaseNamedObjects\\shell32.dll", hFile, &hDllSection, OBJ_PERMANENT)) EXIT("Cannot create shell32.dll section", -21);
	CloseHandle(hFile);

	PSECURITY_DESCRIPTOR sd;
	if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"D:(A;;GA;;;BA)(A;;0x2000f;;;RC)(A;;0x2000f;;;WD)(A;;0x2000f;;;AC)(A;;0x2000f;;;S-1-15-2-2)S:(ML;;NW;;;LW)",
		SDDL_REVISION_1, &sd, 0)) EXIT("ConvertStringSecurityDescriptorToSecurityDescriptorW() failed", -22);
	if (!SetKernelObjectSecurity(hDllSection, DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, sd))
		EXIT("Cannot set security information of shell32 section", -23);

	HANDLE hNewProcess;
	WCHAR szServices[MAX_PATH];
	lstrcpyW(szServices + GetSystemDirectoryW(szServices, sizeof(szServices) / sizeof(WCHAR)), L"\\services.exe");
	if (!CreateProtectedProcessAsUser(token, szServices, &hNewProcess)) EXIT("Start services.exe failed", -24);

	return patchProcess(RVA, WTS_ANY_SESSION, patchAll);
}