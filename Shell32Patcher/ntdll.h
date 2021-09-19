#pragma once
#include <windows.h>
#include <winternl.h>

#define DIRECTORY_ALL_ACCESS            (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | 0x1)

extern "C" NTSTATUS NTAPI NtCreateDirectoryObjectEx(
	OUT PHANDLE SymbolicLinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ShadowDir,
	ULONG Something
);

extern "C" NTSTATUS NTAPI NtCreateSymbolicLinkObject(
	OUT PHANDLE SymbolicLinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING DestinationName
);

extern "C" NTSTATUS NTAPI NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN  ACCESS_MASK DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN  PLARGE_INTEGER MaximumSize OPTIONAL,
	IN  ULONG SectionPageProtection,
	IN  ULONG AllocationAttributes,
	IN  HANDLE FileHandle OPTIONAL
);

extern "C" NTSTATUS NTAPI NtOpenSymbolicLinkObject(
	OUT PHANDLE SymbolicLinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS NTAPI NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C" NTSTATUS NTAPI NtMakeTemporaryObject(
	IN HANDLE ObjectHandle
);