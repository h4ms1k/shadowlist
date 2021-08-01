
#pragma once
#include <windows.h>
#include <ntstatus.h>
#include <NTSecAPI.h>
#include <stdio.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, NULL, NULL }

#define DIRECTORY_QUERY					0x0001
#define DIRECTORY_TRAVERSE				0x0002

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

typedef CONST UNICODE_STRING* PCUNICODE_STRING;

PWSTR m_string_unicode_to_string(PCUNICODE_STRING src)
{
	PWSTR ret = NULL;

	if (src->Length && src->Buffer)
	{
		ret = (PWSTR)LocalAlloc(LPTR, src->Length + sizeof(wchar_t));
		if (ret)
		{
			RtlCopyMemory(ret, src->Buffer, src->Length);
		}
	}

	return ret;
}

void m_string_displayFileTime(IN PFILETIME pFileTime)
{
	SYSTEMTIME st;
	wchar_t buffer[0xff];
	if (pFileTime)
	{
		if (FileTimeToSystemTime(pFileTime, &st))
		{
			if (GetDateFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, ARRAYSIZE(buffer)))
			{
				wprintf(L"%s ", buffer);
				if (GetTimeFormat(LOCALE_USER_DEFAULT, 0, &st, NULL, buffer, ARRAYSIZE(buffer)))
					wprintf(L"%s", buffer);
			}
		}
	}
}

void m_string_displayLocalFileTime(IN PFILETIME pFileTime)
{
	FILETIME ft;
	if (pFileTime)
		if (FileTimeToLocalFileTime(pFileTime, &ft))
			m_string_displayFileTime(&ft);
}

BOOL m_string_sprintf(PWSTR* outBuffer, PCWSTR format, ...)
{
	BOOL status = FALSE;
	int varBuf;
	va_list args;
	va_start(args, format);
	varBuf = _vscwprintf(format, args);
	if (varBuf > 0)
	{
		varBuf++;
		if (*outBuffer = (PWSTR)LocalAlloc(LPTR, varBuf * sizeof(wchar_t)))
		{
			varBuf = vswprintf_s(*outBuffer, varBuf, format, args);
			if (varBuf > 0)
				status = TRUE;
			else *outBuffer = (PWSTR)LocalFree(outBuffer);
		}
	}
	return status;
}

typedef NTSYSAPI BOOLEAN(NTAPI* _RtlEqualUnicodeString)(
	PCUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);
_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEqualUnicodeString");

typedef NTSTATUS (WINAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);
_NtOpenDirectoryObject NtOpenDirectoryObject = (_NtOpenDirectoryObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenDirectoryObject");

typedef NTSTATUS (WINAPI* _NtQueryDirectoryObject)(IN HANDLE DirectoryHandle, OUT OPTIONAL PVOID Buffer, IN ULONG Length, IN BOOLEAN ReturnSingleEntry, IN BOOLEAN RestartScan, IN OUT PULONG Context, OUT OPTIONAL PULONG ReturnLength);
_NtQueryDirectoryObject NtQueryDirectoryObject = (_NtQueryDirectoryObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryDirectoryObject");

DECLARE_CONST_UNICODE_STRING(usRootDevice, L"\\Device");
DECLARE_CONST_UNICODE_STRING(usDevice, L"Device");
const OBJECT_ATTRIBUTES oaDevice = RTL_CONSTANT_OBJECT_ATTRIBUTES(&usRootDevice, 0);
const wchar_t* INT_FILES[] = { L"SYSTEM", L"SAM", L"SECURITY", L"SOFTWARE" };
NTSTATUS shadowcopies()
{
	NTSTATUS status;
	HANDLE hDeviceDirectory;
	BYTE Buffer[0x100];
	ULONG Start, Context, ReturnLength, i, j;
	BOOLEAN RestartScan;
	POBJECT_DIRECTORY_INFORMATION pDirectoryInformation;
	PWSTR szName, szShadowName, szFullPath;
	WIN32_FILE_ATTRIBUTE_DATA Attribute;

	status = NtOpenDirectoryObject(&hDeviceDirectory, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, (POBJECT_ATTRIBUTES)&oaDevice);
	if (NT_SUCCESS(status))
	{
		for (Start = 0, Context = 0, RestartScan = TRUE, status = STATUS_MORE_ENTRIES; status == STATUS_MORE_ENTRIES; )
		{
			status = NtQueryDirectoryObject(hDeviceDirectory, Buffer, sizeof(Buffer), FALSE, RestartScan, &Context, &ReturnLength);
			if (NT_SUCCESS(status))
			{
				pDirectoryInformation = (POBJECT_DIRECTORY_INFORMATION)Buffer;
				for (i = 0; i < (Context - Start); i++)
				{
					if (RtlEqualUnicodeString(&usDevice, &pDirectoryInformation[i].TypeName, TRUE))
					{
						szName = m_string_unicode_to_string(&pDirectoryInformation[i].Name);
						if (szName)
						{
							if (szName == wcsstr(szName, L"HarddiskVolumeShadowCopy"))
							{
								if (m_string_sprintf(&szShadowName, L"\\\\?\\GLOBALROOT\\Device\\%s\\", szName))
								{
									wprintf(L"\nShadowCopy Volume : %s\n", szName);
									wprintf(L"| Path            : %s\n", szShadowName);

									if (GetFileAttributesEx(szShadowName, GetFileExInfoStandard, &Attribute))
									{
										wprintf(L"| Volume LastWrite: ");
										m_string_displayLocalFileTime(&Attribute.ftLastWriteTime);
										wprintf(L"\n");
									}
									else wprintf(L"GetFileAttributesEx");
									wprintf(L"\n");
									for (j = 0; j < ARRAYSIZE(INT_FILES); j++)
									{
										if (m_string_sprintf(&szFullPath, L"%sWindows\\System32\\config\\%s", szShadowName, INT_FILES[j]))
										{
											wprintf(L"* %s\n", szFullPath);

											if (GetFileAttributesEx(szFullPath, GetFileExInfoStandard, &Attribute))
											{
												wprintf(L"  | LastWrite   : ");
												m_string_displayLocalFileTime(&Attribute.ftLastWriteTime);
												wprintf(L"\n");
											}
											else wprintf(L"GetFileAttributesEx");

											(szFullPath);
										}
									}
									LocalFree(szShadowName);
								}
							}
							LocalFree(szName);
						}
					}
				}
				Start = Context;
				RestartScan = FALSE;
			}
			else wprintf(L"NtQueryDirectoryObject: 0x%08x\n", status);
		}
		CloseHandle(hDeviceDirectory);
	}
	else wprintf(L"NtOpenDirectoryObject: 0x%08x\n", status);

	return STATUS_SUCCESS;
}

int main()
{
	shadowcopies();
}