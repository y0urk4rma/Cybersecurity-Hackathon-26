#include "hollow_detect.h"

/* ─────────────────────────────────────────────────────────────────
   Retrieve the image base of a remote process via PEB
───────────────────────────────────────────────────────────────── */
BOOL proc_get_image_base(ENGINE_CONTEXT *ctx, HANDLE hProc, PVOID *imageBase)
{
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;

    NTSTATUS status = ctx->NtQueryInformationProcess(
        hProc,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen);

    if (!NT_SUCCESS(status)) return FALSE;

    /* PEB.ImageBaseAddress:
       On x64: offset 0x10 into PEB
       On x86: offset 0x08 into PEB
       We read a pointer-sized value from pbi.PebBaseAddress + offset */
#ifdef _WIN64
    const SIZE_T IB_OFFSET = 0x10;
#else
    const SIZE_T IB_OFFSET = 0x08;
#endif

    PVOID pebAddr = pbi.PebBaseAddress;
    PVOID ibAddr  = (BYTE *)pebAddr + IB_OFFSET;
    SIZE_T read   = 0;

    if (!ReadProcessMemory(hProc, ibAddr, imageBase,
                           sizeof(PVOID), &read))
        return FALSE;

    return (read == sizeof(PVOID));
}

/* ─────────────────────────────────────────────────────────────────
   Get the on-disk image path for a process
───────────────────────────────────────────────────────────────── */
BOOL proc_get_image_path(HANDLE hProc, char *pathOut, DWORD pathLen)
{
    /* Try QueryFullProcessImageName first (Vista+) */
    DWORD size = pathLen;
    if (QueryFullProcessImageNameA(hProc, 0, pathOut, &size))
        return TRUE;

    /* Fallback: GetModuleFileNameEx */
    if (GetModuleFileNameExA(hProc, NULL, pathOut, pathLen))
        return TRUE;

    return FALSE;
}

/* ─────────────────────────────────────────────────────────────────
   Determine if a process is 64-bit
───────────────────────────────────────────────────────────────── */
BOOL proc_is_64bit(HANDLE hProc, BOOL *is64)
{
#ifdef _WIN64
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(hProc, &isWow64)) return FALSE;
    *is64 = !isWow64;   /* not WOW64 on a 64-bit OS => native 64-bit */
#else
    *is64 = FALSE;      /* we are 32-bit, can only see 32-bit processes */
#endif
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────
   Elevate to SeDebugPrivilege so we can open any process
───────────────────────────────────────────────────────────────── */
BOOL proc_elevate_privileges(void)
{
    HANDLE hToken = NULL;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    BOOL ok = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken))
        return FALSE;

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid))
        goto done;

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ok = AdjustTokenPrivileges(hToken, FALSE, &tp,
                               sizeof(tp), NULL, NULL);
    /* AdjustTokenPrivileges returns TRUE even on partial success;
       check GetLastError to be sure */
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        ok = FALSE;
done:
    CloseHandle(hToken);
    return ok;
}
