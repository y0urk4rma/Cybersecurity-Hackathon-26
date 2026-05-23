#include "hollow_detect.h"

/* ─────────────────────────────────────────────────────────────────
   Initialize the engine: resolve NT APIs, elevate privileges
───────────────────────────────────────────────────────────────── */
BOOL engine_init(ENGINE_CONTEXT *ctx,
                 BOOL  verbose,
                 BOOL  skipSystem,
                 DWORD targetPid,
                 const char *logPath)
{
    ZeroMemory(ctx, sizeof(*ctx));
    ctx->verbose    = verbose;
    ctx->skipSystem = skipSystem;
    ctx->targetPid  = targetPid;

    /* Open log file if requested */
    if (logPath && logPath[0]) {
        ctx->logFile = fopen(logPath, "w");
        if (!ctx->logFile) {
            fprintf(stderr, "[WARN] Cannot open log file: %s\n", logPath);
        }
    }

    /* Resolve NtQueryInformationProcess / NtQueryInformationThread */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        log_error(ctx, "Cannot get ntdll handle");
        return FALSE;
    }

    ctx->NtQueryInformationProcess =
        (PFN_NtQueryInformationProcess)(void*)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");

    ctx->NtQueryInformationThread =
        (PFN_NtQueryInformationThread)(void*)
        GetProcAddress(hNtdll, "NtQueryInformationThread");

    if (!ctx->NtQueryInformationProcess ||
        !ctx->NtQueryInformationThread) {
        log_error(ctx, "Cannot resolve NT APIs from ntdll");
        return FALSE;
    }

    /* Elevate to SeDebugPrivilege — best-effort */
    if (proc_elevate_privileges()) {
        log_info(ctx, "SeDebugPrivilege granted");
    } else {
        log_warn(ctx,
                 "SeDebugPrivilege not granted — some processes may be "
                 "inaccessible. Run as Administrator for full coverage.");
    }

    log_info(ctx, "Process Hollow Detection Engine v%s initialized",
             ENGINE_VERSION);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────
   Cleanup
───────────────────────────────────────────────────────────────── */
void engine_cleanup(ENGINE_CONTEXT *ctx)
{
    if (ctx->logFile) {
        fclose(ctx->logFile);
        ctx->logFile = NULL;
    }
}

/* ─────────────────────────────────────────────────────────────────
   Run: enumerate processes and analyze each one.
   Caller must free(*results) with free().
───────────────────────────────────────────────────────────────── */
int engine_run(ENGINE_CONTEXT *ctx,
               PROCESS_RESULT **results,
               DWORD *count)
{
    *results = NULL;
    *count   = 0;

    /* ── Collect PIDs ──────────────────────────────────────────── */
    DWORD pids[MAX_PROCESSES];
    DWORD pidCount = 0;

    if (ctx->targetPid != 0) {
        /* Single-process mode */
        pids[0] = ctx->targetPid;
        pidCount = 1;
    } else {
        /* Enumerate all */
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            log_error(ctx, "CreateToolhelp32Snapshot failed (err=%lu)",
                      GetLastError());
            return -1;
        }

        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                if (pidCount < MAX_PROCESSES)
                    pids[pidCount++] = pe.th32ProcessID;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    log_info(ctx, "Scanning %lu process(es)...", pidCount);

    /* ── Allocate result array ────────────────────────────────── */
    PROCESS_RESULT *res = (PROCESS_RESULT *)calloc(
        pidCount, sizeof(PROCESS_RESULT));
    if (!res) {
        log_error(ctx, "Out of memory");
        return -1;
    }

    /* ── Analyze each PID ────────────────────────────────────── */
    DWORD analyzed = 0;
    for (DWORD i = 0; i < pidCount; i++) {
        DWORD pid = pids[i];
        if (pid == 0) continue;   /* Idle */

        analyze_process(ctx, pid, &res[analyzed]);
        analyzed++;
    }

    *results = res;
    *count   = analyzed;

    int flagged = 0;
    for (DWORD i = 0; i < analyzed; i++) {
        if (res[i].verdict > VERDICT_CLEAN) flagged++;
    }

    log_info(ctx, "Scan complete. %lu analyzed, %d flagged.", analyzed, flagged);
    return flagged;
}
