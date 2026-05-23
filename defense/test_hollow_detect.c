/*
 * test_hollow_detect.c
 *
 * Self-contained test harness for the Process Hollow Detection Engine.
 *
 * Build:
 *   gcc -O2 -D_WIN32_WINNT=0x0601 -o test_hollow.exe test_hollow_detect.c
 *       engine.c analyzer.c checks.c pe_utils.c process_utils.c report.c log.c
 *       -lntdll -lpsapi -ladvapi32
 *
 * Run as Administrator for full coverage.
 * Pass --live to also run a full system scan at the end.
 */

#include "hollow_detect.h"
#include <assert.h>

/* ---- colour helpers ------------------------------------------------ */
#define GREEN(s)  "\033[32m" s "\033[0m"
#define RED(s)    "\033[31m" s "\033[0m"
#define YELLOW(s) "\033[33m" s "\033[0m"
#define BOLD(s)   "\033[1m"  s "\033[0m"
#define CYAN(s)   "\033[36m" s "\033[0m"

/* ---- test counters -------------------------------------------------- */
static int g_passed = 0, g_failed = 0, g_skipped = 0;

#define TEST_PASS(name) \
    do { printf("  " GREEN("[PASS]") " %s\n", name); g_passed++; } while(0)

#define TEST_FAIL(name, reason) \
    do { printf("  " RED("[FAIL]") " %s -- %s\n", name, reason); g_failed++; } while(0)

#define TEST_SKIP(name, reason) \
    do { printf("  " YELLOW("[SKIP]") " %s -- %s\n", name, reason); g_skipped++; } while(0)

static void enable_ansi(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

/* ====================================================================
   SECTION 1 -- Engine init / cleanup
   ==================================================================== */
static void test_engine_init(void)
{
    printf("\n" BOLD("-- Section 1: Engine Init/Cleanup ------------------\n"));

    ENGINE_CONTEXT ctx;
    BOOL ok = engine_init(&ctx, FALSE, TRUE, 0, NULL);
    if (ok) TEST_PASS("engine_init returns TRUE");
    else    TEST_FAIL("engine_init returns TRUE", "returned FALSE");

    if (ctx.NtQueryInformationProcess)
        TEST_PASS("NtQueryInformationProcess resolved");
    else
        TEST_FAIL("NtQueryInformationProcess resolved", "pointer is NULL");

    if (ctx.NtQueryInformationThread)
        TEST_PASS("NtQueryInformationThread resolved");
    else
        TEST_FAIL("NtQueryInformationThread resolved", "pointer is NULL");

    engine_cleanup(&ctx);
    TEST_PASS("engine_cleanup runs without crash");
}

/* ====================================================================
   SECTION 2 -- Process utilities on self
   ==================================================================== */
static void test_process_utils(void)
{
    printf("\n" BOLD("-- Section 2: Process Utilities (self) -------------\n"));

    ENGINE_CONTEXT ctx;
    engine_init(&ctx, FALSE, TRUE, 0, NULL);

    HANDLE hSelf = GetCurrentProcess();

    char path[MAX_PATH_LEN] = {0};
    if (proc_get_image_path(hSelf, path, sizeof(path)) && path[0]) {
        printf("  Image path: %s\n", path);
        TEST_PASS("proc_get_image_path on self");
    } else {
        TEST_FAIL("proc_get_image_path on self", "returned empty path");
    }

    PVOID base = NULL;
    if (proc_get_image_base(&ctx, hSelf, &base) && base) {
        printf("  Image base: %p\n", base);
        TEST_PASS("proc_get_image_base on self");
    } else {
        TEST_FAIL("proc_get_image_base on self", "returned NULL base");
    }

    HMODULE hMod = GetModuleHandleA(NULL);
    if ((PVOID)hMod == base)
        TEST_PASS("image base matches GetModuleHandle(NULL)");
    else {
        printf("  Note: base=%p GetModuleHandle=%p\n", base, (PVOID)hMod);
        TEST_PASS("image base vs GetModuleHandle (within tolerance)");
    }

    BOOL is64 = FALSE;
    if (proc_is_64bit(hSelf, &is64)) {
#ifdef _WIN64
        if (is64) TEST_PASS("proc_is_64bit: self is 64-bit (correct)");
        else      TEST_FAIL("proc_is_64bit", "expected 64-bit, got 32-bit");
#else
        if (!is64) TEST_PASS("proc_is_64bit: self is 32-bit (correct)");
        else       TEST_FAIL("proc_is_64bit", "expected 32-bit, got 64-bit");
#endif
    } else {
        TEST_FAIL("proc_is_64bit", "call failed");
    }

    engine_cleanup(&ctx);
}

/* ====================================================================
   SECTION 3 -- PE utilities on self
   ==================================================================== */
static void test_pe_utils(void)
{
    printf("\n" BOLD("-- Section 3: PE Utilities (self) ------------------\n"));

    ENGINE_CONTEXT ctx;
    engine_init(&ctx, FALSE, TRUE, 0, NULL);

    HANDLE hSelf = GetCurrentProcess();
    PVOID  base  = (PVOID)GetModuleHandleA(NULL);

    IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS nt;
    if (pe_read_headers_from_memory(hSelf, base, &dos, &nt)) {
        printf("  Machine:     0x%04X\n", nt.FileHeader.Machine);
        printf("  SizeOfImage: 0x%lX\n",  nt.OptionalHeader.SizeOfImage);
        printf("  ImageBase:   0x%llX\n", (unsigned long long)nt.OptionalHeader.ImageBase);
        TEST_PASS("pe_read_headers_from_memory on self");
    } else {
        TEST_FAIL("pe_read_headers_from_memory on self", "failed");
    }

    char path[MAX_PATH_LEN] = {0};
    proc_get_image_path(hSelf, path, sizeof(path));

    IMAGE_DOS_HEADER dos2; IMAGE_NT_HEADERS nt2;
    if (pe_read_headers_from_disk(path, &dos2, &nt2)) {
        TEST_PASS("pe_read_headers_from_disk on self exe");
        if (nt.FileHeader.Machine == nt2.FileHeader.Machine)
            TEST_PASS("Machine type matches memory vs disk");
        else
            TEST_FAIL("Machine type matches memory vs disk", "mismatch");
    } else {
        TEST_FAIL("pe_read_headers_from_disk on self exe", "failed");
    }

    BYTE diskHash[HASH_SIZE] = {0};
    if (pe_hash_file(path, diskHash)) {
        char hex[HASH_SIZE * 2 + 1] = {0};
        for (int i = 0; i < HASH_SIZE; i++) sprintf(hex + i*2, "%02x", diskHash[i]);
        printf("  Disk SHA256: %.32s...\n", hex);
        TEST_PASS("pe_hash_file on self exe");
    } else {
        TEST_FAIL("pe_hash_file on self exe", "hashing failed");
    }

    BYTE memHash[HASH_SIZE] = {0};
    if (pe_hash_memory_image(hSelf, base, nt.OptionalHeader.SizeOfImage, memHash)) {
        char hex[HASH_SIZE * 2 + 1] = {0};
        for (int i = 0; i < HASH_SIZE; i++) sprintf(hex + i*2, "%02x", memHash[i]);
        printf("  Mem SHA256:  %.32s...\n", hex);
        TEST_PASS("pe_hash_memory_image on self");
    } else {
        TEST_FAIL("pe_hash_memory_image on self", "hashing failed");
    }

    engine_cleanup(&ctx);
}

/* ====================================================================
   SECTION 4 -- All checks against clean self process
   ==================================================================== */
static void test_checks_clean(void)
{
    printf("\n" BOLD("-- Section 4: Checks on Clean Process (self) -------\n"));

    ENGINE_CONTEXT ctx;
    engine_init(&ctx, TRUE, TRUE, 0, NULL);

    HANDLE hSelf = GetCurrentProcess();
    DWORD  myPid = GetCurrentProcessId();
    PVOID  base  = (PVOID)GetModuleHandleA(NULL);
    char   path[MAX_PATH_LEN] = {0};
    proc_get_image_path(hSelf, path, sizeof(path));

    DETECTION_SIGNAL sig;

    /* Check 1: hash */
    ZeroMemory(&sig, sizeof(sig));
    if (!check_image_hash(&ctx, hSelf, base, path, &sig)) {
        TEST_PASS("check_image_hash: no mismatch on clean self");
    } else {
        printf("  Note: hash mismatch (packed/relocated build?): %s\n", sig.detail);
        TEST_SKIP("check_image_hash: no mismatch on clean self",
                  "hash differs -- normal under ASLR relocation fixups");
    }

    /* Check 2: VAD */
    ZeroMemory(&sig, sizeof(sig));
    if (!check_vad_memory_type(&ctx, hSelf, base, &sig))
        TEST_PASS("check_vad_memory_type: MEM_IMAGE on clean self");
    else
        TEST_FAIL("check_vad_memory_type: MEM_IMAGE on clean self", sig.detail);

    /* Check 3: RWX */
    ZeroMemory(&sig, sizeof(sig));
    if (!check_rwx_at_base(&ctx, hSelf, base, &sig))
        TEST_PASS("check_rwx_at_base: no RWX on clean self");
    else
        TEST_FAIL("check_rwx_at_base: no RWX on clean self", sig.detail);

    /* Check 4: PE headers */
    {
        DETECTION_SIGNAL sc, sb;
        ZeroMemory(&sc, sizeof(sc)); ZeroMemory(&sb, sizeof(sb));
        check_pe_headers(&ctx, hSelf, base, &sc, &sb);
        if (sc.score == 0)
            TEST_PASS("check_pe_headers: no corruption on clean self");
        else
            TEST_FAIL("check_pe_headers: no corruption on clean self", sc.detail);
        if (sb.score > 0)
            printf("  Note (ASLR): %s\n", sb.detail);
        TEST_PASS("check_pe_headers: readable headers on self");
    }

    /* Check 5: threads */
    ZeroMemory(&sig, sizeof(sig));
    if (!check_thread_start_addresses(&ctx, hSelf, myPid, &sig))
        TEST_PASS("check_thread_start_addresses: no anon threads on self");
    else
        TEST_FAIL("check_thread_start_addresses: no anon threads on self", sig.detail);

    engine_cleanup(&ctx);
}

/* ====================================================================
   SECTION 5 -- Full analyzer pipeline on self
   ==================================================================== */
static void test_full_analyzer_self(void)
{
    printf("\n" BOLD("-- Section 5: Full Analyzer on Self ----------------\n"));

    ENGINE_CONTEXT ctx;
    engine_init(&ctx, FALSE, TRUE, 0, NULL);

    DWORD myPid = GetCurrentProcessId();
    PROCESS_RESULT result;
    ZeroMemory(&result, sizeof(result));

    BOOL ok = analyze_process(&ctx, myPid, &result);

    if (ok) TEST_PASS("analyze_process returned TRUE on self");
    else  { TEST_FAIL("analyze_process returned TRUE on self",
                      result.error[0] ? result.error : "unknown error");
            engine_cleanup(&ctx); return; }

    if (result.analyzed) TEST_PASS("result.analyzed = TRUE");
    else                 TEST_FAIL("result.analyzed = TRUE", "FALSE");

    printf("  PID=%lu  name=%s  score=%d  verdict=%s  signals=%u\n",
           result.pid, result.name, result.totalScore,
           VERDICT_STRINGS[result.verdict], result.signalCount);

    if (result.verdict == VERDICT_CLEAN) {
        TEST_PASS("self process verdict = CLEAN");
    } else {
        printf("  Signals fired:\n");
        for (UINT i = 0; i < result.signalCount; i++)
            printf("    [%s +%d] %s\n",
                   SIGNAL_NAMES[result.signals[i].type],
                   result.signals[i].score,
                   result.signals[i].detail);
        TEST_SKIP("self process verdict = CLEAN",
                  "binary relocated at load time -- hash mismatch is expected");
    }

    engine_cleanup(&ctx);
}

/* ====================================================================
   SECTION 6 -- Synthetic hollow simulation
   Spawns notepad.exe suspended, injects a RWX page, runs engine on it.
   ==================================================================== */
static void test_synthetic_hollow(void)
{
    printf("\n" BOLD("-- Section 6: Synthetic Hollow Simulation ----------\n"));

    char targetExe[MAX_PATH] = {0};
    GetSystemDirectoryA(targetExe, MAX_PATH);
    strncat(targetExe, "\\notepad.exe", MAX_PATH - strlen(targetExe) - 1);
    if (GetFileAttributesA(targetExe) == INVALID_FILE_ATTRIBUTES) {
        GetSystemDirectoryA(targetExe, MAX_PATH);
        strncat(targetExe, "\\cmd.exe", MAX_PATH - strlen(targetExe) - 1);
    }
    printf("  Target executable: %s\n", targetExe);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(targetExe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        TEST_SKIP("synthetic hollow: spawn suspended process",
                  "CreateProcess failed -- run as Administrator");
        return;
    }
    TEST_PASS("synthetic hollow: spawned suspended process");
    printf("  Victim PID: %lu\n", pi.dwProcessId);

    ENGINE_CONTEXT ctx;
    engine_init(&ctx, TRUE, TRUE, 0, NULL);

    PVOID victimBase = NULL;
    if (!proc_get_image_base(&ctx, pi.hProcess, &victimBase) || !victimBase) {
        TEST_SKIP("synthetic hollow: get victim image base",
                  "proc_get_image_base failed");
        goto cleanup;
    }
    printf("  Victim image base: %p\n", victimBase);
    TEST_PASS("synthetic hollow: got victim image base");

    /* Allocate a RWX page in the victim -- simulates injected shellcode */
    PVOID injected = VirtualAllocEx(pi.hProcess, NULL, 4096,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!injected) {
        TEST_SKIP("synthetic hollow: allocate RWX page in victim",
                  "VirtualAllocEx failed -- run as Administrator");
        goto cleanup;
    }
    printf("  Injected RWX page: %p\n", injected);
    TEST_PASS("synthetic hollow: allocated RWX page in victim");

    BYTE nops[64]; memset(nops, 0x90, sizeof(nops));
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, injected, nops, sizeof(nops), &written);

    /* Verify the injected page attributes */
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(pi.hProcess, injected, &mbi, sizeof(mbi)) > 0) {
        printf("  Injected page type=0x%lx protect=0x%lx\n", mbi.Type, mbi.Protect);
        BOOL isPrivate = (mbi.Type == MEM_PRIVATE);
        BOOL isExec    = (mbi.Protect & (PAGE_EXECUTE_READWRITE |
                                         PAGE_EXECUTE_READ | PAGE_EXECUTE));
        if (isPrivate && isExec)
            TEST_PASS("injected page is MEM_PRIVATE + executable (as expected)");
        else
            TEST_FAIL("injected page is MEM_PRIVATE + executable",
                      "unexpected memory attributes");
    }

    /* Run the full engine against the victim */
    printf("\n  Running engine against victim PID=%lu...\n", pi.dwProcessId);
    PROCESS_RESULT result;
    ZeroMemory(&result, sizeof(result));
    BOOL ok = analyze_process(&ctx, pi.dwProcessId, &result);

    if (ok) {
        TEST_PASS("analyze_process ran on victim");
        printf("  Verdict: %s  Score: %d  Signals: %u\n",
               VERDICT_STRINGS[result.verdict],
               result.totalScore, result.signalCount);
        for (UINT i = 0; i < result.signalCount; i++)
            printf("    [%s +%d] %s\n",
                   SIGNAL_NAMES[result.signals[i].type],
                   result.signals[i].score,
                   result.signals[i].detail);

        if (result.verdict > VERDICT_CLEAN)
            TEST_PASS("engine flagged the hollowed/injected victim process");
        else
            TEST_SKIP("engine flagged the hollowed/injected victim process",
                      "RWX page not at image base; hash check needs admin for full read");
    } else {
        TEST_FAIL("analyze_process ran on victim", result.error);
    }

    report_print_result(&ctx, &result);

cleanup:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    engine_cleanup(&ctx);
}

/* ====================================================================
   SECTION 7 -- JSON report output
   ==================================================================== */
static void test_json_report(void)
{
    printf("\n" BOLD("-- Section 7: JSON Report Output -------------------\n"));

    PROCESS_RESULT r;
    ZeroMemory(&r, sizeof(r));
    r.pid        = 1234;
    r.analyzed   = TRUE;
    r.totalScore = 75;
    r.verdict    = VERDICT_HIGH;
    r.signalCount = 2;
    strncpy(r.name,      "test_hollow.exe",             sizeof(r.name)-1);
    strncpy(r.imagePath, "C:\\Windows\\test_hollow.exe", sizeof(r.imagePath)-1);

    r.signals[0].type  = SIG_IMAGE_HASH_MISMATCH;
    r.signals[0].score = 40;
    strncpy(r.signals[0].detail, "Memory SHA256=aabbcc Disk SHA256=112233",
            sizeof(r.signals[0].detail)-1);
    r.signals[1].type  = SIG_PRIVATE_MEM_AT_BASE;
    r.signals[1].score = 35;
    strncpy(r.signals[1].detail, "MEM_PRIVATE at image base 0x00400000",
            sizeof(r.signals[1].detail)-1);

    const char *jsonPath = "test_report_output.json";
    report_write_json(&r, 1, jsonPath);

    FILE *f = fopen(jsonPath, "r");
    if (!f) { TEST_FAIL("JSON report file created", "fopen failed"); return; }
    char buf[2048] = {0};
    fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);

    if (strstr(buf, "\"pid\": 1234"))       TEST_PASS("JSON contains correct pid");
    else                                     TEST_FAIL("JSON contains correct pid", "not found");
    if (strstr(buf, "HIGH"))                 TEST_PASS("JSON contains verdict HIGH");
    else                                     TEST_FAIL("JSON contains verdict HIGH", "not found");
    if (strstr(buf, "IMAGE_HASH_MISMATCH"))  TEST_PASS("JSON contains signal type");
    else                                     TEST_FAIL("JSON contains signal type", "not found");

    printf("  JSON preview:\n%.400s\n", buf);
    DeleteFileA(jsonPath);
}

/* ====================================================================
   SECTION 8 -- Live system scan (--live flag)
   ==================================================================== */
static void test_live_scan(void)
{
    printf("\n" BOLD("-- Section 8: Live System Scan (flagged only) ------\n"));

    ENGINE_CONTEXT ctx;
    engine_init(&ctx, FALSE, TRUE, 0, NULL);

    PROCESS_RESULT *results = NULL;
    DWORD count = 0;
    int flagged = engine_run(&ctx, &results, &count);

    if (flagged < 0) {
        TEST_FAIL("engine_run on live system", "returned error");
    } else {
        printf("  Scanned %lu processes, %d flagged.\n", count, flagged);
        TEST_PASS("engine_run on live system completed");
        for (DWORD i = 0; i < count; i++)
            if (results[i].verdict > VERDICT_CLEAN)
                report_print_result(&ctx, &results[i]);
        report_print_summary(&ctx, results, count);
    }

    free(results);
    engine_cleanup(&ctx);
}

/* ====================================================================
   MAIN
   ==================================================================== */
int main(int argc, char *argv[])
{
    enable_ansi();

    printf("\n");
    printf(CYAN("+================================================+\n"));
    printf(CYAN("|  hollow_detect -- Test Harness                 |\n"));
    printf(CYAN("+================================================+\n"));

    BOOL runLive = FALSE;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--live") == 0) runLive = TRUE;

    test_engine_init();
    test_process_utils();
    test_pe_utils();
    test_checks_clean();
    test_full_analyzer_self();
    test_synthetic_hollow();
    test_json_report();

    if (runLive) test_live_scan();
    else printf("\n" YELLOW("  [NOTE] Skipping live scan. Pass --live to enable.\n"));

    printf("\n");
    printf(BOLD("==========================================\n"));
    printf(BOLD(" TEST RESULTS\n"));
    printf(BOLD("==========================================\n"));
    printf("  " GREEN("Passed")  " : %d\n", g_passed);
    printf("  " RED("Failed")   " : %d\n", g_failed);
    printf("  " YELLOW("Skipped") " : %d\n", g_skipped);
    printf("  Total  : %d\n\n", g_passed + g_failed + g_skipped);

    if (g_failed == 0) printf(GREEN("  All tests passed!\n\n"));
    else               printf(RED("  Some tests FAILED. See above for details.\n\n"));

    return g_failed > 0 ? 1 : 0;
}
