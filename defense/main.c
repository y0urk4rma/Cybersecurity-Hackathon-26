/*
 * hollow_detect -- Process Hollow Detection Engine
 *
 * Usage:
 *   hollow_detect.exe [options]
 *
 * Options:
 *   -p <pid>       Scan a single process by PID
 *   -v             Verbose / debug output
 *   -s             Skip system processes (PID 0 and 4)
 *   -j <file>      Write JSON report to <file>
 *   -l <file>      Write log to <file>
 *   -a             Print ALL results (default: only flagged)
 *   -h             Show this help
 *
 * Build (MinGW-w64):
 *   gcc -O2 -D_WIN32_WINNT=0x0601 -o hollow_detect.exe
 *       main.c engine.c analyzer.c checks.c pe_utils.c
 *       process_utils.c report.c log.c
 *       -lntdll -lpsapi -ladvapi32
 */

#include "hollow_detect.h"

static void enable_ansi(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void print_banner(void)
{
    printf("\n");
    printf("  \033[1m\033[36m+==========================================+\033[0m\n");
    printf("  \033[1m\033[36m|  Process Hollow Detection Engine v%-6s|\033[0m\n", ENGINE_VERSION);
    printf("  \033[1m\033[36m+==========================================+\033[0m\n");
    printf("\n");
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n\n", prog);
    printf("  -p <pid>   Scan a single process by PID\n");
    printf("  -v         Verbose / debug output\n");
    printf("  -s         Skip system processes (PID 0, 4)\n");
    printf("  -j <file>  Write JSON report to file\n");
    printf("  -l <file>  Write log to file\n");
    printf("  -a         Print ALL results (default: flagged only)\n");
    printf("  -h         Show this help\n\n");
    printf("  Run as Administrator for full coverage (SeDebugPrivilege).\n\n");
}

int main(int argc, char *argv[])
{
    enable_ansi();

    BOOL  verbose   = FALSE;
    BOOL  skipSys   = TRUE;
    BOOL  printAll  = FALSE;
    DWORD targetPid = 0;
    const char *jsonOut = NULL;
    const char *logOut  = NULL;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-v") == 0) verbose   = TRUE;
        else if (strcmp(argv[i], "-s") == 0) skipSys   = TRUE;
        else if (strcmp(argv[i], "-a") == 0) printAll  = TRUE;
        else if (strcmp(argv[i], "-h") == 0) {
            print_banner(); print_usage(argv[0]); return 0;
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            targetPid = (DWORD)atoi(argv[++i]);
            if (targetPid == 0) {
                fprintf(stderr, "[ERROR] Invalid PID: %s\n", argv[i]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) jsonOut = argv[++i];
        else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) logOut  = argv[++i];
        else fprintf(stderr, "[WARN] Unknown option: %s\n", argv[i]);
    }

    print_banner();

    ENGINE_CONTEXT ctx;
    if (!engine_init(&ctx, verbose, skipSys, targetPid, logOut)) {
        fprintf(stderr, "[FATAL] Engine initialization failed.\n");
        return 2;
    }

    PROCESS_RESULT *results = NULL;
    DWORD count = 0;
    int flagged = engine_run(&ctx, &results, &count);
    if (flagged < 0) {
        log_error(&ctx, "Scan failed.");
        engine_cleanup(&ctx);
        return 3;
    }

    for (DWORD i = 0; i < count; i++) {
        PROCESS_RESULT *r = &results[i];
        if (!r->analyzed) continue;
        if (!printAll && r->verdict == VERDICT_CLEAN) continue;
        report_print_result(&ctx, r);
    }

    report_print_summary(&ctx, results, count);

    if (jsonOut)
        report_write_json(results, count, jsonOut);

    free(results);
    engine_cleanup(&ctx);
    return flagged;
}
