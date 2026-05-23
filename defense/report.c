#include "hollow_detect.h"

/* Enable ANSI colour support on Windows 10+ CMD */
static void enable_ansi(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_GREEN   "\033[32m"
#define COL_BOLD    "\033[1m"
#define COL_RESET   "\033[0m"
#define COL_MAGENTA "\033[35m"

static const char *verdict_color(VERDICT v)
{
    switch (v) {
        case VERDICT_CRITICAL:   return COL_RED;
        case VERDICT_HIGH:       return COL_MAGENTA;
        case VERDICT_SUSPICIOUS: return COL_YELLOW;
        default:                 return COL_GREEN;
    }
}

void report_print_result(ENGINE_CONTEXT *ctx, const PROCESS_RESULT *r)
{
    if (!r->analyzed) return;

    const char *vc = verdict_color(r->verdict);
    const char *vs = VERDICT_STRINGS[r->verdict];

    printf("\n%s+-- PID %-6lu  %-30s  [%s%s%s]  score=%d%s\n",
           COL_BOLD, r->pid, r->name,
           vc, vs, COL_BOLD, r->totalScore, COL_RESET);
    printf("|   Path: %s\n", r->imagePath[0] ? r->imagePath : "<unknown>");

    if (r->error[0])
        printf("|   Error: %s\n", r->error);

    if (r->signalCount == 0) {
        printf("|   No suspicious signals.\n");
    } else {
        for (UINT i = 0; i < r->signalCount; i++) {
            const DETECTION_SIGNAL *s = &r->signals[i];
            printf("|   %s[+]%s (%+d) %s\n",
                   verdict_color(r->verdict), COL_RESET,
                   s->score, SIGNAL_NAMES[s->type]);
            printf("|       %s\n", s->detail);
        }
    }
    printf("+----------------------------------------------------\n");

    if (ctx && ctx->logFile) {
        fprintf(ctx->logFile,
                "PID=%lu name=%s verdict=%s score=%d signals=%u path=%s\n",
                r->pid, r->name, vs, r->totalScore,
                r->signalCount, r->imagePath);
        for (UINT i = 0; i < r->signalCount; i++) {
            fprintf(ctx->logFile, "  SIGNAL %s (+%d): %s\n",
                    SIGNAL_NAMES[r->signals[i].type],
                    r->signals[i].score,
                    r->signals[i].detail);
        }
    }
}

void report_print_summary(ENGINE_CONTEXT *ctx,
                           const PROCESS_RESULT *results,
                           DWORD count)
{
    enable_ansi();

    printf("\n%s========================================%s\n", COL_BOLD, COL_RESET);
    printf("%s SCAN SUMMARY%s\n", COL_BOLD, COL_RESET);
    printf("%s========================================%s\n\n", COL_BOLD, COL_RESET);

    DWORD clean = 0, susp = 0, high = 0, crit = 0, err = 0;
    for (DWORD i = 0; i < count; i++) {
        const PROCESS_RESULT *r = &results[i];
        if (!r->analyzed)            { err++;  continue; }
        switch (r->verdict) {
            case VERDICT_CLEAN:      clean++; break;
            case VERDICT_SUSPICIOUS: susp++;  break;
            case VERDICT_HIGH:       high++;  break;
            case VERDICT_CRITICAL:   crit++;  break;
        }
    }

    printf("  Total analyzed : %lu\n", count);
    printf("  %sClean%s          : %lu\n", COL_GREEN,   COL_RESET, clean);
    printf("  %sSuspicious%s     : %lu\n", COL_YELLOW,  COL_RESET, susp);
    printf("  %sHigh%s           : %lu\n", COL_MAGENTA, COL_RESET, high);
    printf("  %sCritical%s       : %lu\n", COL_RED,     COL_RESET, crit);
    printf("  Errors         : %lu\n\n", err);

    if (crit + high + susp == 0) {
        printf("  %s[OK] No hollow processes detected.%s\n\n", COL_GREEN, COL_RESET);
        return;
    }

    printf("  %s[!] Flagged processes:%s\n", COL_BOLD, COL_RESET);
    for (DWORD i = 0; i < count; i++) {
        const PROCESS_RESULT *r = &results[i];
        if (!r->analyzed || r->verdict == VERDICT_CLEAN) continue;
        printf("      %s%-6lu  %-28s  [%s]  score=%d%s\n",
               verdict_color(r->verdict), r->pid, r->name,
               VERDICT_STRINGS[r->verdict], r->totalScore, COL_RESET);
    }
    printf("\n");
}

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    while (*s) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            default:   fputc(*s, f);
        }
        s++;
    }
    fputc('"', f);
}

void report_write_json(const PROCESS_RESULT *results, DWORD count, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "[ERROR] Cannot write JSON to %s\n", path); return; }

    fprintf(f, "{\n  \"engine_version\": \"%s\",\n  \"results\": [\n", ENGINE_VERSION);

    for (DWORD i = 0; i < count; i++) {
        const PROCESS_RESULT *r = &results[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"pid\": %lu,\n", r->pid);
        fprintf(f, "      \"name\": ");    json_str(f, r->name);
        fprintf(f, ",\n      \"path\": "); json_str(f, r->imagePath);
        fprintf(f, ",\n      \"verdict\": \"%s\",\n",
                r->analyzed ? VERDICT_STRINGS[r->verdict] : "ERROR");
        fprintf(f, "      \"score\": %d,\n", r->totalScore);
        fprintf(f, "      \"signals\": [\n");
        for (UINT j = 0; j < r->signalCount; j++) {
            const DETECTION_SIGNAL *s = &r->signals[j];
            fprintf(f, "        {\n");
            fprintf(f, "          \"type\": \"%s\",\n", SIGNAL_NAMES[s->type]);
            fprintf(f, "          \"score\": %d,\n", s->score);
            fprintf(f, "          \"detail\": "); json_str(f, s->detail);
            fprintf(f, "\n        }%s\n", j + 1 < r->signalCount ? "," : "");
        }
        fprintf(f, "      ]\n    }%s\n", i + 1 < count ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
    printf("[INFO] JSON report written to %s\n", path);
}
