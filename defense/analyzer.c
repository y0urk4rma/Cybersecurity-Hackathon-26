#include "hollow_detect.h"

/* ─────────────────────────────────────────────────────────────────
   Helper: append a fired signal to the result
───────────────────────────────────────────────────────────────── */
static void result_add_signal(PROCESS_RESULT *r, DETECTION_SIGNAL *sig)
{
    if (r->signalCount >= MAX_SIGNALS) return;
    r->signals[r->signalCount++] = *sig;
    r->totalScore += sig->score;
}

/* ─────────────────────────────────────────────────────────────────
   Compute verdict from total score
───────────────────────────────────────────────────────────────── */
static VERDICT compute_verdict(int score)
{
    if (score >= THRESHOLD_CRITICAL)    return VERDICT_CRITICAL;
    if (score >= THRESHOLD_HIGH)        return VERDICT_HIGH;
    if (score >= THRESHOLD_SUSPICIOUS)  return VERDICT_SUSPICIOUS;
    return VERDICT_CLEAN;
}

/* ─────────────────────────────────────────────────────────────────
   Main per-process analysis entry point
───────────────────────────────────────────────────────────────── */
BOOL analyze_process(ENGINE_CONTEXT *ctx, DWORD pid, PROCESS_RESULT *result)
{
    ZeroMemory(result, sizeof(*result));
    result->pid = pid;

    /* Open the process with enough rights to read memory & query info */
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ           |
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, pid);

    if (!hProc) {
        snprintf(result->error, sizeof(result->error),
                 "OpenProcess failed (err=%lu)", GetLastError());
        return FALSE;
    }

    /* ── Get image path ──────────────────────────────────────── */
    if (!proc_get_image_path(hProc, result->imagePath,
                             sizeof(result->imagePath))) {
        snprintf(result->imagePath, sizeof(result->imagePath),
                 "<unknown>");
    }

    /* Extract short name */
    const char *slash = strrchr(result->imagePath, '\\');
    strncpy(result->name,
            slash ? slash + 1 : result->imagePath,
            sizeof(result->name) - 1);

    log_debug(ctx, "Analyzing PID=%lu  [%s]  path=%s",
              pid, result->name, result->imagePath);

    /* ── Get image base ──────────────────────────────────────── */
    PVOID imageBase = NULL;
    if (!proc_get_image_base(ctx, hProc, &imageBase) || !imageBase) {
        snprintf(result->error, sizeof(result->error),
                 "Cannot determine image base");
        CloseHandle(hProc);
        return FALSE;
    }
    log_debug(ctx, "  ImageBase=%p", imageBase);

    /* ── Skip System/Idle ─────────────────────────────────────
       PIDs 0 (Idle) and 4 (System) don't have user-space images */
    if (ctx->skipSystem && (pid == 0 || pid == 4)) {
        CloseHandle(hProc);
        result->analyzed = TRUE;
        result->verdict  = VERDICT_CLEAN;
        return TRUE;
    }

    /* ════════════════════════════════════════════════════════════
       Run each check — fire signals as needed
       ════════════════════════════════════════════════════════════ */

    DETECTION_SIGNAL sig;

    /* CHECK 1 — image hash mismatch */
    if (strcmp(result->imagePath, "<unknown>") != 0) {
        ZeroMemory(&sig, sizeof(sig));
        if (check_image_hash(ctx, hProc, imageBase,
                             result->imagePath, &sig)) {
            log_warn(ctx, "  [!] %s: %s",
                     SIGNAL_NAMES[sig.type], sig.detail);
            result_add_signal(result, &sig);
        }
    }

    /* CHECK 2 — VAD / private memory at base */
    ZeroMemory(&sig, sizeof(sig));
    if (check_vad_memory_type(ctx, hProc, imageBase, &sig)) {
        log_warn(ctx, "  [!] %s: %s",
                 SIGNAL_NAMES[sig.type], sig.detail);
        result_add_signal(result, &sig);
    }

    /* CHECK 3 — RWX at image base */
    ZeroMemory(&sig, sizeof(sig));
    if (check_rwx_at_base(ctx, hProc, imageBase, &sig)) {
        log_warn(ctx, "  [!] %s: %s",
                 SIGNAL_NAMES[sig.type], sig.detail);
        result_add_signal(result, &sig);
    }

    /* CHECK 4 — PE header integrity + ImageBase value */
    {
        DETECTION_SIGNAL sig_corrupt, sig_base;
        ZeroMemory(&sig_corrupt, sizeof(sig_corrupt));
        ZeroMemory(&sig_base,    sizeof(sig_base));

        BOOL fired = check_pe_headers(ctx, hProc, imageBase,
                                       &sig_corrupt, &sig_base);
        if (fired) {
            if (sig_corrupt.score > 0) {
                log_warn(ctx, "  [!] %s: %s",
                         SIGNAL_NAMES[sig_corrupt.type], sig_corrupt.detail);
                result_add_signal(result, &sig_corrupt);
            }
            if (sig_base.score > 0) {
                log_debug(ctx, "  [~] %s: %s",
                          SIGNAL_NAMES[sig_base.type], sig_base.detail);
                result_add_signal(result, &sig_base);
            }
        }
    }

    /* CHECK 5 — thread start addresses */
    ZeroMemory(&sig, sizeof(sig));
    if (check_thread_start_addresses(ctx, hProc, pid, &sig)) {
        log_warn(ctx, "  [!] %s: %s",
                 SIGNAL_NAMES[sig.type], sig.detail);
        result_add_signal(result, &sig);
    }

    /* ── Compute final verdict ───────────────────────────────── */
    result->verdict  = compute_verdict(result->totalScore);
    result->analyzed = TRUE;

    CloseHandle(hProc);
    return TRUE;
}
