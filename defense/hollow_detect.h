#ifndef HOLLOW_DETECT_H
#define HOLLOW_DETECT_H

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

/* ─────────────────────────────────────────────
   Version
───────────────────────────────────────────── */
#define ENGINE_VERSION "1.0.0"

/* ─────────────────────────────────────────────
   Scoring thresholds
───────────────────────────────────────────── */
#define SCORE_IMAGE_MISMATCH        40
#define SCORE_PRIVATE_AT_BASE       35
#define SCORE_THREAD_ANON_START     30
#define SCORE_RWX_AT_BASE           25
#define SCORE_PE_HEADER_CORRUPT     20
#define SCORE_IMAGEBASE_MISMATCH    15
#define SCORE_SUSPICIOUS_IMPORTS    10

#define THRESHOLD_SUSPICIOUS        30
#define THRESHOLD_HIGH              60
#define THRESHOLD_CRITICAL          90

/* ─────────────────────────────────────────────
   Max limits
───────────────────────────────────────────── */
#define MAX_PROCESSES       1024
#define MAX_PATH_LEN        512
#define MAX_THREADS         256
#define HASH_SIZE           32      /* SHA-256 */
#define MAX_SIGNALS         16

/* ─────────────────────────────────────────────
   NT compatibility
   winternl.h (MinGW / MSVC SDK) already defines:
     NTSTATUS, NT_SUCCESS, UNICODE_STRING,
     PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY.
   Guard everything so we never redefine them.
───────────────────────────────────────────── */
#ifndef NT_SUCCESS
#  define NT_SUCCESS(s)  ((NTSTATUS)(s) >= 0)
#endif
#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

/* NtQueryInformationProcess */
typedef NTSTATUS (WINAPI *PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

/* NtQueryInformationThread */
typedef NTSTATUS (WINAPI *PFN_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG  ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength,
    PULONG ReturnLength
);

/* ThreadQuerySetWin32StartAddress = 9 */
#define ThreadQuerySetWin32StartAddress 9

/* ─────────────────────────────────────────────
   Detection signal
───────────────────────────────────────────── */
typedef enum _SIGNAL_TYPE {
    SIG_IMAGE_HASH_MISMATCH   = 0,
    SIG_PRIVATE_MEM_AT_BASE   = 1,
    SIG_THREAD_ANON_START     = 2,
    SIG_RWX_AT_IMAGE_BASE     = 3,
    SIG_PE_HEADER_CORRUPT     = 4,
    SIG_IMAGEBASE_MISMATCH    = 5,
    SIG_SUSPICIOUS_IMPORTS    = 6,
    SIG_MAX
} SIGNAL_TYPE;

static const char *SIGNAL_NAMES[] = {
    "IMAGE_HASH_MISMATCH",
    "PRIVATE_MEM_AT_IMAGE_BASE",
    "THREAD_START_IN_ANONYMOUS_REGION",
    "RWX_PAGE_AT_IMAGE_BASE",
    "PE_HEADER_CORRUPT",
    "IMAGEBASE_VALUE_MISMATCH",
    "SUSPICIOUS_IMPORTS"
};

typedef struct _DETECTION_SIGNAL {
    SIGNAL_TYPE type;
    int         score;
    char        detail[256];
} DETECTION_SIGNAL;

/* ─────────────────────────────────────────────
   Per-process result
───────────────────────────────────────────── */
typedef enum _VERDICT {
    VERDICT_CLEAN       = 0,
    VERDICT_SUSPICIOUS  = 1,
    VERDICT_HIGH        = 2,
    VERDICT_CRITICAL    = 3
} VERDICT;

static const char *VERDICT_STRINGS[] = {
    "CLEAN",
    "SUSPICIOUS",
    "HIGH",
    "CRITICAL"
};

typedef struct _PROCESS_RESULT {
    DWORD   pid;
    char    name[MAX_PATH];
    char    imagePath[MAX_PATH_LEN];
    int     totalScore;
    VERDICT verdict;
    UINT    signalCount;
    DETECTION_SIGNAL signals[MAX_SIGNALS];
    BOOL    analyzed;
    char    error[256];
} PROCESS_RESULT;

/* ─────────────────────────────────────────────
   Engine context
───────────────────────────────────────────── */
typedef struct _ENGINE_CONTEXT {
    PFN_NtQueryInformationProcess NtQueryInformationProcess;
    PFN_NtQueryInformationThread  NtQueryInformationThread;
    BOOL  verbose;
    BOOL  skipSystem;         /* skip PID 0, 4 */
    DWORD targetPid;          /* 0 = scan all */
    FILE *logFile;
} ENGINE_CONTEXT;

/* ─────────────────────────────────────────────
   Function prototypes
───────────────────────────────────────────── */

/* engine.c */
BOOL  engine_init(ENGINE_CONTEXT *ctx, BOOL verbose, BOOL skipSystem, DWORD targetPid, const char *logPath);
void  engine_cleanup(ENGINE_CONTEXT *ctx);
int   engine_run(ENGINE_CONTEXT *ctx, PROCESS_RESULT **results, DWORD *count);

/* analyzer.c */
BOOL  analyze_process(ENGINE_CONTEXT *ctx, DWORD pid, PROCESS_RESULT *result);

/* checks.c */
BOOL  check_image_hash(ENGINE_CONTEXT *ctx, HANDLE hProc, PVOID imageBase,
                       const char *imagePath, DETECTION_SIGNAL *sig);
BOOL  check_vad_memory_type(ENGINE_CONTEXT *ctx, HANDLE hProc, PVOID imageBase,
                             DETECTION_SIGNAL *sig);
BOOL  check_rwx_at_base(ENGINE_CONTEXT *ctx, HANDLE hProc, PVOID imageBase,
                         DETECTION_SIGNAL *sig);
BOOL  check_pe_headers(ENGINE_CONTEXT *ctx, HANDLE hProc, PVOID imageBase,
                        DETECTION_SIGNAL *sig_corrupt, DETECTION_SIGNAL *sig_base);
BOOL  check_thread_start_addresses(ENGINE_CONTEXT *ctx, HANDLE hProc, DWORD pid,
                                    DETECTION_SIGNAL *sig);

/* pe_utils.c */
BOOL  pe_read_headers_from_memory(HANDLE hProc, PVOID base,
                                   IMAGE_DOS_HEADER *dosOut,
                                   IMAGE_NT_HEADERS *ntOut);
BOOL  pe_read_headers_from_disk(const char *path,
                                 IMAGE_DOS_HEADER *dosOut,
                                 IMAGE_NT_HEADERS *ntOut);
BOOL  pe_hash_memory_image(HANDLE hProc, PVOID base, DWORD sizeOfImage,
                            BYTE hash[HASH_SIZE]);
BOOL  pe_hash_file(const char *path, BYTE hash[HASH_SIZE]);

/* process_utils.c */
BOOL  proc_get_image_base(ENGINE_CONTEXT *ctx, HANDLE hProc, PVOID *imageBase);
BOOL  proc_get_image_path(HANDLE hProc, char *pathOut, DWORD pathLen);
BOOL  proc_is_64bit(HANDLE hProc, BOOL *is64);
BOOL  proc_elevate_privileges(void);

/* report.c */
void  report_print_result(ENGINE_CONTEXT *ctx, const PROCESS_RESULT *r);
void  report_print_summary(ENGINE_CONTEXT *ctx,
                            const PROCESS_RESULT *results, DWORD count);
void  report_write_json(const PROCESS_RESULT *results, DWORD count,
                         const char *path);

/* log.c */
void  log_info (ENGINE_CONTEXT *ctx, const char *fmt, ...);
void  log_warn (ENGINE_CONTEXT *ctx, const char *fmt, ...);
void  log_error(ENGINE_CONTEXT *ctx, const char *fmt, ...);
void  log_debug(ENGINE_CONTEXT *ctx, const char *fmt, ...);

#endif /* HOLLOW_DETECT_H */