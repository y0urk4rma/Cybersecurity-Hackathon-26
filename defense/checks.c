#include "hollow_detect.h"

/* ─────────────────────────────────────────────────────────────────
   Helper: add a signal to an array (returns TRUE if added)
───────────────────────────────────────────────────────────────── */
static void fill_signal(DETECTION_SIGNAL *sig,
                        SIGNAL_TYPE type, int score,
                        const char *fmt, ...)
{
    sig->type  = type;
    sig->score = score;
    va_list a; va_start(a, fmt);
    vsnprintf(sig->detail, sizeof(sig->detail), fmt, a);
    va_end(a);
}

/* ─────────────────────────────────────────────────────────────────
   CHECK 1: Compare SHA-256 of in-memory image vs on-disk file
───────────────────────────────────────────────────────────────── */
BOOL check_image_hash(ENGINE_CONTEXT *ctx,
                      HANDLE hProc,
                      PVOID  imageBase,
                      const char *imagePath,
                      DETECTION_SIGNAL *sig)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;

    if (!pe_read_headers_from_memory(hProc, imageBase, &dos, &nt)) {
        log_debug(ctx, "  [hash] cannot read PE headers from memory");
        return FALSE;
    }

    DWORD sizeOfImage = nt.OptionalHeader.SizeOfImage;
    if (sizeOfImage == 0) return FALSE;

    BYTE memHash[HASH_SIZE]  = {0};
    BYTE diskHash[HASH_SIZE] = {0};

    if (!pe_hash_memory_image(hProc, imageBase, sizeOfImage, memHash)) {
        log_debug(ctx, "  [hash] failed to hash memory image");
        return FALSE;
    }

    if (!pe_hash_file(imagePath, diskHash)) {
        log_debug(ctx, "  [hash] failed to hash disk file: %s", imagePath);
        return FALSE;
    }

    if (memcmp(memHash, diskHash, HASH_SIZE) != 0) {
        /* Build hex strings for detail */
        char memHex[HASH_SIZE * 2 + 1]  = {0};
        char diskHex[HASH_SIZE * 2 + 1] = {0};
        for (int i = 0; i < HASH_SIZE; i++) {
            sprintf(memHex  + i*2, "%02x", memHash[i]);
            sprintf(diskHex + i*2, "%02x", diskHash[i]);
        }
        fill_signal(sig, SIG_IMAGE_HASH_MISMATCH, SCORE_IMAGE_MISMATCH,
                    "Memory SHA256=%s  Disk SHA256=%s", memHex, diskHex);
        return TRUE;    /* signal fired */
    }
    return FALSE;       /* hashes match — clean */
}

/* ─────────────────────────────────────────────────────────────────
   CHECK 2: VAD / VirtualQueryEx — memory type at image base
            Legitimate: MEM_IMAGE  |  Hollowed: MEM_PRIVATE
───────────────────────────────────────────────────────────────── */
BOOL check_vad_memory_type(ENGINE_CONTEXT *ctx,
                            HANDLE hProc,
                            PVOID  imageBase,
                            DETECTION_SIGNAL *sig)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret = VirtualQueryEx(hProc, imageBase, &mbi, sizeof(mbi));
    if (ret == 0) return FALSE;

    log_debug(ctx, "  [vad] base=%p type=0x%lx protect=0x%lx state=0x%lx",
              imageBase, mbi.Type, mbi.Protect, mbi.State);

    if (mbi.Type == MEM_PRIVATE &&
        (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        fill_signal(sig, SIG_PRIVATE_MEM_AT_BASE, SCORE_PRIVATE_AT_BASE,
                    "MEM_PRIVATE (type=0x%lx) with executable protection "
                    "(protect=0x%lx) at image base %p",
                    mbi.Type, mbi.Protect, imageBase);
        return TRUE;
    }
    return FALSE;
}

/* ─────────────────────────────────────────────────────────────────
   CHECK 3: Detect RWX pages at image base
───────────────────────────────────────────────────────────────── */
BOOL check_rwx_at_base(ENGINE_CONTEXT *ctx,
                        HANDLE hProc,
                        PVOID  imageBase,
                        DETECTION_SIGNAL *sig)
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret = VirtualQueryEx(hProc, imageBase, &mbi, sizeof(mbi));
    if (ret == 0) return FALSE;

    if (mbi.Protect == PAGE_EXECUTE_READWRITE ||
        mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
        fill_signal(sig, SIG_RWX_AT_IMAGE_BASE, SCORE_RWX_AT_BASE,
                    "RWX page at image base %p (protect=0x%lx)",
                    imageBase, mbi.Protect);
        return TRUE;
    }
    return FALSE;
}

/* ─────────────────────────────────────────────────────────────────
   CHECK 4a + 4b: PE header integrity
   4a: Can we even read valid PE headers?
   4b: Does OptionalHeader.ImageBase match actual load address?
       (Only meaningful when ASLR is disabled — we flag but lower score)
───────────────────────────────────────────────────────────────── */
BOOL check_pe_headers(ENGINE_CONTEXT *ctx,
                       HANDLE hProc,
                       PVOID  imageBase,
                       DETECTION_SIGNAL *sig_corrupt,
                       DETECTION_SIGNAL *sig_base)
{
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;
    BOOL fired = FALSE;

    /* 4a: corrupt headers */
    if (!pe_read_headers_from_memory(hProc, imageBase, &dos, &nt)) {
        fill_signal(sig_corrupt, SIG_PE_HEADER_CORRUPT,
                    SCORE_PE_HEADER_CORRUPT,
                    "Cannot read valid DOS/NT PE headers from memory at %p",
                    imageBase);
        fired = TRUE;
        /* Cannot continue with base check */
        return fired;
    }

    /* 4b: image base mismatch
       Under ASLR this is always different on Vista+; we note it but
       assign a low score — useful as a corroborating signal only. */
    ULONG64 expectedBase = (ULONG64)nt.OptionalHeader.ImageBase;
    ULONG64 actualBase   = (ULONG64)(ULONG_PTR)imageBase;

    if (expectedBase != 0 && expectedBase != actualBase) {
        log_debug(ctx,
                  "  [pe] ImageBase in header=0x%llx actual=0x%llx (ASLR shift=%lld)",
                  expectedBase, actualBase,
                  (long long)(actualBase - expectedBase));
        fill_signal(sig_base, SIG_IMAGEBASE_MISMATCH,
                    SCORE_IMAGEBASE_MISMATCH,
                    "PE OptionalHeader.ImageBase=0x%llx but actual load "
                    "address=0x%llx (delta=%lld; may be normal ASLR)",
                    expectedBase, actualBase,
                    (long long)(actualBase - expectedBase));
        fired = TRUE;
    }

    return fired;
}

/* ─────────────────────────────────────────────────────────────────
   CHECK 5: Thread start addresses — are they in anonymous/private memory?
───────────────────────────────────────────────────────────────── */
BOOL check_thread_start_addresses(ENGINE_CONTEXT *ctx,
                                   HANDLE hProc,
                                   DWORD  pid,
                                   DETECTION_SIGNAL *sig)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 te = { sizeof(te) };
    BOOL fired       = FALSE;
    int  anonCount   = 0;
    int  threadCount = 0;

    if (!Thread32First(snap, &te)) goto done;

    do {
        if (te.th32OwnerProcessID != pid) continue;
        threadCount++;

        HANDLE hThread = OpenThread(
            THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!hThread) continue;

        PVOID startAddr = NULL;
        ULONG retLen    = 0;
        NTSTATUS status = ctx->NtQueryInformationThread(
            hThread,
            ThreadQuerySetWin32StartAddress,
            &startAddr,
            sizeof(startAddr),
            &retLen);

        CloseHandle(hThread);

        if (!NT_SUCCESS(status) || startAddr == NULL) continue;

        /* Query what kind of memory that address falls in */
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T qret = VirtualQueryEx(hProc, startAddr, &mbi, sizeof(mbi));
        if (qret == 0) continue;

        log_debug(ctx,
                  "  [thread] TID=%lu startAddr=%p type=0x%lx protect=0x%lx",
                  te.th32ThreadID, startAddr, mbi.Type, mbi.Protect);

        /* A thread starting in MEM_PRIVATE executable memory is suspicious */
        if (mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            anonCount++;
        }
    } while (Thread32Next(snap, &te));

    if (anonCount > 0) {
        fill_signal(sig, SIG_THREAD_ANON_START, SCORE_THREAD_ANON_START,
                    "%d of %d threads start in MEM_PRIVATE executable memory",
                    anonCount, threadCount);
        fired = TRUE;
    }

done:
    CloseHandle(snap);
    return fired;
}
