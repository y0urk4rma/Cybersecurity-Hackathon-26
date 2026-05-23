#include "hollow_detect.h"

/* ─────────────────────────────────────────────────────────────────
   SHA-256 via Windows CryptoAPI
───────────────────────────────────────────────────────────────── */
static BOOL sha256_buffer(const BYTE *data, DWORD len, BYTE out[HASH_SIZE])
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL ok = FALSE;
    DWORD hashLen = HASH_SIZE;

    if (!CryptAcquireContextA(&hProv, NULL, NULL,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        goto done;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto done;
    if (!CryptHashData(hHash, data, len, 0))
        goto done;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, out, &hashLen, 0))
        goto done;
    ok = TRUE;
done:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return ok;
}

/* ─────────────────────────────────────────────────────────────────
   Read PE headers from a remote process memory
───────────────────────────────────────────────────────────────── */
BOOL pe_read_headers_from_memory(HANDLE hProc,
                                  PVOID  base,
                                  IMAGE_DOS_HEADER *dosOut,
                                  IMAGE_NT_HEADERS *ntOut)
{
    SIZE_T read = 0;

    if (!ReadProcessMemory(hProc, base, dosOut,
                           sizeof(IMAGE_DOS_HEADER), &read))
        return FALSE;
    if (read != sizeof(IMAGE_DOS_HEADER))  return FALSE;
    if (dosOut->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PVOID ntAddr = (BYTE *)base + dosOut->e_lfanew;
    if (!ReadProcessMemory(hProc, ntAddr, ntOut,
                           sizeof(IMAGE_NT_HEADERS), &read))
        return FALSE;
    if (read != sizeof(IMAGE_NT_HEADERS))  return FALSE;
    if (ntOut->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────
   Read PE headers from a file on disk
───────────────────────────────────────────────────────────────── */
BOOL pe_read_headers_from_disk(const char *path,
                                IMAGE_DOS_HEADER *dosOut,
                                IMAGE_NT_HEADERS *ntOut)
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD read = 0;
    BOOL ok = FALSE;

    if (!ReadFile(hFile, dosOut, sizeof(IMAGE_DOS_HEADER), &read, NULL)
        || read != sizeof(IMAGE_DOS_HEADER)
        || dosOut->e_magic != IMAGE_DOS_SIGNATURE)
        goto done;

    if (SetFilePointer(hFile, dosOut->e_lfanew, NULL, FILE_BEGIN)
        == INVALID_SET_FILE_POINTER)
        goto done;

    if (!ReadFile(hFile, ntOut, sizeof(IMAGE_NT_HEADERS), &read, NULL)
        || read != sizeof(IMAGE_NT_HEADERS)
        || ntOut->Signature != IMAGE_NT_SIGNATURE)
        goto done;

    ok = TRUE;
done:
    CloseHandle(hFile);
    return ok;
}

/* ─────────────────────────────────────────────────────────────────
   Hash the in-memory image of a process (page-by-page, skip
   unreadable pages, accumulate all readable bytes then SHA-256).
───────────────────────────────────────────────────────────────── */
BOOL pe_hash_memory_image(HANDLE hProc,
                           PVOID  base,
                           DWORD  sizeOfImage,
                           BYTE   hash[HASH_SIZE])
{
    if (sizeOfImage == 0 || sizeOfImage > 256 * 1024 * 1024)
        return FALSE;   /* sanity check: skip > 256 MB */

    BYTE *buf = (BYTE *)malloc(sizeOfImage);
    if (!buf) return FALSE;
    ZeroMemory(buf, sizeOfImage);

    /* Read the image chunk by chunk, skipping bad pages */
    SIZE_T offset = 0;
    while (offset < sizeOfImage) {
        SIZE_T chunkSize = min((SIZE_T)4096,
                               (SIZE_T)sizeOfImage - offset);
        SIZE_T read = 0;
        ReadProcessMemory(hProc,
                          (BYTE *)base + offset,
                          buf + offset,
                          chunkSize, &read);
        /* ignore failures — zero bytes left in buf */
        offset += chunkSize;
    }

    BOOL ok = sha256_buffer(buf, sizeOfImage, hash);
    free(buf);
    return ok;
}

/* ─────────────────────────────────────────────────────────────────
   Hash a file on disk (up to 256 MB)
───────────────────────────────────────────────────────────────── */
BOOL pe_hash_file(const char *path, BYTE hash[HASH_SIZE])
{
    HANDLE hFile = CreateFileA(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER fileSize;
    BOOL ok = FALSE;

    if (!GetFileSizeEx(hFile, &fileSize)) goto done;
    if (fileSize.QuadPart == 0 ||
        fileSize.QuadPart > 256LL * 1024 * 1024) goto done;

    DWORD size = (DWORD)fileSize.QuadPart;
    BYTE *buf  = (BYTE *)malloc(size);
    if (!buf) goto done;

    DWORD read = 0;
    if (!ReadFile(hFile, buf, size, &read, NULL) || read != size) {
        free(buf);
        goto done;
    }

    ok = sha256_buffer(buf, size, hash);
    free(buf);
done:
    CloseHandle(hFile);
    return ok;
}
