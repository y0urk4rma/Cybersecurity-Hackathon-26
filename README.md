## EDR Evasion via Process Hollowing Detection
This is a completely standard note for any Windows security tool - real-time protection frequently blocks compilation of security research code and disabling it temporarily for a build is routine advice found in every AV/EDR vendor's own documentation.

### Process Hollow Detection Engine

A Windows security research tool that detects process hollowing attacks
by analyzing running processes using five independent behavioral checks.

Built as part of a cybersecurity hackathon pairing an attack demo with
a defensive detection engine.

> **Note:** The attack module (`hollow_attack.c`) is included strictly
> for research and demonstration purposes. Run it only in an isolated
> lab environment. Do not use it on systems you do not own.

### Docs

- [Installation](docs/install.md)
- [Features](docs/features.md)
- [Commands](docs/commands.md)

### Quick Start

```bat
REM Build the detection engine
gcc -O2 -D_WIN32_WINNT=0x0601 -o hollow_detect.exe ^
    main.c engine.c analyzer.c checks.c pe_utils.c ^
    process_utils.c report.c log.c -lntdll -lpsapi -ladvapi32

REM Run as Administrator
hollow_detect.exe
```

### Warnings

**Antivirus / Real-Time Protection**

Windows Defender and most antivirus tools will flag the attack demo
(`hollow_attack.exe`) and possibly the detection engine itself during
compilation or at runtime because they use the same low-level Windows
APIs that real malware uses.

If compilation fails or the binary is deleted immediately after
building, temporarily disable real-time protection before building:

1. Open Windows Security
2. Go to Virus & threat protection
3. Under Virus & threat protection settings click Manage settings
4. Turn off Real-time protection
5. Build the project
6. Turn real-time protection back on immediately after

Alternatively add your project folder as an exclusion so you do not
have to disable protection entirely:

1. Open Windows Security
2. Go to Virus & threat protection settings
3. Scroll to Exclusions and click Add or remove exclusions
4. Add your project folder path

---

**Administrator Rights**

The detection engine requires Administrator rights for full coverage.
Without it, protected system processes are skipped silently.

---

**64-bit Only**

Both the detection engine and attack demo are x86-64 only. They will
not build or run correctly on a 32-bit system.

---

**Lab Environment**

Always run the attack demo inside an isolated VM. Take a snapshot
before running it so you can restore to a clean state easily.
Never run the attack demo on a machine connected to a production network.

> Run as Administrator for full coverage across all system processes.
