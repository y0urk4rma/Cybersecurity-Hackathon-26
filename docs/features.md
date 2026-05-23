# Features

## Detection Engine

### Five Independent Checks

Each check looks at a different property of a running process.
Scores from all fired checks add up to a final verdict.

| Check | What It Looks For | Score |
|---|---|---|
| Image Hash Comparison | SHA-256 of process memory differs from the file on disk | +40 |
| Memory Type at Image Base | Process image is backed by anonymous memory instead of a file | +35 |
| Thread Start Address | Threads starting inside anonymous executable memory | +30 |
| RWX Page at Image Base | Read-write-execute page where only read-execute should exist | +25 |
| PE Header Integrity | DOS or NT headers in memory are missing or corrupt | +20 |

### Verdict Levels

| Score | Verdict | Meaning |
|---|---|---|
| < 30 | CLEAN | No signals of concern |
| 30 – 59 | SUSPICIOUS | One or two weak signals fired |
| 60 – 89 | HIGH | Multiple strong signals fired |
| ≥ 90 | CRITICAL | Almost certainly hollowed |

### Output Formats

- **Console** — colour-coded results per process, verdict and score shown inline
- **Log file** — plain text timestamped log written to disk
- **JSON report** — structured output for every process scanned including
  verdict, total score, and full detail string for every signal that fired

### Scan Modes

- Scan all running processes at once
- Scan a single process by PID
- Verbose mode for per-check debug output
- Show all processes including clean ones

## Attack Demo

### VM Detection

Before running, the attack module checks whether it is inside a
virtual machine using four independent signals:

| Check | Method |
|---|---|
| Registry | Looks for VMware and VirtualBox driver registry keys |
| Processes | Looks for known VM guest service process names |
| CPUID | Checks the hypervisor bit and reads the vendor string |
| MAC Address | Matches network adapter OUI prefixes against known VM vendors |

A score out of 4 is printed so the operator knows the environment
before proceeding.

### Hollowing Procedure

- Spawns a legitimate process in a suspended state
- Allocates memory inside it with execute permissions
- Writes a raw binary payload into that memory
- Redirects the thread instruction pointer to the payload
- Resumes the thread

## Test Harness

- 31 automated tests across 7 sections
- Tests engine init, process utilities, PE utilities,
  individual checks, full analyzer pipeline, synthetic
  hollow simulation, and JSON report output
- Optional live system scan with `--live` flag
- Returns exit code 0 on all pass, 1 if any fail