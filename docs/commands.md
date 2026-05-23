# Commands

## Detection Engine

```
hollow_detect.exe [options]
```

| Flag | Description |
|---|---|
| `-p <pid>` | Scan a single process by PID |
| `-v` | Verbose output showing per-check debug info |
| `-a` | Print all processes including clean ones |
| `-j <file>` | Write JSON report to file |
| `-l <file>` | Write log to file |
| `-h` | Show help |

### Examples

```bat
REM Scan all processes
hollow_detect.exe

REM Scan all processes and save a JSON report
hollow_detect.exe -j report.json

REM Scan a single process by PID
hollow_detect.exe -p 4812

REM Verbose scan with log file
hollow_detect.exe -v -l scan.log

REM Print every process including clean ones
hollow_detect.exe -a

REM Full output with both JSON and log
hollow_detect.exe -v -a -j report.json -l scan.log
```

## Test Harness

```
test_hollow.exe [options]
```

| Flag | Description |
|---|---|
| `--live` | Also run a full live system scan at the end |

### Examples

```bat
REM Run all tests
test_hollow.exe

REM Run all tests including live scan
test_hollow.exe --live
```

## Attack Demo

```
gcc .\hollower2.c -o halo -liphlpapi

.\halo.exe C:\WINDOWS\system32\notepad.exe <path_to_payload.bin>
```

| Argument | Description |
|---|---|
| `<target_process>` | Full path to the legitimate host executable |
| `<payload.bin>` | Raw binary payload file to inject |

### Example

```bat
hollow_attack.exe C:\Windows\System32\notepad.exe payload.bin
```

> Only run this in an isolated lab environment on a machine you own.
