# Installation

## Requirements

- Windows 10 or Windows 11 (64-bit)
- MinGW-w64 or MSVC (Visual Studio)
- Administrator rights recommended

## Install MinGW-w64

Download from https://www.mingw-w64.org or via winget:

```bat
winget install mingw
```

Verify the install:

```bat
gcc --version
```

## Clone the Repository

```bat
git clone https://github.com/y0urk4rma/Cybersecurity-Hackathon-26.git ./
```

## Dependencies

No external packages needed. All libraries used ship with Windows:

| Library | Used For |
|---|---|
| `ntdll` | NT process and thread query APIs |
| `psapi` | Process memory and image path APIs |
| `advapi32` | Registry access and privilege elevation |
| `iphlpapi` | Network adapter info (attack module only) |

