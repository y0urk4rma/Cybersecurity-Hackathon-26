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
  \ 
  #text(size: 20pt, fill: black)[
    *Foundations of Cyber Security Hackathon*
  ]
  #v(2em)
  #text(size: 14pt, fill:black,weight: "bold")[
    Done By:
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
```C
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
```
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
- The solution is tested on a controlled Windows VM, not a production system.


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

= System Requirements and Specifications
// #pagebreak()

= Thread Model Used 
// #pagebreak()

= System Architecture 
// #pagebreak()

= Implementation Details 
// #pagebreak()

= Deployment Details
// #pagebreak()

= Results and Testing 
// #pagebreak()

= Limitations and Future Work 
// #pagebreak()

= Conclusion 
// #pagebreak()

= References 
1. #underline[https://www.fortinet.com/blog/threat-research/unmasking-agent-tesla-deep-dive-into-multi-stage-campaign]

2. #underline[https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations]