// #show heading.where(level: 1): set text(size: 20.5pt)
// #show heading.where(level: 2): set text(size: 17.5pt)
// #show heading.where(level: 3): set text(size: 15pt)
// #show heading.where(level: 4): set text(size: 13pt)
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
  // #text(size: 16pt, fill: black)[
  //   *Course Code: 23CSE313*
  // ]
  #v(-6pt)
  #text(size: 20pt, fill: black)[
    *Threat Model Document*
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
= Executive Summary

This document outlines the threat model for Problem Statement \#22 - EDR Evasion via Process Hollowing Detection. The goal of this document is to identify what is being protected, who the attacker is, how the attack is carried out, and how our solution addresses the threat. The attack technique in focus is Process Hollowing (MITRE ATT&CK: T1055.012), a memory-based evasion technique used by malware to hide inside legitimate Windows processes.

= System Overview

- *Environment:* On-premises enterprise setup with physical or virtualised Windows servers
- *Target OS:* Windows 10 / Windows Server 2019
- *Network:* Isolated LAN with no direct internet egress from servers
// - *Existing Security Tools:* SIEM solutions such as Splunk or IBM QRadar receiving logs via syslog/CEF
- *Virtualization:* VMware / Hyper-V based server infrastructure
- *Identity Management:* Active Directory / LDAP

= Asset Identification

#table(
  columns: (auto, auto, auto),
  // inset: 10pt,
  [*Asset*], [*Type*], [*Why It Matters*],
  [Windows System Processes], [Software], [Trusted by OS - prime targets for hollowing],
  [User Credentials], [Data], [Accessible once attacker is inside a trusted process],
  [Active Directory], [Infrastructure], [Compromise leads to full network takeover],
  [Internal Network], [Infrastructure], [Lateral movement becomes possible post-compromise],
  // [SIEM Logs], [Data], [Tampered logs can hide attacker activity],
  [Sensitive Enterprise Files], [Data], [Accessible through hollowed trusted processes],
)

= Threat Actor Profile

#table(
  columns: (auto, auto),
  // inset: 10pt,
  [*Attribute*], [*Details*],
  [Actor Type], [External attacker or insider threat],
  [Motivation], [Data theft, credential harvesting, ransomware deployment],
  [Capability Level], [Intermediate to Advanced],
  [Initial Access Method], [Phishing, malicious attachments, compromised user accounts],
  [Privileges Required], [Admin-level privileges enough to spawn processes],
  [Known Malware Using This Technique], [Agent Tesla],
)
\ \
= Attack Flow

+ *Initial Access* - Attacker gains a foothold on the system through a phishing email or malicious attachment
+ *Execution* - Attacker runs a dropper that initiates the process hollowing sequence
+ *Spawn Suspended Process* - A legitimate process like `svchost.exe` or `notepad.exe` is created in a suspended state using `CreateProcess()` with the `CREATE_SUSPENDED` flag
+ *Hollow The Process* - The original executable image is unmapped from memory using `NtUnmapViewOfSection()`
+ *Inject Payload* - Malicious payload is allocated and written into the empty memory space using `VirtualAllocEx()` and `WriteProcessMemory()`
+ *Redirect Execution* - The entry point is redirected to the malicious code using `SetThreadContext()`
+ *Resume Process* - The process is resumed using `ResumeThread()` - it now runs malicious code under the name of a trusted Windows process
+ *Persist and Operate* - The attacker steals credentials, moves laterally, or deploys ransomware - all from within a trusted process

= MITRE ATT&CK Mapping

#table(
  columns: (auto,auto,auto,auto),
  // inset: 10pt,
  [*Technique*], [*ID*], [*Tactic*], [*Relevance*],
  [Process Hollowing], [T1055.012], [Defense Evasion,\ Privilege Escalation], [Core attack technique],
  [Process Injection], [T1055], [Defense Evasion,\ Privilege Escalation], [Parent technique of \ hollowing],
  [Phishing], [T1566], [Initial Access], [Primary delivery method],
  [OS Credential Dumping], [T1003], [Credential Access], [Post-exploitation goal],
  [Lateral Movement via SMB], [T1021.002], [Lateral Movement], [Post-compromise network spread],
  [Masquerading], [T1036], [Defense Evasion], [Malicious code hiding \ under legitimate process name],
)

= Impact Analysis

- *Immediate Impact:* Malicious code executes freely inside a trusted process with no alerts triggered by conventional tools
- *Credential Theft:* Attacker can harvest saved passwords, browser cookies, and Active Directory credentials
- *Lateral Movement:* Using stolen credentials, the attacker can move across the internal network undetected
- *Data Exfiltration:* Sensitive enterprise files and data can be silently copied and sent out
- *Ransomware Deployment:* The hollowed process can be used as a launchpad to deploy ransomware across the network
- *Log Tampering:* Attacker operating inside a trusted process can potentially manipulate or suppress security logs

= Current Security Gaps

- *File-based AV scanners* look for suspicious files on disk - process hollowing leaves no file on disk
- *Signature-based detection* cannot detect this attack as the payload only exists in memory
- *Traditional EDR tools* in on-premises environments primarily monitor file and network activity, not memory integrity
- *SIEM tools alone* cannot catch this - they rely on logs being generated, but no log is generated for in-memory manipulation
- *Slow patch cycles* in on-premises environments mean vulnerabilities that enable initial access remain open longer

= How Our Solution Addresses The Threat

- The detector runs as a lightweight service on the Windows host - no internet connection required
- It monitors *all process creation events* in real time using Windows API hooks
- For every newly created process, it computes the *SHA-256 hash of the on-disk binary*
- It then reads the *in-memory PE headers* of the same running process using `ReadProcessMemory()`
- If the on-disk hash and the in-memory hash *do not match*, an alert is immediately raised
- The alert is formatted in *CEF/syslog* format and forwarded to the existing SIEM for centralized monitoring
- This intervention happens *at step 7 of the attack flow* - the moment the hollowed process is resumed

= Residual Risks

- *False Negatives:* Highly sophisticated attackers may patch only specific memory regions, making the hash difference subtle and harder to detect
- *Privilege Requirement:* The detector itself requires elevated privileges to read process memory - if the attacker has higher privileges, they may be able to terminate the detector
- *Scope Limitation:* The current solution only detects hollowing in newly created processes - hollowing performed on already running processes may be missed
- *No Forensic Capability:* The tool detects live attacks but does not perform forensic analysis of past incidents