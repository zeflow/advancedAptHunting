# Advanced APT Hunting – Participant Exercise Guide

Welcome to the **Advanced APT Hunting** workshop.

This guide is your **hands-on companion** during the lab. You will use it to drive your investigation in Splunk, form hypotheses, pivot through data, and gradually build a story of what an adversary may have done.

Threat hunting is **not** about following steps to a predefined answer. It is about curiosity, pattern recognition, and knowing when to dig deeper.

To stay true to the original workshop, this guide follows the **original exercise numbering (Exercise 1–24)** from the slides.
However, the **structure and flow** follow a **hunt-based approach**:

* exercises build on one another
* early exercises establish leads
* later exercises deepen, pivot, and validate

Each exercise:

* represents a **single hunting action**
* aligns to one or more **MITRE ATT&CK techniques**
* includes a **starting search** taken directly from the workshop slides

Use the starting search to get oriented, then adapt and extend it as your investigation evolves.

---

## How to Use This Guide

For each exercise:

1. Read the **hypothesis** to understand what type of behavior you are hunting for.
2. Run the **starting search** to establish an initial view of the data.
3. Use the **questions and hints** to guide pivots and refinements.
4. Follow the data when something looks unusual — even if it takes you outside the current exercise.

You are encouraged to keep notes, revisit earlier searches, and move back and forth between exercises as new leads emerge.

---

## Exercise 1 – Scheduled Task Abuse (Persistence)

### Hypothesis

An adversary may use Windows Scheduled Tasks to establish persistence or perform remote execution.

### MITRE ATT&CK

* T1053.005 – Scheduled Task / Job

### Starting Search

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process_exec=schtasks.exe
| stats dc(host) values(host) values(user) count by CommandLine ParentCommandLine
| sort - count

```

### Investigation Questions & Hints

* Which users are creating scheduled tasks?
  *Hint:* Focus on the user context of `schtasks.exe` executions.
* On which systems are tasks being created?
  *Hint:* Compare servers and workstations — do the patterns make sense?
* Do any task names, paths, schedules, or switches stand out as outliers?
  *Hint:* Look for uncommon names, unusual folders, or rare scheduling options.
* What command-line switches are being used?
  *Hint:* Break the command line apart and interpret `/TN`, `/TR`, `/RU`, and `/SC`.
* What parent process created the scheduled task?
  *Hint:* Ask whether the parent process would normally create tasks in your environment.

---

## Exercise 2 – Asset & Identity Contextualization

### Hypothesis

Suspicious activity becomes more meaningful when enriched with business and identity context.

### Starting Point

Use the hosts and users identified in **Exercise 1**.

### Data to Explore

* Enterprise Security Assets & Identities

### Investigation Questions & Hints

* What business unit is each identified host associated with?
  *Hint:* High-value or infrastructure systems typically warrant more scrutiny.
* Who owns the system and what is its priority?
  *Hint:* Compare expectations for servers versus user workstations.
* What IP address is assigned to the host?
  *Hint:* You may reuse this information when pivoting to network data later.
* When did the associated users last complete security awareness training?
  *Hint:* Context does not prove intent, but it informs risk.

---

## Exercise 3 – Script Execution via WScript

### Hypothesis

Adversaries may abuse `wscript.exe` to execute JavaScript as part of execution or persistence.

### MITRE ATT&CK

* T1059.007 – Command and Scripting Interpreter: JavaScript

### Starting Search

```spl
WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine=*<insert string here>*

```

### Investigation Questions & Hints

* Is `wscript.exe` executing `.js` files?
  *Hint:* Look closely at the full command line, not just the process name.
* From which directories are scripts being executed?
  *Hint:* User profile paths are often more suspicious than system directories.
* Which users and systems are involved?
  *Hint:* Repeated activity across systems can indicate broader compromise.
* What parent processes spawned `wscript.exe`?
  *Hint:* Consider whether the parent process aligns with legitimate scripting use.
* Are these executions rare or common in your environment?
  *Hint:* Rarity often makes strong hunting leads.

---

## Exercise 4 – Privilege Escalation via Fodhelper

### Hypothesis

An adversary may bypass User Account Control (UAC) using `fodhelper.exe` to elevate privileges.

### MITRE ATT&CK

* T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control

### Starting Search

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" fodhelper.exe
```

### Investigation Questions & Hints

* Is `fodhelper.exe` acting as a parent process?
  *Hint:* This is uncommon during normal system behavior.
* What child processes does it spawn?
  *Hint:* Scripting engines and other LOLBins are strong indicators.
* How frequently does this occur and over what time window?
  *Hint:* Repeated executions may indicate loss and re-gain of privileges.
* Are executions tied to the same `LogonGuid`?
  *Hint:* Session-level grouping often reveals intent.

---

## Exercise 5 – Living-off-the-Land Tool Abuse

### Hypothesis

Legitimate Windows binaries may be abused to collect, stage, and prepare data for exfiltration.

### MITRE ATT&CK

* T1005 – Data from Local System
* T1560 – Archive Collected Data

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" host=mvalitus-l ProcessGuid IN ({ebf7a186-2306-5f3c-5506-000000001c00}, {ebf7a186-2ff9-5f3c-360a-000000001c00})
| table _time EventCode CommandLine ParentCommandLine parent_process_exec user ProcessGuid LogonGuid
| sort + _time

```

### Investigation Questions & Hints

* Do you see unexpected execution chains involving native Windows binaries?
  *Hint:* Focus on the sequence of processes, not isolated events.
* Are files or archives being created?
  *Hint:* Compression utilities and password-protected archives are strong staging indicators.
* Are registry run keys or other persistence mechanisms established?
  *Hint:* Persistence often follows privilege escalation.
* What does the overall timeline of activity look like?
  *Hint:* Timelines often reveal intent more clearly than individual events.

---

## Exercise 6 – Lateral Tool Transfer over SMB

### Hypothesis

An adversary may move tools or data between compromised systems using SMB.

### MITRE ATT&CK

* T1570 – Lateral Tool Transfer

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" host=mvalitus-l
[| search source="wineventlog:microsoft-windows-sysmon/operational" host=mvalitus-l LogonGuid={ebf7a186-1b5e-5f3c-3e36-080000000000}
| stats count by ProcessGuid | fields - count ]
| stats count by EventDescription EventCode
| sort - count
```

### Investigation Questions & Hints

* Which internal systems communicate most frequently over SMB?
  *Hint:* Start with RFC1918-to-RFC1918 traffic.
* Are administrative shares (for example `C$`) being accessed?
  *Hint:* These are rarely required for routine user activity.
* What files, directories, or paths are being enumerated or transferred?
  *Hint:* Enumeration often precedes file transfer.
* Does one system consistently act as the source of activity?
  *Hint:* This may indicate the initial point of compromise.

---

## Exercise 7 – ATT&CK Mapping & Operationalization

### Hypothesis

A hunt delivers value when findings are translated into detection and response improvements.

### Starting Point

Use the findings from **Exercises 1–6**.

#starting search

```
source="wineventlog:microsoft-windows-sysmon/operational" host=mvalitus-l
[| search source="wineventlog:microsoft-windows-sysmon/operational" host=mvalitus-l LogonGuid={ebf7a186-1b5e-5f3c-3e36-080000000000}
| stats count by ProcessGuid | fields - count ]
| stats count by EventDescription EventCode
| sort - count

```

### References

* [https://attack.mitre.org/](https://attack.mitre.org/)
* [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)

### Reflection Questions

* Which ATT&CK techniques and sub-techniques did you observe with evidence?
* Which expected techniques were not observed?
* What data or visibility gaps did you encounter?
* How could these findings be operationalized in Splunk Enterprise Security?

---

## Exercise 8 – Process Lineage Validation

### Hypothesis

Suspicious behavior observed earlier may become clearer when validating full process lineage.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" ProcessGuid=<process_guid>
| table _time EventCode process_exec parent_process_exec CommandLine ParentCommandLine user LogonGuid
| sort _time
```

### Investigation Questions & Hints

* Does the parent-child relationship make sense for normal system behavior?
  *Hint:* Focus on unexpected parents spawning administrative or scripting tools.
* Is this process part of a longer execution chain?
  *Hint:* Look for multiple children spawned in short succession.

---

## Exercise 9 – Binary Legitimacy Check (msinfo32)

### Hypothesis

A legitimate Windows binary may be abused or executed in an unusual context.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" process_exec=msinfo32.exe
| table _time user host CommandLine ParentCommandLine Hashes Company OriginalFileName
```

### Investigation Questions & Hints

* Is the binary signed and expected on this system?
  *Hint:* Compare Company and OriginalFileName fields.
* Is msinfo32 executed interactively or scripted?
  *Hint:* Parent process context is key.

---

## Exercise 10 – Micro Time-Window Analysis

### Hypothesis

Short-lived malicious activity may only be visible when narrowing the time range.

### Event Times

* **2026-02-03 03:10:30 – 2026-02-03 03:10:35**
* **2026-02-03 04:12:46 – 2026-02-03 04:12:49**

### Instructions

Use the **Time Picker** and set it to **Between** for each window.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" host=<target_host> EventCode=1
```

### Investigation Questions & Hints

* What processes start and stop within this narrow window?
  *Hint:* Even a single event can be meaningful here.
* Are similar patterns visible in both windows?

---

## Exercise 11 – Associated Sysmon Event Pivot

### Hypothesis

Related Sysmon events can provide additional context for the same process.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" ProcessGuid=<process_guid>
| table _time EventCode EventDescription TargetFilename
```

### Investigation Questions & Hints

* Do you observe file creation or registry modification events?
  *Hint:* Look for EventCode 11 or 13.

---

## Exercise 12 – WMI Execution Validation

### Hypothesis

WMI may be used to execute processes remotely or stealthily.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" ParentImage=*WmiPrvSE.exe*
| table _time user host CommandLine ParentCommandLine ProcessGuid LogonGuid
```

### Investigation Questions & Hints

* Are child processes spawned that should not normally originate from WMI?
* Does the timing align with earlier suspicious activity?

---

## Exercise 13 – Logon Session Pivot

### Hypothesis

Grouping events by logon session can reveal attacker activity boundaries.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" LogonGuid=<logon_guid>
| table _time EventCode process_exec parent_process_exec CommandLine
| sort _time
```

### Investigation Questions & Hints

* Does the session show a clear start and end?
* Are multiple suspicious processes linked to the same session?

---

## Exercise 14 – Full Session Reconstruction

### Hypothesis

Reconstructing a full session timeline reveals intent and sequence.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" LogonGuid=<logon_guid>
| sort _time
```

### Investigation Questions & Hints

* Can you identify distinct phases (initial execution, escalation, staging)?

---

## Exercise 15 – Detailed Timeline Review

### Hypothesis

Detailed timelines help separate benign from malicious activity.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" ProcessGuid=<process_guid>
| table _time EventCode process_exec parent_process_exec user
| sort _time
```

### Investigation Questions & Hints

* Are there gaps or bursts of activity?
* Does the sequence match known attack patterns?

---

## Exercise 16 – Service Binary Analysis (spoolsv.exe)

### Hypothesis

Service binaries may be abused to execute attacker-controlled code.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" process_exec=spoolsv.exe
| table _time user host CommandLine ParentCommandLine Hashes Company
```

### Investigation Questions & Hints

* Is spoolsv.exe executing with unexpected arguments?
* Is it launched outside of normal service startup?

---

## Exercise 17 – Service Execution Behavior

### Hypothesis

Abnormal service execution patterns may indicate abuse.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" process_exec=spoolsv.exe
| stats earliest(_time) latest(_time) values(CommandLine) by LogonGuid ParentCommandLine
```

### Investigation Questions & Hints

* Is execution repeated or one-off?

---

## Exercise 18 – File Creation Validation (node.js)

### Hypothesis

File creation may indicate staging or tool deployment.

### Starting Search

```spl
source="wineventlog:microsoft-windows-sysmon/operational" EventCode=11 TargetFilename=*node.js*
| table _time TargetFilename ProcessGuid
```

### Investigation Questions & Hints

* Was node.js expected on this host?
* Which process created the file?

---

## Exercise 19 – SMB Activity Overview

### Hypothesis

Increased SMB activity may indicate lateral movement or data access.

### Starting Search

```spl
sourcetype=stream:smb
| stats count by src_ip dest_ip
| sort - count
```

---

## Exercise 20 – SMB Flow Context

### Hypothesis

Individual SMB flows can reveal intent.

### Starting Search

```spl
sourcetype=stream:smb
| stats values(filename) values(path) values(command) by flow_id src_ip dest_ip
```

---

## Exercise 21 – SMB Flow Detail

### Hypothesis

Detailed SMB flows validate lateral movement.

### Starting Search

```spl
sourcetype=stream:smb flow_id=<flow_id>
| table _time src_ip dest_ip command filename path filesize
```

---

## Exercise 22 – Windows Security Log Validation

### Hypothesis

Security logs can confirm access to sensitive objects.

### Starting Search

```spl
source="XmlWinEventLog:Security" EventCode=4663
| table _time host user ObjectName AccessMask ProcessName
```

---

## Exercise 23 – MITRE ATT&CK Mapping

### Hypothesis

Observed behavior can be mapped to ATT&CK techniques.

### Approach

Map confirmed actions to techniques and sub-techniques using ATT&CK Navigator.

---

## Exercise 24 – Operationalization

### Hypothesis

Hunting results should improve detection and response.

### Outcome

Translate findings into:

* detections
* dashboards
* risk-based alerting
* data onboarding improvements

---

## Final Thoughts

Threat hunting is iterative and exploratory. You may confirm some hypotheses, partially confirm others, or disprove them entirely. All of these outcomes are valid.

Your goal is not perfection — it is understanding.
