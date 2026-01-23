# Advanced APT Hunting – Participant Exercise Guide

Welcome to the **Advanced APT Hunting** workshop.

This guide is your **hands-on companion** during the lab. You’ll use it to drive your investigation in Splunk, form hypotheses, pivot through data, and gradually build a story of what an adversary may have done.

Threat hunting is **not** about following steps to a predefined answer. It is about curiosity, pattern recognition, and knowing when to dig deeper.

Each exercise below represents a **complete hunt**, aligned to one or more **MITRE ATT&CK techniques**. Each exercise includes a **starting search** taken directly from the workshop slides. Use these searches to get oriented, then adapt and extend them as your investigation evolves.

---

## How to Use This Guide

For each exercise:

1. Read the **hypothesis** to understand what type of behavior you are hunting for.
2. Run the **starting search** to establish an initial view of the data.
3. Use the **questions and hints** to guide pivots and refinements.
4. Follow the data when something looks unusual — even if it takes you outside the original exercise.

You are encouraged to keep notes, revisit earlier searches, and jump between exercises as new leads emerge.

---

## Exercise 1 – Scheduled Task Abuse (Persistence)

### Hypothesis

An adversary may use Windows Scheduled Tasks to establish persistence or perform remote execution.

### MITRE ATT&CK

* T1053.005 – Scheduled Task / Job

### Starting Search

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process_exec=schtasks.exe
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
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 CommandLine=*wscript*
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
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=<suspicious_host>
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
sourcetype=stream:smb
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

Use the findings from Exercises 1–6.

### References

* [https://attack.mitre.org/](https://attack.mitre.org/)
* [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)

### Reflection Questions

* Which ATT&CK techniques and sub-techniques did you observe with evidence?
* Which expected techniques were not observed?
* What data or visibility gaps did you encounter?
* How could these findings be operationalized in Splunk Enterprise Security?

---

## Final Thoughts

Threat hunting is iterative and exploratory. You may confirm some hypotheses, partially confirm others, or disprove them entirely. All of these outcomes are valid.

Your goal is not perfection — it is understanding.
