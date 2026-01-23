# Advanced APT Hunting – Exercise Guide

Welcome to the **Advanced APT Hunting** workshop.

This document is your **participant handout**. You will use it throughout the workshop to guide your hands-on investigation in Splunk. Each exercise represents a **complete threat hunt**, aligned to MITRE ATT&CK techniques.

You are not expected to find a single “right answer”. The goal is to:

* Form and test hypotheses
* Explore the data you have available
* Pivot when something looks interesting
* Build a clear story of what happened

Hints are provided to help you get started, but you are encouraged to explore beyond them.

---

## Exercise 1 – Scheduled Task Abuse (Persistence)

– Scheduled Task Abuse (Persistence)

**Hypothesis**
An adversary may use Windows Scheduled Tasks to establish persistence or perform remote execution.

**MITRE ATT&CK**

* T1053.005 – Scheduled Task / Job

**Primary Data Sources**

* `WinEventLog:Microsoft-Windows-Sysmon/Operational` (EventCode=1)

**Investigation Questions & Hints**

* Which users are creating scheduled tasks?
  *Hint:* Focus on `schtasks.exe` executions and look at the user context.
* On which systems are tasks being created?
  *Hint:* Group by host and compare workstations vs servers.
* Are there task names, paths, schedules, or switches that stand out as outliers?
  *Hint:* Look for unusual task names, uncommon folders, or rare scheduling options.
* What command-line switches are used during task creation?
  *Hint:* Break apart the command line to understand what `/TR`, `/TN`, `/RU`, and `/SC` are doing.
* What parent process is responsible for creating the scheduled task?
  *Hint:* Ask yourself whether the parent process makes sense for legitimate administration.

---

## Exercise 2 – Asset & Identity Contextualization

**Hypothesis**
Suspicious activity becomes more meaningful when enriched with business and identity context.

**Primary Data Sources**

* Enterprise Security Assets & Identities

**Investigation Questions & Hints**

* What business unit is each identified host associated with?
  *Hint:* High-value or infrastructure systems usually deserve more scrutiny.
* Who owns the system and what is its priority?
  *Hint:* Compare server vs workstation priorities.
* What IP address is assigned to the host?
  *Hint:* This may help later when pivoting to network data.
* When did the associated users last complete security awareness training?
  *Hint:* Consider whether user behavior aligns with their role and training history.

---

## Exercise 3 – Script Execution via WScript

**Hypothesis**
Adversaries may abuse `wscript.exe` to execute JavaScript for execution and persistence.

**MITRE ATT&CK**

* T1059.007 – Command and Scripting Interpreter: JavaScript

**Primary Data Sources**

* Sysmon – Process Creation

**Investigation Questions & Hints**

* Is `wscript.exe` executing JavaScript files?
  *Hint:* Look for `.js` files in the command line.
* From which directories are scripts being executed?
  *Hint:* User profile directories are more suspicious than system paths.
* Which users and systems are involved?
  *Hint:* Are the same users or hosts recurring?
* What processes spawned `wscript.exe`?
  *Hint:* Does the parent process align with normal scripting usage?
* Are these executions rare or common in the environment?
  *Hint:* Rarity often makes good hunting leads.

---

## Exercise 4 – Privilege Escalation via Fodhelper

**Hypothesis**
An adversary may bypass User Account Control (UAC) using `fodhelper.exe` to elevate privileges.

**MITRE ATT&CK**

* T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control

**Primary Data Sources**

* Sysmon – Process Creation

**Investigation Questions & Hints**

* Is `fodhelper.exe` acting as a parent process?
  *Hint:* `fodhelper.exe` rarely spawns child processes in normal usage.
* What child processes does it spawn?
  *Hint:* Pay attention to scripting engines or LOLBins.
* How frequently and over what time window does this occur?
  *Hint:* Repeated execution may indicate privilege loss and re-escalation.
* Are multiple executions tied to the same logon session (`LogonGuid`)?
  *Hint:* Use session context to group related activity.

---

## Exercise 5 – Living-off-the-Land Tool Abuse

**Hypothesis**
Legitimate Windows binaries may be abused to collect, stage, and prepare data for exfiltration.

**MITRE ATT&CK**

* T1105 – Ingress Tool Transfer
* T1005 – Data from Local System
* T1560 – Archive Collected Data

**Primary Data Sources**

* Sysmon – Process Creation
* Sysmon – File Creation
* Sysmon – Registry Events

**Investigation Questions & Hints**

* Are Microsoft binaries being used in unexpected execution chains?
  *Hint:* Focus on the *sequence* of processes, not just individual events.
* Are files or archives being created as part of these chains?
  *Hint:* Look for compression utilities or password-protected archives.
* Are registry run keys or other persistence mechanisms established?
  *Hint:* Persistence often appears shortly after privilege escalation.
* What does the full execution timeline look like?
  *Hint:* A timeline often reveals intent more clearly than individual events.

---

## Exercise 6 – Lateral Tool Transfer over SMB

**Hypothesis**
Adversaries may move tools and files between compromised systems using SMB.

**MITRE ATT&CK**

* T1570 – Lateral Tool Transfer

**Primary Data Sources**

* Stream for Splunk – SMB (`stream:smb`)

**Investigation Questions & Hints**

* Which internal systems are communicating most frequently over SMB?
  *Hint:* Start with RFC1918-to-RFC1918 communication.
* Are administrative shares (e.g. `C$`) being accessed?
  *Hint:* Admin shares are rarely needed for day-to-day user activity.
* What files, directories, or paths are being enumerated or transferred?
  *Hint:* Directory listing often precedes file transfer.
* Is one system consistently acting as the source of activity?
  *Hint:* This may indicate the initial point of compromise.

---

## Exercise 7 – ATT&CK Mapping & Operationalization

**Hypothesis**
Threat hunting is most valuable when results are translated into detection coverage and operational improvements.

**Primary References**

* [https://attack.mitre.org/](https://attack.mitre.org/)
* [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)

**Investigation Questions & Hints**

* Which ATT&CK techniques and sub-techniques did you observe during the hunt?
  *Hint:* Focus on what you have evidence for, not assumptions.
* Which expected techniques were *not* observed?
  *Hint:* Absence can indicate detection or data gaps.
* What data or visibility gaps did you encounter?
  *Hint:* Missing data is a finding, not a failure.
* How could these findings be operationalized in Splunk Enterprise Security?
  *Hint:* Think detections, risk-based alerting, dashboards, or data onboarding.

---

**Reminder:** Hunting is iterative. You may not confirm every hypothesis — and that is expected.
