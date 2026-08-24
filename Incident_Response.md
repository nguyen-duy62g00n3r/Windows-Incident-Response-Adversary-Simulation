# Incident Response
### Incident Context
The incident begins when the SIEM generates an alert indicating a potential modification of a Windows Registry Run Key associated with persistence.
![alert](https://hackmd.io/_uploads/HkI8i62Ifx.png)


After receiving the alert, the SOC and Incident Response team follow a structured investigation process designed to preserve relevant evidence, establish the initial scope of the incident, reconstruct the attack activity, assess its impact, and determine appropriate response actions. The response process is divided into five phases:

1. [**Preparation**](#phase_1): Establish the investigation environment, evidence sources, investigation toolkit, and response methodology.
2. [**Detection & Initial Triage**](#phase_2): Validate the alert, perform an initial assessment, identify the affected asset, and initialize the investigation case.
3. [**Evidence Acquisition & Initial Scoping**](#phase_3):  Preserve relevant evidence, review host and network evidence, and establish the initial scope of the incident.
4. [**Investigation & Analysis**](#phase_4): Correlate evidence, reconstruct the attack timeline, identify attacker activity and objectives, and assess the impact of the incident.
5. [**Containment, Eradication & Recovery**](#phase_5) Contain the compromised environment, remove the attacker's foothold and persistence mechanisms, and restore the affected system to a trusted state.

## 1. Phase 1: Preparation
<div id="phase_1"></div>

The Preparation phase establishes the technical environment, evidence sources, investigation tools, and response methodology required to detect, investigate, and respond to security incidents. The objective of this phase is to ensure that the environment can generate and preserve sufficient telemetry for subsequent incident investigation while maintaining a clear understanding of where each type of evidence originates.

### 1.1 System Architecture

The simulated environment represents a small enterprise network centered around a Windows employee workstation. The workstation communicates with internal services and external networks through a dedicated gateway. The simplified enterprise network architecture is illustrated below.
![image](https://hackmd.io/_uploads/S1z4eZuIfe.png)

The main components are:

- **Windows Workstation :** Represents an employee endpoint within the enterprise environment. It generates endpoint and Windows telemetry used throughout the investigation.
- **Gateway :** Provides network connectivity between the internal workstation and external networks. Network traffic passing through the gateway is captured for subsequent network investigation.
- **SIEM Server (Splunk Enterprise) :** Centrally receives and stores selected endpoint telemetry used for security monitoring, alerting, and incident investigation.

The Windows workstation communicates with the SIEM through the network gateway, while the SIEM server is maintained outside the workstation's private network.

### 1.2 Evidence Sources

The investigation relies on multiple evidence sources collected from both the compromised workstation and the network infrastructure. These sources provide complementary visibility into endpoint activity and network communications.

#### Host Evidence

Host evidence is used to investigate process execution, file activity, registry modifications, PowerShell activity, and other actions occurring on the affected workstation. The primary host evidence sources include:

- Sysmon logs
- Windows Event Logs
- PowerShell Operational Logs
- Filesystem artifacts
- Windows Registry
- filesystem metadata

#### Network Evidence
- Packet captures collected from the network gateway

### 1.3 Investigation Toolkit
The following tools are prepared before the investigation to support evidence review, endpoint analysis, network analysis, and timeline reconstruction : 
- **Splunk Enterprise :** SIEM and centralized log analysis
- **Wireshark :** Network traffic and packet analysis
- **Windows Event Viewer :** Windows event log review
- **Registry Explorer :** Windows Registry examination
- **JournalViewer :** NTFS journal artifact analysis

_Additional tools may be used when required by the investigation._

### 1.4 Response Methodology

The incident response process combines established incident response lifecycle concepts : 
- **NIST Incident Response Lifecycle**
- **Mandiant Investigation Methodology**

These methodologies provide the overall structure for the response process while the subsequent phases define the specific activities performed during the simulated incident.

## 2. Phase 2: Detection & Initial Triage
<div id="phase_2"></div>

The Detection & Initial Triage phase begins when the SIEM generates an alert indicating a potential Registry Run Key modification associated with persistence.

### 2.1 Alert Validation
The investigation begins when the SOC analyst selects **View Results** from the **Actions** column of the corresponding alert in Splunk. This redirects the analyst to the underlying event that triggered the detection.

**Alert:** `Persistence - Windows Registry Run Keys Modification Detected - T1547.001`
![alert_result](https://hackmd.io/_uploads/Bkoehp3IGe.png)


![alert_event_fields](https://hackmd.io/_uploads/SkRzhTnUze.png)

The analyst reviews the key fields of the event to determine whether the alert represents legitimate activity or potentially malicious behavior.

| Field | Value |
| :--- | :--- |
| _time | `08/14/2026 04:53:52.686 PM` |
| EventCode | `13` |
| ProcessId | `5744` |
| ComputerName | `DESKTOP-O7F02KF` |
| User | `DESKTOP-O7F02KF\john` |
| Image | `C:\Windows\System32\notepad.exe` |
| TargetObject | `HKU\S-1-5-21-4207412933-3579095289-3878667832-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftOffice` |
| Details | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& 'C:\Users\john\AppData\Local\Microsoft\Windows\update.exe'"` |

The event indicates that `notepad.exe` performed a Registry value modification under the user's `CurrentVersion\Run` key. The created value, `MicrosoftOffice`, is configured to execute `update.exe` through PowerShell with a hidden window and execution policy bypass. The combination of a Registry Run Key modification, an executable located under the user's profile, and a hidden PowerShell command is considered suspicious and inconsistent with expected Notepad activity.

The alert is therefore considered a legitimate and security event, and is escalated for further investigation.

### 2.2 Initial Assessment
#### Incident Severity
The incident is initially classified as **high severity**. The severity is based on the presence of a potential persistence mechanism that executes an executable from a user-writable directory and uses PowerShell with suspicious execution parameters.

#### Affected Assets
The initially affected asset is identified as:

- **Computer Name:** `DESKTOP-O7F02KF`
- **User:** `DESKTOP-O7F02KF\john`

At this stage, `DESKTOP-O7F02KF` is treated as the primary affected asset. The possibility of additional affected users remains open and will be evaluated during the scoping phase.

#### Initial Hypothesis
Based on the alert and the underlying Sysmon event, the initial hypothesis is:
> A suspicious process, identified as `notepad.exe`, modified a Registry Run Key to establish persistence by configuring PowerShell to execute `update.exe` when the user logs on.

### 2.3 Case Initialization
An investigation case is opened for the suspected compromise of `DESKTOP-O7F02KF`. The case records the initial alert, affected assets, user, initial severity, initial hypothesis, and the relevant alert timestamp. Subsequent evidence and investigation findings are associated with this case throughout the incident response process.

## 3. Phase 3: Evidence Acquisition & Initial Scoping

<div id="phase_3"></div>

Following the initial alert validation and assessment, the investigation proceeds to evidence acquisition and initial scoping. The primary objectives of this phase are to preserve relevant evidence, review available host and network telemetry, identify potentially affected entities, and establish an initial understanding of the incident scope.
### 3.1 Evidence Preservation
The affected workstation DESKTOP-O7F02KF is isolated from the private network to prevent further attacker activity and preserve the state of the compromised environment. The isolation is performed before extensive investigation activities are conducted on the workstation. The following principles are applied during evidence acquisition:

- Collect relevant artifacts without modifying the original evidence where possible.
- Minimize software installation and other changes to the compromised workstation.
- Preserve collected artifacts for subsequent analysis.
- Perform detailed analysis on collected copies and minimize directly modifying the original artifacts on the workstation.

>Memory acquisition is intentionally excluded from the scope of this project.

### 3.2 Host Evidence Review
Host  evidence is reviewed from two locations: centralized telemetry available on SIEM server and artifacts collected directly from the affected workstation. The purpose of this review is to identify potentially relevant processes, files, Registry modifications, and PowerShell activity surrounding the initial alert and to establish a preliminary host activity window.

#### SIEM Telemetry Review
The initial review begins from the Sysmon Event ID 13 that triggered the alert. The investigation pivots from the triggering event using process identifiers and related Registry events to identify additional activities associated with the alert.

The following approaches are used during the initial review:

- Review related Sysmon Registry events (Event ID 12, 13, and 14) associated with the alert.
- Pivot on the process identifier and parent process identifier associated with the triggering event.
- Search for events containing the suspicious executable paths:
```
C:\Users\john\AppData\Local\Microsoft\Windows\update.exe
C:\Windows\System32\notepad.exe
```
- Use SPL table queries to summarize important process and relationship fields, including:
```
ProcessId
ParentProcessId
Image
ParentImage
TargetImage
CommandLine
```
- Identify additional process identifiers and executable paths associated with the suspicious activity.

<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/rJyD0638zg.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/Sk3P063Uzg.png" width="100%"><br>
    </td>
  </tr>
</table>
<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/BJ3-AT38fe.png" width="100%"><br>
    </td>
  </tr>
</table>                                                              
                                                        
The initial review identifies several process identifiers associated with the triggering event, including `8444`, `7364`, `5824`, `5048`. It also identifies the following executable path as potentially relevant:
```
C:\Users\john\Downloads\Office Security Update.exe
```
During this preliminary review, no additional suspicious Registry modification relevant to the initial alert is identified beyond the Run Key modification already observed.

The available Sysmon telemetry returned by the SPL queries establishes an initial host activity window from:
**2026-08-14 16:43:36.228 -> 2026-08-14 16:58:21.203**

This time window is treated as a preliminary host evidence window and can be expanded during subsequent investigation if earlier or later related activity is identified.
 
#### Endpoint Evidence Review
Relevant artifacts are then reviewed directly on the affected workstation. Because the alert identifies a Registry Run Key modification, the following persistence locations are reviewed:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

%AppData%\Microsoft\Windows\Start Menu\Programs\Startup
%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup
```
The `MicrosoftOffice` value is identified under:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
with a value associated with the execution of `update.exe` through PowerShell.
![registry_run_key_modification](https://hackmd.io/_uploads/BySDhboIfg.png)

File system artifacts are subsequently reviewed for the files identified during the initial SIEM review. The following file is present:
![[artifact]update.exe_ presence](https://hackmd.io/_uploads/r1TEGC2IMl.png)

However, the `Office Security Update.exe` file is no longer present on the workstation. The absence of this executable is recorded as a preliminary finding. The circumstances surrounding the missing file are reserved for further investigation in Phase 4.

The integrity and metadata of the system executable `C:\Windows\System32\notepad.exe` are also reviewed. The executable is located in the expected Windows system directory and its file characteristics are consistent with a legitimate system binary. Therefore, this executable is not treated as a disguised program at this stage.
![notepad_characteristics](https://hackmd.io/_uploads/BkwUEMs8Mx.png)

Additional remote command execution artifacts are identified on the workstation. These artifacts are preserved for subsequent correlation and detailed analysis in Phase 4. 
<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/ryJiN03Ifx.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/r1aiNAhUzx.png" width="100%"><br>
</table>
    
Based on the timestamps of the collected endpoint artifacts, primarily PowerShell Operational logs, the preliminary endpoint review identifies relevant artifacts within the following broader activity period:
**2026-08-14 16:45:44.556 -> 2026-08-14 16:53:52.644**

This endpoint time window is maintained as a preliminary boundary and can be expanded when additional evidence is correlated during the investigation.

### 3.3 Network Evidence Review
Network evidence is reviewed using packet captures collected at the network gateway. The initial network review is performed to identify the primary external destinations associated with the affected workstation and to establish a preliminary network activity window. The workstation is observed communicating most frequently with ` 192.168.232.2`
![[artifact]most_frequent_comunication](https://hackmd.io/_uploads/HyChOC3IMe.png)
    
The observed communications primarily involve TCP traffic on port `8888` and `443`
![[artifact]ports_used_in_suspicious_comunication](https://hackmd.io/_uploads/BJm6_Rh8Ml.png)

The review of the available network traffic also identifies no additional internal hosts communicating with `192.168.232.2` within the examined capture period.

The network observation window is established using packets whose source or destination IP address is `192.168.232.2`. The preliminary network evidence window is defined as:
**2026-08-14 16:43:35.762 -> 2026-08-14 16:58:20.757**

This represents the initial network observation window and can be expanded during Phase 4 if additional related communication is identified outside this interval.

### 3.4 Initial Scoping
The results of the initial host and network evidence reviews are consolidated to establish the preliminary scope of the incident. At this stage, the objective is to identify the assets, users, processes, files, PowerShell activities, and IP address that require further investigation. 

Based on the evidence currently available, the initial scope consists of :
- **Affected workstation:** `DESKTOP-O7F02KF`
- Associated user: `john`
- **Relevant process IDs:** `8444`, `7364`, `5824`, `5048`, `5744`
- **Relevant executables:** `Office Security Update.exe`, `update.exe` and `notepad.exe`
- **Persistence artifact:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftOffice`
- **PowerShell Operational events:** Multiple events associated with remote command execution
- **External IP address:** `192.168.232.2`
- **Network ports:** `8888` and `443`
- **Initial time window:** Base on the host and network time window, the consolidated time window for this incident spans from approximately `16:43:35` to `16:58:21` on August 14, 2026 
    
No additional affected workstation or internal host is identified within the currently available evidence.

## 4. Phase 4: Investigation & Analysis   
<div id="phase_4"></div>
    
Following the initial scoping phase, the investigation proceeds to detailed analysis of the identified host, process, PowerShell, filesystem, Registry, and network evidence. This phase aims to reconstruct the sequence of attacker activity, correlate evidence from multiple sources, identify the attacker's objectives, and assess the impact of the incident. 

The investigation follows a hypotheical approach. Each significant finding is used as a pivot to identify related evidence, validate the finding through independent telemetry where possible, and determine whether the scope of the incident should be expanded.
    
### 4.1 Investigation Strategy & Anchor Event Selection
#### 4.1.1 Investigation Question
The initial scope provides several entities that require further investigation:

- `DESKTOP-O7F02KF`
- User `john`
- `Office Security Update.exe`
- `update.exe`
- `notepad.exe`
- Process IDs `8444`, `7364`, `5824`, `5048` and `5744`
- Registry Run Key `MicrosoftOffice`
- External IP `192.168.232.2`
- Ports `443` and `8888`
- Multiple PowerShell Operational events
    
The primary investigation questions are:

- What process initiated the activity associated with the alert?
- What is the relationship between `notepad.exe`, `Office Security Update.exe`, and `update.exe`?
- How was `update.exe` introduced to the workstation?
- Did the attacker establish any C2 channels?
- If a C2 channel was created then what activities were performed through the channel?
- Did the attacker collect any information from the workstation?
- Was collected data transferred outside the workstation?
- How was persistence established?
- Were artifacts removed after the attack activity?
- Did the incident affect any additional hosts or accounts?
    
#### 4.1.2 Anchor Event Selection
The investigation uses the alert-triggering Sysmon Event ID 13 as the initial anchor event. The event identifies process ID `5744` and the image `C:\Windows\System32\notepad.exe` as the initail anchor point. Because `notepad.exe` was previously verified during Phase 3 to be a legitimate Windows executable located in its expected system directory, the investigation does not initially focus on determining whether the binary itself is malicious. Instead, the investigation focuses on determining what caused notepad.exe to participate in the Registry modification. The two additional suspicious executables identified during initial scoping, `Office Security Update.exe` and `update.exe`, are investigated in parallel because of their potential relationship with the alert-triggering process.

The initial investigation therefore pivots around three executable entities:
- `notepad.exe`
- `Office Security Update.exe`
- `update.exe`
    
#### 4.1.3 Initial Hypotheses
The investigation begins with the following hypotheses:

**Hypothesis 1 – Execution Origin**

`notepad.exe` was involved in the persistence operation because it was used as an execution context for malicious activity.

**Hypothesis 2 – Payload Relationship**

`Office Security Update.exe` and `update.exe` are related to the activity that ultimately resulted in the Registry Run Key modification.

**Hypothesis 3 – External Control**

`update.exe` established communication with external IP address and was used as the primary post compromise execution component.

**Hypothesis 4 – Post Compromise Activity**

A C2 channel was used to perform discovery, collection, persistence, and other attacker-controlled actions on the workstation.

### 4.2 Process and Execution Chain Reconstruction
#### 4.2.1 Alert Process Investigation
The first pivot searches for Sysmon events associated with Process ID `5744`.

At:

**2026-08-14 16:53:52.424**

a Sysmon Event ID 1 identifies the creation of Process ID `5744` with:

Image:
`C:\Windows\System32\notepad.exe`
    
Parent Process ID:
`8444`
    
The parent process is later identified as:

`C:\Users\john\AppData\Local\Microsoft\Windows\update.exe`

This establishes a direct process relationship between update.exe and the notepad.exe process associated with the persistence alert.
![image](https://hackmd.io/_uploads/BJECeaewGl.png)

Shortly afterwards, at:

**2026-08-14 16:53:52.533**

a Sysmon Event ID 11 records the creation of:

`C:\Users\john\AppData\Local\Temp\__PSScriptPolicyTest_fpytzo0r.mdl.ps1`

The filename is consistent with a PowerShell execution policy test artifact.

At this stage, this event is treated as evidence of PowerShell activity occurring in the context of the process, but not as standalone proof that `notepad.exe` directly spawned `powershell.exe`, because no corresponding Sysmon process creation event for `powershell.exe` was identified at this point.
![image](https://hackmd.io/_uploads/Ske02Zaxvfx.png)

At:

**2026-08-14 16:53:52.686**

Sysmon Event ID `13` records the Registry modification that triggered the initial detection:

`HKU\S-1-5-21-4207412933-3579095289-3878667832-1001\
SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftOffice`
![image](https://hackmd.io/_uploads/rJDZXJzPzx.png)

<!--
The associated PowerShell Operational telemetry contains activity related to the execution of a script that establishes persistence.
![image](https://hackmd.io/_uploads/S1lU76gPfx.png)
<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/ByScVpeDzg.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/SJg24plDfx.png" width="100%"><br>
</table>
-->
The sequence demonstrates that the process associated with the alert was operating under the context of `notepad.exe`, while `update.exe` was identified as its parent process.

#### 4.2.2 notepad.exe Investigation
To further investigate the role of the legitimate `notepad.exe` executable, the Sysmon logs are filtered for:
    
`C:\Windows\System32\notepad.exe`

Three relevant Sysmon Event ID 11 events are identified. Each event records the creation of a temporary PowerShell policy-test file by one of the `notepad.exe` processes:
    
| Process ID | Time | Created File |
| :--- | :--- | :--- |
| `5824` | `2026-08-14 16:45:44.405` | `C:\Users\john\AppData\Local\Temp\__PSScriptPolicyTest_2ozqio4o.ens.ps1` |
| `7364` | `2026-08-14 16:47:31.756` | `C:\Users\john\AppData\Local\Temp\__PSScriptPolicyTest_jsvkjbqf.snw.ps1` |
| `5744` | `2026-08-14 16:53:52.533` | `C:\Users\john\AppData\Local\Temp\__PSScriptPolicyTest_fpytzo0r.mdl.ps1` |

<table align="center" width="100%">
  <tr>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/SkYwB1GDMg.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HkJ5rJfPfe.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HkGsSyfPMe.png" width="100%"><br>
    </td>
</table>    

The three events show a repeated pattern in which different `notepad.exe` instances are associated with temporary PowerShell policy test files at three distinct points during the incident. The timestamps correspond closely with the subsequent PowerShell Operational activity associated with Process IDs `5824`, `7364`, and `5744`. This provides a basis for pivoting from the `notepad.exe` processes to PowerShell execution telemetry. The evidence establishes PowerShell activities associated with the three `notepad.exe` processes, but the FileCreate events alone do not establish that `notepad.exe` directly launched `powershell.exe`.

This pivot raises the following investigation question:

- What PowerShell activity occurred within the execution context associated with these three `notepad.exe` processes?

#### 4.2.3 Office Security Update.exe Investigation
The investigation then pivots to:

`C:\Users\john\Downloads\Office Security Update.exe`

5 events are identified as particularly relevant.

At:

**2026-08-14 16:43:35.930**

a Sysmon Event ID 1 records:

ParentImage:
`C:\Windows\explorer.exe`

Image:
`C:\Users\john\Downloads\Office Security Update.exe`

with Process ID `5048`.

The parent process relationship is consistent with direct user execution of the executable.
![image](https://hackmd.io/_uploads/SyAqukGDGl.png)

At:    
    
**2026-08-14 16:43:36.066**

a Sysmon Event ID 11 records the creation of:

`C:\Users\john\AppData\Local\Temp\
__PSScriptPolicyTest_swufhjr0.kht.ps1`
    
![image](https://hackmd.io/_uploads/BJIOtkGPfe.png)


At:

**2026-08-14 16:43:36.228**

a Sysmon Event ID 11 records creation of:

`C:\Users\john\AppData\Local\Microsoft\Windows\update.exe`

![image](https://hackmd.io/_uploads/HkmoYJGwMe.png)

At:

**2026-08-14 16:43:36.700**

a Sysmon Event ID 1 records execution of:

`C:\Users\john\AppData\Local\Microsoft\Windows\update.exe`

with Process ID `8444`.

The Office `Security Update.exe` process is therefore associated with the creation and subsequent execution of update.exe.
![image](https://hackmd.io/_uploads/SJRCYJfvGx.png)

Finally, at:

**2026-08-14 16:43:36.714**

Sysmon Event ID 5 records termination of Process ID `5048`.
![image](https://hackmd.io/_uploads/SJBN9yGPMg.png)


These events establish the relationship between the initial user executed file and the second stage executable.
    
#### 4.2.4 update.exe Investigation
The investigation then pivots to:

`C:\Users\john\AppData\Local\Microsoft\Windows\update.exe`

The search returns 120 Sysmon events. These events are grouped by event type to identify the major behavioral categories.
![image](https://hackmd.io/_uploads/H14Li1GwGx.png)

The most relevant findings are:

**Process Creation**

Three Sysmon Event ID 1 events show `update.exe` creating instances of:

`C:\Windows\System32\notepad.exe`

with Process IDs:
- `5824`
- `7364`
- `5744`

The corresponding timestamps are:

- 16:45:44.280
- 16:47:31.649
- 16:53:52.424

<table align="center" width="100%">
  <tr>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/SkDxakfPGg.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/ByfVayGvfe.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HyjwpkMwMl.png" width="100%"><br>
    </td>
</table> 
    
<div id="notable_directory"></div>
    
A notable change is also observed in the CurrentDirectory field. Earlier process activity is associated with:

`C:\Users\john\Downloads\`

while the process associated with PID `5744` operates with:

`C:\Users\john\AppData\Local\Temp\`

![image](https://hackmd.io/_uploads/HJoXkeGwGx.png)

**Remote Thread Creation**

3 Sysmon Event ID 8 events record remote thread activity associated with `update.exe` and the three `notepad.exe` processes.

<table align="center" width="100%">
  <tr>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HJiWlxMPMe.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HyVXeezPfx.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/B19ExlGvMx.png" width="100%"><br>
    </td>
</table> 

This behavior is consistent with **Process Injection (T1055)**. The available evidence is insufficient to confidently assign a more specific Process Injection sub-technique.

 **Network Connections**

A total of 109 Sysmon Event ID 3 events associated with update.exe are identified.

All observed connections are directed toward:

`192.168.232.2:8888`

![image](https://hackmd.io/_uploads/rk8yblzPzx.png)
This strongly associates `update.exe` with the external IP address identified during the initial scoping phase.

**Process Termination**

At:

**2026-08-14 16:58:21.203**

Sysmon Event ID 5 records termination of Process ID `8444`, corresponding to `update.exe`.
![image](https://hackmd.io/_uploads/H11w-gMDMl.png)

#### 4.2.5 Process and Execution Chain Finding
4.2.5 Process and Execution Chain Finding
The correlated process evidence establishes the following execution sequence.

**User execution**

At approximately **16:43:35**, the user executes:

`Office Security Update.exe`

from the Downloads directory through `explorer.exe`.

**Payload delivery and execution**

The dropper creates:

`update.exe`

under the user's profile and subsequently launches it as Process ID `8444`.

**Post compromise execution**

`update.exe` creates multiple `notepad.exe` processes and subsequently performs remote-thread activity associated with those processes.

The `notepad.exe` processes become associated with PowerShell artifacts and activities at approximately:

- **16:45:44**
- **16:47:31**
- **16:53:52**

The available evidence therefore supports the conclusion that `update.exe` acted as the primary post compromise process and used legitimate `notepad.exe` processes as execution contexts for subsequent activity. The initial question regarding the relationship between `Office Security Update.exe`, `update.exe`, and `notepad.exe` is therefore resolved.

The next investigation question becomes:

> How was `update.exe` introduced to the workstation, and what Powershell activities did the attacker perform on the victim workstation?
    
### 4.3 Network Analysis
The network investigation begins with the conclusions established during Phase 3. The preliminary network review identified:

- `192.168.232.2` as the primary external destination associated with the workstation.
- Port `8888` as the dominant destination port.
- Port `443` as a separate communication channel.
- No additional internal host communicating with `192.168.232.2`.

Rather than immediately investigating individual packets, the network analysis first determines the purpose and behavior of the repeated communication on port 8888.
    
#### 4.3.1 C2 Communication Analysis
 The PCAP is initially filtered for traffic involving:

`192.168.232.2`

and port:

`8888`

<table align="center" width="100%">
  <tr>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/Hy-zrbGPfe.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HJe7SbGwMl.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/SkamH-GPGe.png" width="100%"><br>
    </td>
 </tr>
  <tr>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/r1GYBbfwGx.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/ry15rWzwMl.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/rJj5BZzwzl.png" width="100%"><br>
    </td>
 </tr>
</table>

The captured communication consists primarily of TCP and TLSv1.3 traffic.

At multiple points, short-lived conversations are observed between the victim and `192.168.232.2`. TCP reset packets are also observed following individual conversations.
Filtering for TCP RST, ACK packets shows that these packets originate from the victim and occur repeatedly over the investigation window, with intervals ranging approximately from 1 to 15 seconds.

<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/SJ7UDbfwzx.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/S1kDwbfwzl.png" width="100%"><br>
    </td>
 </tr>
</table>

The beaconing behavior is inferred from the repeated sequence of short-lived communications between the same victim process and the same external endpoint.

This behavior is consistent with the beacon style C2 model. The implant periodically communicates with the C2 infrastructure rather than maintaining one continuous connection.

The endpoint telemetry corroborates this finding. Sysmon records 109 network connections from:

`C:\Users\john\AppData\Local\Microsoft\Windows\update.exe`

to:

`192.168.232.2:8888`

The combination of:

- Repeated TLS communication
- A consistent external destination
- Repeated short-lived conversations
- Process level attribution to update.exe

establishes 192.168.232.2:8888 as the primary C2 channel associated with the compromised host.

Because the C2 communication is encrypted, the packet capture does not expose the plaintext tasking exchanged between the operator and the implant.

The encrypted C2 behavior is mapped to:

**T1573.002 – Encrypted Channel: Asymmetric Cryptography**

MITRE describes this technique as using asymmetric cryptography to protect adversary command and control traffic, TLS channels can fall under this technique because asymmetric cryptography is commonly used during session establishment.

#### 4.3.2 Payload Delivery Analysis
After identifying the port `8888` communication as the primary C2 activity, the investigation pivots to the second network channel identified in Phase 3:

`192.168.232.2:443`

The objective is:

> How was `update.exe` introduced onto the workstation?

The PCAP is filtered for traffic involving:

`192.168.232.2`

and port:

`443`

All relevant packets belong to a single TCP conversation.

<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/Skbno-fwzg.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/HknhoZzPGe.png" width="100%"><br>
    </td>
 </tr>
</table>

At:

**2026-08-14 16:43:35.763**

an HTTP request is identified:

`GET /agent.exe`

![[artifact]suspicious_web_request](https://hackmd.io/_uploads/BkJGh-MPfx.png)

A corresponding HTTP response contains a media payload with:

`application/x-msdos-program`

![[artifact]suspicious_web_response](https://hackmd.io/_uploads/rkx7hbMvze.png)

The response object is exported from Wireshark as:

`agent.exe`

![image](https://hackmd.io/_uploads/rJYD3ZMPzx.png)

The hash of the exported payload is then compared with the hash of:

`C:\Users\john\AppData\Local\Microsoft\Windows\update.exe`

The hashes match.

<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/BJ_P6WfDze.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/rJJTnZfvfl.png" width="100%"><br>
    </td>
 </tr>
</table>

This provides direct evidence that the executable transferred through the HTTP conversation is the same executable later stored on the workstation as `update.exe`

The payload transfer is therefore mapped to:

**T1105 – Ingress Tool Transfer**

MITRE defines T1105 as transferring tools or other files from an external system into a compromised environment. The network evidence therefore resolves the previously unanswered question concerning the origin of `update.exe`.

The investigation also establishes that the communication on port 443 and the subsequent communication on port 8888 served different purposes:
- `443`: initial payload delivery
- `8888`: subsequent encrypted C2 communication

#### 4.3.3 Host Network Correlation

The endpoint and network evidence can now be correlated:
![image](https://hackmd.io/_uploads/BJ0x7zfvMl.png)
The process and packet evidence therefore provide a coherent explanation for both external communication channels.

The next investigation question is:

> What activities were performed through the established C2 channel?

### 4.4 PowerShell & Remote Tasking Analysis   
After establishing the relationship between update.exe, the notepad.exe processes, and the external C2 infrastructure, the investigation pivots to PowerShell Operational logs to determine what activities were performed on the compromised workstation.
#### 4.4.1 Host and User Validation
The earliest relevant PowerShell activity is identified at:

**2026-08-14 16:45:44.556**

with Process ID `5824`.

The corresponding ScriptBlockText contains commands used to collect information about the compromised workstation and the currently logged on user.

<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/r1go14QPze.png" width="100%"><br>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/SyfnJVmvMe.png" width="100%"><br>
    </td>
 </tr>
</table>

The observed script performs the following actions:

- Retrieves the computer name from `$env:COMPUTERNAME`.
- Retrieves the hostname using `[System.Net.Dns]::GetHostName()`.
- Identifies the current user from `$env:USERDOMAIN\$env:USERNAME`.
- Queries `Win32_Processor` to obtain CPU information.
- Queries `Win32_PhysicalMemory` to calculate total RAM.
- Retrieves IPv4 addresses from the network interfaces.
- Queries the operating system's last boot time to calculate uptime.
- Loads `System.Windows.Forms` to obtain the primary monitor resolution.

The collected information corresponds to the following discovery activities:

**T1082 – System Information Discovery**
**T1033 – System Owner/User Discovery**

MITRE describes T1082 as obtaining information about the operating system and hardware, while T1033 concerns identifying the primary or currently logged on user.
    
#### 4.4.2 Interpretation of Additional PowerShell ScriptBlock Events
Several additional PowerShell Operational events are observed immediately after the initial validation activity. Some of these events contain ScriptBlockText fragments such as:

<table align="center" width="100%">
  <tr>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/B1CMMV7wMe.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/HkzfG47wMe.png" width="100%"><br>
    </td>
    <td align="center" width="33%">
      <img src="https://hackmd.io/_uploads/SkVWzEXwMl.png" width="100%"><br>
    </td>
 </tr>
</table>
    
These events are not treated as separate attacker commands. The fragments are interpreted as PowerShell telemetry associated with the execution of the original validation script. In particular, the validation script uses commands such as `Get-CimInstance` and `Get-NetIPAddress`, which can invoke PowerShell's internal cmdletization and CIM processing. PowerShell Script Block Logging records script blocks processed by the PowerShell engine, so a single higher level command may result in multiple related ScriptBlock events.

This distinction is important because otherwise normal internal PowerShell processing could be incorrectly interpreted as additional attacker activity.    
    
#### 4.4.3 Archive PowerShell Activity
At approximately:

**2026-08-14 16:47:32.220**

2 PowerShell Operational events associated with Process ID `7364` show the following module activity.

The first event records:

```
CommandInvocation(Add-Type): "Add-Type"

ParameterBinding(Add-Type):
name="AssemblyName";
value="System.IO.Compression"
```

with:

```
Host Application:
notepad.exe

Script Name:
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
Microsoft.PowerShell.Archive\Microsoft.PowerShell.Archive.psm1

Sequence Number:
20
```
![image](https://hackmd.io/_uploads/r1I_4NQvzg.png)


The second event records:

```
CommandInvocation(Add-Type): "Add-Type"

ParameterBinding(Add-Type):
name="AssemblyName";
value="System.IO.Compression.FileSystem"
```

with the same PowerShell host, Runspace ID, and module:

`Microsoft.PowerShell.Archive.psm1`

![image](https://hackmd.io/_uploads/B1-cNN7PGe.png)

The 2 events provide strong evidence that the PowerShell Archive module loaded the `.NET` compression libraries required for ZIP archive operations.

Microsoft documents that the `Microsoft.PowerShell.Archive` module provides `Compress-Archive` and `Expand-Archive`, and that `Compress-Archive` creates ZIP archives using the `System.IO.Compression.ZipArchive` API. The 2 events provide evidence that archive creation occurred within the attacker's PowerShell execution sequence. However, these two `Add-Type` events alone do not identify the exact input files or the exact Compress Archive command.
    
#### 4.4.4 Persistence Script
At:

**2026-08-14 16:53:52.644**

A PowerShell Operational event associated with Process ID `5744` contains the script responsible for persistence.
![Screenshot 2026-08-19 205841](https://hackmd.io/_uploads/HyHA8NXvfl.png)
The script modifies:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

and creates the:

`MicrosoftOffice`

value configured to execute `update.exe` through PowerShell.

This activity directly corresponds to the Sysmon Event ID 13 that generated the initial SIEM alert.

The behavior is mapped to:

**T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder**

#### 4.4.5 PowerShell Investigation Finding

The PowerShell investigation establishes three major attacker's activity periods:
- Host and user validation
- Archive activity
- Persistence establishment

The three activity periods are associated with Process IDs:
- `5824`: Host/User Discovery
- `7364`: Archive-related activity
- `5744`: Persistence

These Process IDs correspond to the `notepad.exe` instances previously identified as being created by `update.exe`. The correlation between Process ID, Runspace ID, timestamps, PowerShell telemetry, and Sysmon process activity establishes that the observed PowerShell operations form part of the same post compromise execution chain.
    
### 4.5 Collection, Archive & Artifact Removal Analysis
Following the identification of attacker's PowerShell activity and the associated execution contexts, the investigation focuses on determining whether local data was collected, whether the collected data was archived, and whether artifacts associated with the activity were subsequently removed.

#### 4.5.1 Archive Creation Analysis
PowerShell Operational telemetry identified activity involving:

`System.IO.Compression`
`System.IO.Compression.FileSystem`
`Microsoft.PowerShell.Archive.psm1`

at approximately:

**2026-08-14 16:47:32.220**

The corresponding Process ID is `7364`.
    
To determine whether the archive activity resulted in an actual file being created, filesystem artifacts are examined using JournalViewer.

An archive named:

`Collected_Data.zip`

is identified with the following timestamps:

Created:
**2026-08-14 16:47:32.208**

Deleted:
**2026-08-14 16:55:42.974**

![image](https://hackmd.io/_uploads/BkcDDUXwGx.png)

The creation timestamp of `Collected_Data.zip` is within milliseconds of the PowerShell events associated with `System.IO.Compression` and the PowerShell archive module. The temporal correlation between the PowerShell telemetry and filesystem evidence therefore provides strong evidence that the observed PowerShell activity resulted in the creation of the ZIP archive.

**Finding**

> A ZIP archive named `Collected_Data.zip` was created on the compromised workstation at approximately 16:47:32 and was subsequently deleted.

The archive creation is mapped to:

**T1560.001 – Archive Collected Data: Archive via Utility**

#### 4.5.2 Identifying the Archive Inputs
The next investigation question is:

> Which data was included in `Collected_Data.zip`?

The investigation searches the available telemetry for direct evidence linking specific files to the archive operation. The following evidence sources are reviewed:

- PowerShell Operational logs
- Sysmon FileCreate events
- Sysmon ProcessCreate events
- Windows file-access telemetry, where available
- NTFS journal artifacts
- Filesystem metadata
- Relevant PowerShell ScriptBlockText

The investigation confirms the creation of the archive but does not identify a telemetry record that directly exposes the exact input file list supplied to the archive operation. 
There is a [notable directory](#notable_directory) associated with the archive creation period :
    
`C:\Users\john\AppData\Local\Temp\`
    
But the presence of files in this directory is treated only as contextual evidence. Their presence alone does not establish that they were read or included in the ZIP archive. Therefore, the investigation distinguishes between the following findings:

**Confirmed**

- `Collected_Data.zip` was created.
- PowerShell archive functionality was invoked during the same execution period.

**Not confirmed**

- The exact files included in `Collected_Data.zip`.
- The exact content of the archive.

#### 4.5.3 Exfiltration Assessment
The next investigation question is:

> Was the archived data transferred from the compromised workstation to external infrastructure?

The network evidence is reviewed around:

- The archive creation timestamp
- The archive deletion timestamp
- known C2 communication time window
- outbound traffic generated by the suspicious process.

The PCAP confirms continued encrypted communication between the workstation and:

`192.168.232.2:8888`

However, the C2 traffic is encrypted. The packet capture therefore exposes the network connection, direction, timing, and volume of the traffic but does not expose the plaintext content of the application data. No independent evidence is identified that directly associates a specific outbound transfer with:

`Collected_Data.zip`

or proves that the contents of that archive were successfully transferred to the external system.

The investigation therefore concludes:

**Confirmed**
- An encrypted C2 channel existed between the workstation and `192.168.232.2:8888`.
- The archive `Collected_Data.zip` was created during the period of C2 activity.

**Not confirmed**
- That `Collected_Data.zip` was transmitted over the C2 channel.
- The contents of any outbound transfer.
- The identity of any files or data successfully exfiltrated.

#### 4.5.4 Artifact Removal
During the endpoint evidence review in Phase 3, `Office Security Update.exe` was identified as a relevant executable, but the file was no longer present in its original location:

`C:\Users\john\Downloads\Office Security Update.exe`

At that stage, the reason for its absence could not be established. Therefore, the missing file is used as a pivot for further investigation. The investigation searches filesystem journal artifacts for historical activity associated with `Office Security Update.exe`. Using JournalViewer, a deletion record is identified:

File:
`C:\Users\john\Downloads\Office Security Update.exe`

Deletion Time:
`2026-08-14 16:57:43.034`

![image](https://hackmd.io/_uploads/HyAmpmVDfx.png)
    
The finding establishes that the executable previously identified during the process investigation was subsequently deleted from the workstation.

The deletion of both `Office Security Update.exe` and `Collected_Data.zip` occurred after the main post compromise activities had taken place. The available evidence therefore confirms that two files associated with the intrusion were removed from the workstation during the incident window.

The file deletion behavior is mapped to:

**T1070.004 – Indicator Removal: File Deletion**
    
### 4.6 Timeline Reconstruction & Attack Chain
Before reconstructing the final attack timeline, the investigation incorporates the statement provided by the affected employee, John. According to the employee's statement, he received an email that appeared to originate from Microsoft and instructed him to download and execute an Office security update. John reported that he followed the instructions, downloaded `Office Security Update.exe`, and subsequently executed the file. This statement provides contextual support for the initial access scenario. However, because email server telemetry is outside the scope of the investigation, the email itself is not independently verified through technical evidence.
   
**Correlated Attack Timeline**

The following table summarizes the major events identified across the available evidence sources.

| Time | Evidence Source | Activity | Confidence |
| :--- | :--- | :--- | :--- |
| `16:43:35.763` | PCAP | HTTP `GET /agent.exe` to `192.168.232.2:443` | High |
| `16:43:35.930` | Sysmon | John executes `Office Security Update.exe` through `explorer.exe` | High |
| `16:43:36.228` | Sysmon | `update.exe` is created | High |
| `16:43:36.700` | Sysmon | `update.exe` is executed as Process ID `8444` | High |
| `16:43:35–16:43:36` | PCAP + File Hash | Downloaded `agent.exe` is confirmed to be the same binary as `update.exe` | High |
| `16:45:44.280` | Sysmon | `update.exe` creates `notepad.exe` as Process ID `5824` | High |
| `16:45:44.556` | PowerShell Operational | Host and user discovery activity | High |
| `16:47:31.649` | Sysmon | `update.exe` creates `notepad.exe` as Process ID `7364` | High |
| `16:47:32.208` | JournalViewer | `Collected_Data.zip` is created | High |
| `16:47:32.220` | PowerShell Operational | Compression libraries and archive functionality are loaded | High |
| `16:53:52.424` | Sysmon | `update.exe` creates `notepad.exe` as Process ID `5744` | High |
| `16:53:52.644` | PowerShell Operational | Persistence script is executed | High |
| `16:53:52.686` | Sysmon | `MicrosoftOffice` Registry Run Key is modified | High |
| `16:55:42.974` | JournalViewer | `Collected_Data.zip` is deleted | High |
| `16:57:43.034` | JournalViewer | `Office Security Update.exe` is deleted | High |
| `16:58:21.203` | Sysmon | `update.exe` terminates | High |

>Note on cross source timestamps: 
The timestamps presented above are the timestamps recorded by the respective evidence sources. Minor differences in event timing may occur between Sysmon, PowerShell Operational logs, filesystem artifacts, and packet captures due to differences in event generation, buffering, and timestamp recording. Therefore, the timestamps should be interpreted together with process relationships, file relationships, and network correlation rather than treated as an absolute representation of causal order. The final attack sequence is established through cross source correlation rather than by timestamp alone.

Based on the correlated evidence, the attack sequence can be reconstructed as follows:

![image](https://hackmd.io/_uploads/ryazd84wMl.png)
   
#### 4.6.1 Confirmed MITRE ATT&CK Mapping
The following techniques are directly supported by the available evidence:
| Tactic | Technique | ID | Evidence |
| :--- | :--- | :--- | :--- |
| Initial Access | Phishing: Spearphishing Attachment | `T1566.001` | Malicious executable delivered through the phishing scenario |
| Execution | User Execution: Malicious File | `T1204.002` | User executes `Office Security Update.exe` |
| Command and Control | Ingress Tool Transfer | `T1105` | `agent.exe` is transferred to the workstation and confirmed to match `update.exe` |
| Discovery | System Information Discovery | `T1082` | Host and system information is collected |
| Discovery | System Owner/User Discovery | `T1033` | User information is collected |
| Collection | Archive Collected Data: Archive via Utility | `T1560.001` | PowerShell archive functionality and `Collected_Data.zip` creation |
| Command and Control | Encrypted Channel: Asymmetric Cryptography | `T1573.002` | Encrypted communication with `192.168.232.2:8888` |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | `T1547.001` | `MicrosoftOffice` Registry Run Key executes `update.exe` |
| Defense Evasion | Indicator Removal: File Deletion | `T1070.004` | `Office Security Update.exe` and `Collected_Data.zip` are deleted |
| Defense Evasion | Process Injection | `T1055` | `update.exe` creates remote threads in `notepad.exe` processes |

#### 4.6.2 Unconfirmed or Partially Supported Techniques
2 activities identified during the attack simulation cannot be promoted to confirmed MITRE ATT&CK findings based on the available evidence.

**Data from Local System – T1005**

The investigation confirms that archive activity occurred. However, the exact contents of `Collected_Data.zip` cannot be independently established. Therefore, **T1005 – Data from Local System** is treated as a supported hypothesis rather than a confirmed finding.

**Exfiltration Over C2 Channel – T1041**

The established C2 channel supports bidirectional encrypted communication between the victim and `192.168.232.2`. However, the encrypted traffic does not allow the exact contents of individual application data transfers to be independently identified. Therefore, the investigation cannot conclusively establish that the targeted files were successfully exfiltrated. **T1041 – Exfiltration Over C2 Channel** is therefore treated as a high confidence hypothesis based on the attack scenario and surrounding evidence, but not as a confirmed finding.
    
### 4.7 Attacker Objective & Impact Assessment
#### 4.7.1 Attacker Objective
The reconstructed attack sequence indicates that the attacker pursued several objectives during the compromise. The initial discovery activity was used to obtain information about the compromised workstation and its user. Subsequent PowerShell activity was associated with archive creation, while the Registry Run Key modification established a mechanism for maintaining execution after user logon. Based on the available evidence, the observed objectives are assessed as:

- Host and user reconnaissance
- Local data staging and potential collection
- Persistence
- Maintaining an encrypted C2 channel for continued operator interaction

The potential exfiltration of the staged archive remains an unresolved finding because the contents of the encrypted C2 traffic cannot be independently verified.
    
#### 4.7.2 Impact Assessment
The investigation confirms that the workstation was successfully compromised and that the attacker obtained the ability to execute commands through the established C2 channel. The following impacts are confirmed:
- `DESKTOP-O7F02KF` was compromised.
- `update.exe` was introduced and executed.
- The attacker established Registry persistence.
- Host and user information was collected.
- Archive creation occurred during the post compromise activity.
- Multiple intrusion artifacts were subsequently deleted.
- The workstation maintained repeated encrypted communication with the external infrastructure `192.168.232.2`.

The following impacts remain unconfirmed:
- The exact contents of `Collected_Data.zip`.
- Whether the archive was successfully transferred to the attacker.
- The exact contents of the encrypted C2 tasking and returned data.

Based on the confirmed findings, the incident resulted in a successful endpoint compromise with persistence and remote execution. The potential exposure of locally stored data is considered a significant but partially unconfirmed impact.
    
### 4.8 Investigation Limitations & Unknowns
#### 4.8.1 Encrypted C2 Tasking
The C2 channel uses encrypted communication. Consequently, the exact commands exchanged between the operator and the implant cannot be directly reconstructed from the PCAP. The investigation therefore relies on host side effects, process relationships, PowerShell telemetry, filesystem artifacts, and temporal correlation to infer the purpose of the remote activity.

4.8.2 Archive Contents
The investigation confirms the creation and deletion of `Collected_Data.zip`, but the available evidence does not preserve the exact file list supplied to the archive operation.

4.8.3 Exfiltration Contents
The encrypted C2 traffic does not expose the contents of application data transfers. Therefore, the investigation cannot independently determine which files or data, if any, were successfully transferred to the attacker.

4.8.4 Initial Access Evidence
The phishing email is treated as the assumed initial access vector of the simulation and is supported by the employee's statement. However, email-server telemetry was not collected as part of the project. The phishing email itself is therefore not independently verified through technical evidence.
    
>Investigation Note – Cross Source Timestamp Discrepancy:
During an earlier execution of the attack simulation, an approximately 30 seconds discrepancy was observed between selected Sysmon timestamps and packet capture timestamps during the initial payload delivery stage. The discrepancy also affected the apparent order of some related events.
>
>A subsequent execution of the attack simulation was performed to validate the observation. The later execution produced a more consistent relationship between endpoint and network timestamps and was therefore selected as the primary evidence set for this investigation.
>
>The earlier execution is retained as an investigation note because it demonstrates an important forensic consideration: timestamp data from individual telemetry sources should not automatically be treated as the sole authoritative representation of event order. Cross source correlation, process relationships, file metadata, and causal relationships should be considered when reconstructing an incident timeline.
    
## 5. Phase 5: Containment, Eradication & Recovery
<div id="phase_5"></div>
    
Following the completion of the investigation and impact assessment, the response proceeds to containment, eradication, and recovery. The objective of this phase is to prevent further attacker activity, remove the identified malicious components and persistence mechanisms, restore the affected workstation to a trusted state, and implement defensive improvements based on the findings of the investigation.    
    
### 5.1 Containment
The containment phase focuses on preventing the attacker from maintaining access to the compromised workstation or continuing activity within the environment. The affected workstation, `DESKTOP-O7F02KF`, is kept isolated from the internal network while remediation activities are performed.

The following containment actions are performed:
- Keep `DESKTOP-O7F02KF` isolated from the internal network.
- Confirm that no additional affected user accounts were identified during the investigation.
- Confirm that no evidence of lateral movement was identified within the available telemetry.
- Temporarily disable the compromised user account `john` to prevent further use of the account during remediation.
- Block the identified external address `192.168.232.2` at the network security boundary, such as firewall or proxy.

The containment actions are directly derived from the findings established during Phase 4. In particular, blocking `192.168.232.2` prevents the identified external infrastructure from being used to re-establish the C2 communication.

### 5.2 Eradication
The eradication phase removes the identified malicious artifacts, persistence mechanisms, and remaining attacker footholds from the workstation.

Before removing the identified artifacts, the endpoint is checked to confirm that no suspicious processes remain active. The following remediation activities are performed:
- Review currently running processes and confirm that no process associated with the identified malicious activity remains active.
- Confirm that no additional persistence mechanism was identified beyond the Registry Run Key observed during the investigation.
- Review filesystem activity during the incident window using JournalViewer and confirm that no additional suspicious artifact remains on the workstation apart from the identified `update.exe`.
- Remove the `MicrosoftOffice` Registry Run Key from:
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Remove the malicious `update.exe` executable from the workstation.
- Recheck relevant Registry locations and startup locations to verify that the identified persistence mechanism has been completely removed.
- Reset the credentials associated with the compromised user account `john`.

The eradication process is considered complete only after the malicious executable, persistence mechanism, and associated attacker foothold have been removed and the workstation has been rechecked for residual indicators.

### 5.3 Recovery
After eradication is completed, the workstation is prepared for restoration to normal operation. The following recovery activities are performed:
- Reconnect the workstation to the internal network.
- Monitor network connections generated by the workstation after reconnection and confirm that the workstation no longer communicates with `192.168.232.2`.
- Confirm that no recurring communication pattern consistent with the previously observed C2 beaconing behavior is present.
- Confirm that Sysmon, PowerShell logging, and the configured SIEM forwarding mechanism remain operational after recovery.
- Confirm that new endpoint events continue to reach the SIEM correctly.

**Enhanced Post-Recovery Monitoring**
    
Following recovery, `DESKTOP-O7F02KF` is placed under enhanced monitoring for a defined observation period. For this project, a 7-day enhanced monitoring period is used as a practical laboratory example rather than as a universal enterprise requirement. During this period, monitoring focuses on:
- Outbound network connections from the recovered workstation.
- Connections to previously identified malicious address.
- Reappearance of C2 beaconing behavior.
- Reappearance of the removed Registry persistence mechanism.
- Execution of previously identified malicious filenames or hashes.
- Suspicious PowerShell activity.
- Unexpected process relationships involving legitimate system binaries.
- New indicators associated with the previous incident.

The workstation can be considered to have returned to normal monitoring after the enhanced monitoring period when no recurrence of malicious activity is observed and the endpoint continues to produce expected telemetry.

### 5.4 Security Architecture, Logging Improvements & Defensive Improvements
#### 5.4.1 Security Architecture & Logging Improvements
The investigation identified several limitations in the current monitoring and evidence collection architecture.

Two limitations were particularly relevant to the investigation:

1. **Limited endpoint file access visibility**

    The investigation was able to establish file creation and deletion through Sysmon and filesystem artifacts. However, the available telemetry did not initially provide direct evidence identifying which specific files were accessed during the collection operation or included in the resulting archive.

2. **Cross source timestamp reliability**

   An earlier execution of the attack simulation demonstrated that timestamps from different telemetry sources may not always align perfectly. This introduced additional uncertainty when reconstructing the exact order of events across endpoint and network evidence.

Based on these findings, several improvements are proposed.

**Centralize PowerShell Telemetry**
    
PowerShell Operational logs should be centrally forwarded to the SIEM rather than remaining only on the endpoint.

Centralizing this telemetry would allow analysts to correlate PowerShell script activity with:

- Sysmon process creation
- Network connections
- Registry modifications
- Filesystem activity

This is particularly important for incidents involving remote tasking and encrypted C2, where the network traffic itself cannot expose the plaintext commands.

**Improve File System Access Auditing**

Windows Object Access auditing should be enabled selectively for sensitive directories and files where direct access evidence would provide meaningful investigative value. The objective is to obtain evidence that identifies which files were accessed, complementing the existing Sysmon file creation and file deletion telemetry. When the appropriate audit policy and SACL are configured, Windows Security Event ID `4663` can record operations actually performed against an audited object. This provides a complementary evidence source for investigating file access activity.
#### Controlled Validation
The proposed logging improvement was validated in a controlled laboratory test. A test script was used to simulate the same collection behavior observed during the incident by reading `C:\Users\john\Downloads\test.txt` file and compressing it into a ZIP archive : 
```powershell script
$userProfile = $env:USERPROFILE
$tempDir     = $env:TEMP

$file = Join-Path -Path $userProfile -ChildPath "Documents\test.txt"

$zipOutputFile = Join-Path -Path $tempDir -ChildPath "test.zip"

$filesToZip = @()
$filesToZip += $file

Compress-Archive -Path $filesToZip -DestinationPath $zipOutputFile -Force
```
After Object Access auditing was enabled and the appropriate audit policy/SACL configuration was applied, the Security log recorded file access events containing the specific object paths.
    
![image](https://hackmd.io/_uploads/Hkn90Q_PGe.png)
    
The resulting evidence can then be correlated with the PowerShell Operational logs associated with the archive creation. This additional telemetry addresses the principal visibility gap identified during the investigation. While PowerShell telemetry can demonstrate that archive functionality was invoked, the Object Access auditing provides independent evidence of the specific files accessed during the collection operation. The combination of both sources therefore provides substantially stronger evidence for determining the files involved in a collection operation than either source alone.

The test also demonstrates an important principle for the production environment file access auditing should be applied selectively rather than indiscriminately, because auditing every file access across all endpoints can generate substantial event volume. The scope should therefore prioritize sensitive directories and high value assets.

**Improve Network Visibility**
The current architecture relies primarily on packet capture for post-incident network analysis. A production environment could introduce network security monitoring at the network boundary, such as IDS/IPS or networ monitoring technologies, to provide higher level detection and alerting for suspicious external communication.

For example, Suricata could be deployed near the organization's firewall or proxy to provide network detection and prevention capabilities. The detailed deployment and tuning of such infrastructure is outside the scope of this project. The recommendation is intended as an architectural improvement rather than as an additional implementation project.

**Improve Time Synchronization and Monitoring**
The incident demonstrates that reliable timestamps are critical when correlating endpoint and network telemetry. The environment should therefore maintain:

- A consistent organizational time source.
- Reliable synchronization of endpoints and network devices.
- Monitoring of Windows Time Service health.
- Verification of synchronization status on systems used for incident investigation.
- Investigation of significant or unexpected clock adjustments.

Windows provides `w32tm` for inspecting Windows Time Service status, synchronization source, and configuration. This can be used as an operational mechanism for checking endpoint time synchronization. The purpose is not merely to ensure that systems display the same local time, but to improve the reliability of timestamps used during forensic correlation.

#### 5.4.2 Defensive Improvements
The investigation findings are used to identify detection gaps and improve the organization's behavioral detection coverage. The detection improvements focus on behaviors that were either directly observed during the investigation or identified as important indicators of the investigated attack chain. The objective is to establish reusable detections that can identify suspicious behavior and, where possible, correlate multiple behaviors into a more confidence detection. The rules are designed primarily for alert generation.
    
##### Detection Design & Sigma Rule Creation

3 primary detection objectives are defined from the investigation findings:

1. Detect suspicious PowerShell activity involving hidden execution, execution policy bypass, or explicit command execution.
2. Detect suspicious remote thread creation involving the legitimate `notepad.exe` process.
3. Detect outbound network connections from suspicious processes to external address.

These individual detections are then correlated to identify a multi stage behavior pattern involving PowerShell execution, process injection, and network communication.

**Suspicious PowerShell Execution**

**Detection Objective**

Detect PowerShell execution containing parameters frequently associated with suspicious or stealthy execution:

* `-ExecutionPolicy Bypass`
* `-WindowStyle Hidden`
* `-Command`

The detection is intended to identify suspicious behavior rather than a specific malware sample. These parameters can occur in legitimate administrative activity, so the rule requires subsequent validation and tuning.

**Primary Evidence Sources**

* Sysmon Process Creation
* PowerShell Script Block Logging

**Sigma Rule - PowerShell Script Block**

```yaml
title: Suspicious PowerShell Script Execution Parameters
id: 2c7b0e51-0ea0-4dd5-9476-8b6b0d0f1b27
status: experimental
description: >
  Detects suspicious PowerShell Script Block content containing execution
  policy bypass, hidden execution, or explicit command execution parameters.
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: nguyen duy
date: 2026-08-23
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: ps_script
  product: windows
detection:
  selection:
    ScriptBlockText|contains:
      - 'ExecutionPolicy Bypass'
      - 'WindowStyle Hidden'
      - '-Command'
  condition: selection
falsepositives:
  - Legitimate administrative PowerShell scripts
  - Enterprise automation
  - Software deployment and management
level: high
```

The `ps_script` detection is applicable only when PowerShell Script Block Logging is enabled. In the current project, this telemetry is available during endpoint investigation and is recommended for centralized collection as part of the logging improvements.

**Suspicious Process Injection into Notepad**

**Detection Objective**

Detect remote thread creation targeting the legitimate Windows `notepad.exe` process. The objective is to detect behavior consistent with process injection rather than to classify `notepad.exe` itself as malicious.

**Evidence Source**

* Sysmon Event ID 8 – CreateRemoteThread

**Sigma Rule - Process Injection into Notepad**

```yaml
title: Suspicious Remote Thread Creation in Notepad
id: 5e5e86c3-63c6-4c6f-a8f8-1b8b11d3c9a2
status: experimental
description: >
  Detects remote thread creation targeting the legitimate Windows Notepad
  process. The behavior may indicate process injection when the source
  process is not expected to interact with Notepad.
references:
  - https://attack.mitre.org/techniques/T1055/
author: nguyen duy
date: 2026-08-23
tags:
  - attack.defense_evasion
  - attack.t1055
logsource:
  category: create_remote_thread
  product: windows
detection:
  selection:
    TargetImage|endswith: '\notepad.exe'
  condition: selection
falsepositives:
  - Legitimate debugging software
  - Accessibility software
  - Security or monitoring software
  - Other applications that legitimately interact with Notepad
level: high
```

The rule is intentionally assigned high severity rather than critical because a single remote thread creation event does not necessarily prove malicious process injection. Higher confidence is obtained through correlation with the additional behaviors identified during the investigation.

**Suspicious Network Connection**

**Detection Objective**

Detect outbound network connections from executable processes located in user writable directories to external destinations. This detection is designed to identify behavior similar to the `update.exe` -> `192.168.232.2:8888` communication observed during the investigation.

**Evidence Source**

* Sysmon Event ID 3 – Network Connection

**Sigma Rule - Suspicious Network Connection**

```yaml
title: Suspicious Network Connection from User-Writable Executable
id: 0d2a15e7-9f49-4ed1-94c0-7b3e4c5f81a6
status: experimental
description: >
  Detects outbound network connections originating from executables located
  in user writable directories.
author: nguyen duy
date: 2026-08-23
tags:
  - attack.command_and_control
  - attack.t1071
logsource:
  category: network_connection
  product: windows
detection:
  selection_process:
    Image|contains:
      - '\Users\'
      - '\AppData\'
      - '\Temp\'
      - '\Users\Public\'
  selection_external:
    DestinationIp|exists: true
  condition: selection_process and selection_external
falsepositives:
  - Legitimate user-installed applications
  - Development tools
  - Enterprise applications installed under user profiles
  - Software using temporary execution directories
level: medium
```

This rule is intentionally set to medium because connections originating from user writable paths can be common in legitimate software. Additional tuning or enrichment with reputation, destination classification, or process reputation would be appropriate in a production environment.

**Correlation Detection**

The investigation demonstrated that the individual events become significantly more meaningful when correlated.

For example:

```text
Suspicious PowerShell
        +
Process Injection into notepad.exe
        +
Outbound Network Connection
```

occurring on the same workstation within a short period provides stronger evidence than any of the three events individually.

The correlation detection therefore combines the three base rules:

* Suspicious PowerShell Script Block
* Suspicious Remote Thread Creation in Notepad
* Suspicious Network Connection

**Sigma Correlation Rule**

```yaml
title: Correlated Suspicious PowerShell Process Injection and Network Activity
id: 9d1d8f4a-8f5f-47d4-93c6-2b1aee8a64f0
status: experimental
description: >
  Detects a combination of suspicious PowerShell execution, remote-thread
  creation targeting Notepad, and outbound network communication occurring
  on the same Windows host within a short time window.
author: nguyen duy
date: 2026-08-23
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1055
  - attack.command_and_control
correlation:
  type: temporal
  rules:
    - 2c7b0e51-0ea0-4dd5-9476-8b6b0d0f1b27
    - 5e5e86c3-63c6-4c6f-a8f8-1b8b11d3c9a2
    - 0d2a15e7-9f49-4ed1-94c0-7b3e4c5f81a6
  group-by:
    - ComputerName
  timespan: 5m
level: critical
```

The correlation rule is intentionally assigned critical severity because it requires three independent behavioral signals to occur within the same host and time window. The exact correlation window should be tuned using the organization's normal telemetry and expected attacker behavior. A five-minute window is used here as a demonstration for the project rather than as a universal operational threshold.

##### Validation
Before deployment, each Sigma rule is validated to ensure that:

- The YAML follows the Sigma rule schema.
-  The selected logsource matches the telemetry actually available in the environment.
- The rule converts successfully to Splunk SPL.
- The generated SPL uses the correct local field mappings.
- The converted query matches the expected events from the previously investigated incident.
- The correlation rule identifies the expected multi event behavior.
    
The rules are also checked against the existing incident evidence to confirm that the intended detections would have generated alerts from the observed activity.

##### Deployment

After validation, the Sigma rules are converted to Splunk SPL and deployed as Splunk saved searches and alerts. The Sigma rules remain the portable detection definitions, while the generated SPL represents their implementation within the Splunk environment.

##### Detection Testing & Tuning
The rules are tested against the previously collected incident telemetry to verify that the expected events and correlations are detected. Additional testing should be performed against representative benign activity to identify obvious false positives, followed by controlled execution of individual behaviors where necessary. Any detected false positives, missing matches, or field mapping issues should be addressed by adjusting the detection conditions or correlation window and then revalidating the rule.

Full testing and long-term tuning are outside the scope of this project. The rules presented here are therefore treated as laboratorial detections requiring further tuning before production deployment.
    
### 5.5 Lessons Learned
The incident provides several lessons that can be applied to future detection and response activities.

**Detection Gaps**
    
The initial alert detected the Registry persistence mechanism only after several post-compromise activities had already occurred. The alert therefore provided an effective investigation trigger but did not represent the beginning of the compromise.

**Visibility Gaps**

The investigation demonstrated the value of combining:
- Sysmon
- PowerShell Operational logs
- filesystem artifacts
- Registry artifacts
- PCAP

The absence of some endpoint file-access telemetry made it difficult to independently establish the exact contents of the collected archive.

**Investigation Challenges**

Encrypted C2 communication prevented direct reconstruction of the operator's commands from network traffic. Host side effects therefore had to be correlated with C2 communication to infer the purpose of remote tasking.

**Timestamp Reliability**

The earlier attack simulation demonstrated the importance of validating timestamps across multiple evidence sources rather than relying on one telemetry source when reconstructing an incident timeline.

**Logging Improvements**

Centralized PowerShell telemetry, selective Object Access auditing, improved network visibility, and reliable time synchronization would increase the quality and confidence of future investigations.

**Future Response Improvements**

Future response exercises should continue to evaluate whether each attack behavior generates sufficient telemetry to answer the corresponding investigation question. Detection, logging, and evidence-collection requirements should therefore be reviewed together rather than treated as separate capabilities.
