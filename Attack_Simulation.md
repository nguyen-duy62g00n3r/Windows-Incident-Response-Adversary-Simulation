# Attack Simulation

## 1. Attack Scenario
The project simulates an incident representing a targeted phishing attack against an employee workstation in a small enterprise environment. An attacker sends a spoofed email designed to appear as a legitimate Microsoft Office notification. The email contains instructions encouraging the victim to download and execute a malicious executable disguised as an Office security update.

## 2. Attack chain

The project will simulate these [MITRE ATT&CK](https://attack.mitre.org/) techniques:

| ID | Tactic | MITRE ATT&CK Technique |
| :--- | :--- | :--- |
| **T1566.001** | Initial Access | Phishing: Spearphishing Attachment |
| **T1204.002** | Execution | User Execution: Malicious File |
| **T1105** | Command and Control | Ingress Tool Transfer |
| **T1071.001** | Command and Control | Application Layer Protocol: Web Protocols |
| **T1573.002** | Command and Control | Encrypted Channel: Asymmetric Cryptography |
| **T1082** | Discovery | System Information Discovery |
| **T1033** | Discovery | System Owner/User Discovery |
| **T1005** | Collection | Data from Local System |
| **T1560.001** | Collection | Archive Collected Data: Archive via Utility |
| **T1041** | Exfiltration | Exfiltration Over C2 Channel |
| **T1547.001** | Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **T1070.004** | Defense Evasion | Indicator Removal: File Deletion |
    
### 2.1	Phishing / Dropper Delivery	
#### Action
The attack begins with a phishing email sent to the victim workstation. The email is designed to resemble a legitimate Microsoft Office security notification and attempts to persuade the user to download an executable security update. The email informs the victim that a security update is available and provides a link to a controlled OneDrive-hosted laboratory file. The victim is instructed to download the executable and execute it as part of the simulated update process

![spoofed_email](https://hackmd.io/_uploads/BycklM8Ifg.png)

#### Result 
The malicious executable is successfully delivered to the victim workstation and is ready to be executed by the user.

#### MITRE ATT&CK Mapping
- **T1566.001 – Phishing: Spearphishing Attachment:** The attack uses a link embedded in the phishing email to direct the victim to the location from which the executable is downloaded.

### 2.2	Dropper Execution and Payload Delivery	
#### Action
The victim opens the downloaded `Office Security Update.exe`, believing it to be a legitimate Microsoft Office security update. After opening the executable, it retrieves the payload from the attacker server. The downloaded payload is saved to the following location on the victim workstation: 
```
C:\Users\john\AppData\Local\Microsoft\Windows\update.exe
```
The use of a filename and directory resembling a legitimate Windows component is intended to make the payload less conspicuous during the simulation.

After the payload is successfully written to disk, the dropper executes `update.exe`, allowing the second-stage payload to begin its post-compromise activity.

#### Result

The execution of `Office Security Update.exe` results in second-stage payload being introduced and executed on the victim workstation. The execution of `update.exe` marks the transition from the initial payload delivery stage to the post-compromise phase of the attack.


#### MITRE ATT&CK Mapping
- **T1204.002 – User Execution: Malicious File:** The victim manually executes the `Office Security Update.exe` file
- **T1105 – Ingress Tool Transfer:** The dropper downloads the second-stage `update.exe` payload from the attacker server and places it on the compromised workstation.

### 2.3	C2 Establishment	
#### Action
After `update.exe` is executed, it establishes a Command and Control (C2) connection with the attacker Sliver server.

The payload operates in Beacon mode and communicates with the C2 server through an encrypted mTLS channel. This communication channel allows the attacker to remotely issue tasks to the compromised workstation and receive the corresponding results.

The C2 establishment can be summarized as:
![image](https://hackmd.io/_uploads/r1pCVZUUfl.png)

<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/Sk_dgzUIMx.png" width="100%"><br>
      <i>Sliver interface</i>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/SkS_dTnUfg.png" width="100%"><br>
      <i>successful connection from the victim</i>
    </td>
  </tr>
</table>

#### Result
A functional C2 channel is established between the compromised workstation and the attacker-controlled Sliver server. The attacker can subsequently use this channel to perform post compromise activities on the victim workstation.

#### MITRE ATT&CK Mapping
- **T1071.001 – Application Layer Protocol: Web Protocols:** The C2 channel uses an application layer protocol over the network for communication between the compromised workstation and the attacker  server.
- **T1573.002 – Encrypted Channel:** Asymmetric Cryptography: The C2 communication is protected using mutual TLS, providing an encrypted communication channel between the Beacon and the C2 server.

### 2.4	Host Validation	 
#### Action
After establishing the C2 channel, the attacker performs an initial validation of the compromised workstation. The purpose of this step is to obtain basic information about the host and confirm that the implant is operating as expected. The attacker uses the C2 channel to execute a validation utility on the victim workstation.
![host_validation](https://hackmd.io/_uploads/BkKgF62Izl.png)


#### Result
The attacker obtains basic information about the compromised workstation and its current user environment. This information provides the attacker with sufficient context to proceed with subsequent post-compromise activities.

#### MITRE ATT&CK Mapping
- **T1082 – System Information Discovery:** The attacker collects information about the operating system and hardware configuration of the compromised workstation.
- **T1033 – System Owner/User Discovery:** The attacker obtains information identifying the user associated with the compromised workstation.

### 2.5	Data Collection	and Archive Creation
#### Action

After validating the compromised workstation, the attacker uses the established Sliver C2 channel to execute a collection utility on the compromised workstation.
![data_collection](https://hackmd.io/_uploads/HJXQta28Me.png)


For the purpose of this simulation, two text files containing simulated business information are selected from the Documents directory:

```text
C:\Users\john\Documents\
├── Nhan su
|        └── nhansu.txt
└── Pay roll
         └── payroll.txt
```

The attacker collects these files and subsequently compresses them into a ZIP archive. The resulting archive is stored in the temporary directory:

```text
C:\Users\john\AppData\Local\Temp\Collected_Data.zip
```

#### Result
Two files containing simulated sensitive business information are collected from the compromised workstation and compressed into a single ZIP archive in the temporary directory. The archive is subsequently used as the data object for the exfiltration stage of the simulated attack.

#### MITRE ATT&CK Mapping
- **T1005 – Data from Local System:** The attacker collects files containing simulated business information from the victim's local filesystem.
- **T1560.001 – Archive Collected Data: Archive via Utility:** The collected files are compressed into a ZIP archive before exfiltration.

### 2.6	Exfiltration
#### Action
After creating the ZIP archive, the attacker uses the Sliver `download` command to retrieve the archive from the compromised workstation through the established C2 channel.
<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/BkYwYT3Lzx.png" width="100%"><br>
      <i>The attacker downloads the ZIP archive</i>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/rkNkXzPLMg.png" width="100%"><br>
      <i>The attacker successfully retrives and unzips the ZIP archive</i>
    </td>
  </tr>
</table>

#### Result
The ZIP archive containing the collected files is transferred from the compromised workstation to the attacker-controlled infrastructure through the established C2 channel.

#### MITRE ATT&CK Mapping
- **T1041 – Exfiltration Over C2 Channel:** The collected archive is transferred to the attacker through the existing C2 channel.

### 2.7 Persistence	
#### Action
After completing the collection and exfiltration activities, the attacker executes a persistence utility on the compromised workstation.
![persistence](https://hackmd.io/_uploads/rkCZca2Ize.png)

The attacker establishes persistence by modifying the current user's Registry Run Key. The following Registry location is modified:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
A new value named `MicrosoftOffice` is created with a command that launches `update.exe`:
```
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& 'C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\update.exe'"
```
This causes the payload to be executed automatically when the affected user logs in.

#### Result
The attacker establishes a persistence mechanism that allows `update.exe` to be relaunched when the affected user logs into the workstation.

#### MITRE ATT&CK Mapping
- **T1547.001 – Registry Run Keys / Startup Folder:** The attacker creates a Registry Run Key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to automatically execute the malicious payload at user logon.

### 2.8 Cleanup
#### Action
After completing the attack, the attacker attempts to remove selected artifacts generated during the operation. The attacker deletes:
```
C:\Users\john\AppData\Local\Temp\Collected_Data.zip
C:\Users\john\Downloads\Office Security Update.exe
```
<table align="center" width="100%">
  <tr>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/SJCEqT38Ge.png" width="100%"><br>
      <i>The attacker removes Office Secutiry Update.exe</i>
    </td>
    <td align="center" width="50%">
      <img src="https://hackmd.io/_uploads/SJkKqan8Mg.png" width="100%"><br>
      <i>The attacker removes Collected_Data.zip</i>
    </td>
  </tr>
</table>

The attacker then uses the Sliver kill command to terminate the currently running implant process (update.exe) on the compromised workstation.
![killing implant process](https://hackmd.io/_uploads/rJyhqahLzx.png)


#### Result
Selected files associated with the attack are removed and the currently active implant process is terminated. However, the persistence mechanism remains present on the workstation, meaning that the malicious payload can be automatically executed again during a subsequent user logon.

#### MITRE ATT&CK Mapping
- **T1070.004 – File Deletion:** The attacker deletes selected  files to remove artifacts associated with the attack.


    
    
    
    
