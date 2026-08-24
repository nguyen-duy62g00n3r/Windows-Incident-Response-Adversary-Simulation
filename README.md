#### ⚠️ Disclaimer
This project is created for research and educational purposes and is conducted entirely within a controlled laboratory environment. The author does not endorse or assume responsibility for any illegal, unauthorized, or harmful use of the techniques, tools, or concepts described in this project. The techniques demonstrated in this project should only be reproduced in environments where the user has explicit authorization.

---

# Windows Incident Response & Adversary Simulation

## 1. Project Goals
This project aims to simulate a Windows security incident and demonstrate an Incident Response process from initial detection to investigation, containment, eradication, recovery, and defensive improvement. The primary objectives are to:
- Simulate a realistic post compromise attack chain in a controlled Windows environment.
- Generate and collect endpoint and network telemetry produced by the simulated attack.
- Investigate the incident using a combination of SIEM, endpoint, filesystem, Registry, PowerShell, and network evidence.
- Reconstruct the attack timeline and assess the attacker's objectives and impact.
- Develop detection improvements based on findings from the investigation.

## 2. Project Overview
The project consists of two connected components:

**Attack Simulation**
A controlled Windows attack scenario is simulated using a phishing initial access vector, a malicious dropper, a second-stage payload, encrypted C2 communication, host discovery, data collection, archive creation, persistence, and artifact removal. The simulated attack is designed to generate realistic endpoint and network artifacts that can subsequently be investigated.

**Incident Response**
The generated telemetry is investigated using an Incident Response methodology covering:
- Preparation
- Detection & Initial Triage
- Evidence Acquisition & Initial Scoping
- Investigation & Analysis
- Containment, Eradication & Recovery

The investigation combines centralized SIEM telemetry with endpoint artifacts and network evidence to reconstruct the incident and evaluate its impact.

## 3. Environment & Technologies
The laboratory environment primarily consists of:
- **Windows Workstation** – Simulated employee endpoint.
- **Network Gateway** – Provides network connectivity and packet capture.
- **Splunk Enterprise** – Centralized SIEM and detection platform.
- **Sysmon** – Endpoint process, file, Registry, and network telemetry.
- **PowerShell Operational Logging** – PowerShell execution telemetry.
- **Wireshark** – Network and PCAP analysis.
- **Registry Explorer** – Registry investigation.
- **JournalViewer** – NTFS journal and filesystem artifact analysis.
- **Sliver** – Controlled C2 and adversary simulation.

## 4. Scope & Limitations
This project is intentionally limited to a small controlled Windows environment and does not attempt to reproduce the full complexity of an enterprise Incident Response operation. The project focuses primarily on endpoint and network evidence available from the simulated environment. Memory acquisition and enterprise telemetry from additional endpoints are outside the project scope.

---

<p align="center">
  <b>Documentation created for educational purposes, technical research, and community knowledge sharing.</b>
</p>
