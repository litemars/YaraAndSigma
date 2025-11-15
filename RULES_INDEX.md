# Detection Rules Index

**Generated:** 2025-11-15 18:55:13 UTC

**Total Rules:** 63 (28 YARA, 35 Sigma)

---

## YARA Rules

| # | Rule Name | File |
|---|-----------|------|
| 1 | `APT41_ToughProgress` | `Yara/apt41-tough-progress.yar` |
| 2 | `APT_EggStreme_Framework` | `Yara/eggstreme-malware.yar` |
| 3 | `APT_MeshAgent_Weaponized_Awaken_Likho` | `Yara/apt-meshagent.yar` |
| 4 | `APT_MostereRAT_Banking_Trojan` | `Yara/mostere-rat.yar` |
| 5 | `APT_Tickler_Backdoor_Peach_Sandstorm` | `Yara/tickeler-backdoor.yar` |
| 6 | `COLDRIVER_COLDCOPY_ClickFix_Lure` | `Yara/coldriver-no-robot.yar` |
| 7 | `COLDRIVER_MAYBEROBOT_Powershell_Backdoor` | `Yara/coldriver-no-robot.yar` |
| 8 | `COLDRIVER_NOROBOT_Downloader` | `Yara/coldriver-no-robot.yar` |
| 9 | `COLDRIVER_YESROBOT_Python_Backdoor` | `Yara/coldriver-no-robot.yar` |
| 10 | `Charon_DLL_Sideloading` | `Yara/Charon_DLL_Sideloading.yar` |
| 11 | `Charon_Ransomware_August_2025` | `Yara/Charon_Ransomware_August_2025.yar` |
| 12 | `DripDropper_Linux_Malware` | `Yara/dripdropper-malware.yar` |
| 13 | `DripDropper_Network_IOCs` | `Yara/dripdropper-malware.yar` |
| 14 | `GodRAT_Malware_August_2025` | `Yara/godrat-malware-august-2025.yar` |
| 15 | `GodRAT_Steganography_Loader` | `Yara/godrat-steganography-loader.yar` |
| 16 | `Kalambur_Backdoor_Detection` | `Yara/kalabur-backdoor.yar` |
| 17 | `Kalambur_FileHash_Known_Sample` | `Yara/kalabur-backdoor.yar` |
| 18 | `LameHug_APT28_Infostealer` | `Yara/lamehug-apt28-infostealer.yar` |
| 19 | `MiniJunk_UserEnv_DLL_Loader` | `Yara/minijunk-dllloader.yar` |
| 20 | `NET_STAR_IIServerCore` | `Yara/net-start.yar` |
| 21 | `NubSpy_ScarCruft_Backdoor` | `Yara/nubspy-malware.yar` |
| 22 | `PlugX_UNC6384_Detection` | `Yara/plugx.yar` |
| 23 | `PyLangGhost_RAT_Lazarus_August_2025` | `Yara/py-lang-ghost-rat-lazarus-august-2025.yar` |
| 24 | `ScarCruft_VCD_Ransomware` | `Yara/nubspy-malware.yar` |
| 25 | `ShadowPad_Modular_Backdoor` | `Yara/shadowpad-backdoor.yar` |
| 26 | `ToughProgress_APT41_2025` | `Yara/ToughProgress.yar` |
| 27 | `ZEROLOT_Wiper_Malware` | `Yara/zerolot-malware.yar` |
| 28 | `wAgent_Lazarus_Backdoor` | `Yara/wagent-lazarus-backdoor.yar` |

---

## Sigma Rules

### 🔴 CRITICAL

| # | Title | File |
|---|-------|------|
| 1 | COLDRIVER NOROBOT BITSAdmin File Download from C2 | `Sigma/coldriver-norobot-bitsadmin-file-download-sigma-rule.yml` |
| 2 | COLDRIVER NOROBOT Malicious DLL Execution via Rundll32 | `Sigma/coldriver-norobot-rundll-dll-execution-sigma-rule.yml` |
| 3 | COLDRIVER NOROBOT Registry Persistence Mechanism | `Sigma/coldriver-norobot-registry-persistence-sigma-rule.yml` |
| 4 | Charon Ransomware Activity Detection | `Sigma/charon-ransomware-sigma-rule.yml` |
| 5 | DripDropper Apache ActiveMQ Exploitation | `Sigma/dripdropper-activemq-exploitation-sigma-rule.yml` |
| 6 | LameHug APT28 LLM-Powered Infostealer Detection | `Sigma/lamehug-apt28-infostealer.yml` |
| 7 | ScarCruft VCD Ransomware Deployment | `Sigma/nubspy-vcd-ransomware-deployment-sigma-rule.yml` |
| 8 | ZEROLOT Wiper Malware Detection | `Sigma/zerolot-wiper-malware-detection-sigma-rule.yml` |

### 🟠 HIGH

| # | Title | File |
|---|-------|------|
| 1 | COLDRIVER MAYBEROBOT Logon Script Persistence | `Sigma/coldriver-mayberobot-logon-script-persistence-sigma-rule.yml` |
| 2 | COLDRIVER MAYBEROBOT PowerShell Backdoor Network Activity | `Sigma/coldriver-mayberobot-powershell-backdoor-network-activity-sigma-rule.yml` |
| 3 | COLDRIVER YESROBOT Python Backdoor Scheduled Task Persistence | `Sigma/coldriver-yesrobot-python-scheduled-task-persistence-sigma-rule.yml` |
| 4 | DripDropper Dropbox C2 Communication | `Sigma/dripdropper-dropbox-c2-sigma-rule.yml` |
| 5 | DripDropper Persistence Mechanisms | `Sigma/dripdropper-persistence-sigma-rule.yml` |
| 6 | DripDropper Sliver C2 Framework Usage | `Sigma/dripdropper-sliver-c2-sigma-rule.yml` |
| 7 | EggStreme APT Framework Detection | `Sigma/eggstreme-sigma-rule.yml` |
| 8 | GodRAT Remote Access Trojan Detection | `Sigma/godrat-sigma-rule.yml` |
| 9 | Kalambur Backdoor Curl TOR SOCKS Proxy Execution | `Sigma/kalabur-backdoor-sigma-rule.yml` |
| 10 | MostereRAT Banking Trojan Activity | `Sigma/mostere-rat-sigma-rule.yml` |
| 11 | NET-STAR IIServerCore Execution | `Sigma/net-star-sigma-rule.yml` |
| 12 | NubSpy Memory Execution Pattern | `Sigma/nubspy-memory-execution-pattern-sigma-rule.yml` |
| 13 | PlugX RAT Malware Detection - UNC6384 Diplomatic Espionage | `Sigma/plugx-rat-sigma-rule.yml` |
| 14 | PyLangGhost RAT Lazarus Group Campaign | `Sigma/py-lang-ghost-rat-sigma-rule.yml` |
| 15 | ScarCruft NubSpy Phishing Campaign Detection | `Sigma/nubspy-phishing-campaign-detection-sigma-rule.yml` |
| 16 | Suspicious DLL Loading from Alternate Path (MiniJunk) | `Sigma/minijunk-dll-loader-sigma-rule.yml` |
| 17 | Suspicious Rundll32 Execution of APT41 ToughProgress Module | `Sigma/toughprogress-apt41-sigma-rule.yml` |
| 18 | Tickler Malware Process Execution Pattern | `Sigma/tickeler-backdoor-peach-sandstorm-sigma-rule.yml` |
| 19 | ToughProgress APT41 Google Calendar C2 Detection | `Sigma/toughprogress-sigma-rule.yml` |
| 20 | Weaponized MeshAgent Activity by Awaken Likho APT | `Sigma/meshagent-sigma-rule.yml` |
| 21 | ZEROLOT File System Manipulation | `Sigma/zerolot-file-system-manipulation-sigma-rule.yml` |
| 22 | ZEROLOT Process Injection and Evasion | `Sigma/zerolot-process-injection-and-evasion-sigma-rule.yml` |

### 🟡 MEDIUM

| # | Title | File |
|---|-------|------|
| 1 | DripDropper Post-Exploitation Patching | `Sigma/dripdropper-post-exploitation-patching-sigma-rule.yml` |
| 2 | NubSpy PubNub C2 Communication | `Sigma/nubspy-pubnub-c2-communication-sigma-rule.yml` |
| 3 | ScarCruft Multi-Language Lure Detection | `Sigma/nubspy-multi-language-lure-detection-sigma-rule.yml` |
| 4 | ScarCruft Registry Autorun Disabling | `Sigma/nubspy-registry-autorun-disabling-sigma-rule.yml` |
| 5 | ZEROLOT Network Communication Patterns | `Sigma/zerolot-network-communication-patterns-sigma-rule.yml` |


---

