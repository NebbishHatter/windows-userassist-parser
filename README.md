# Windows UserAssist Forensic Parser

A cross-platform DFIR tool for extracting and analyzing Windows `UserAssist` registry artifacts from live systems or offline hives (`NTUSER.DAT`).

*Кроссплатформенный инструмент цифровой криминалистики (DFIR) для извлечения и анализа артефактов реестра Windows `UserAssist` с живых систем или офлайн-дампов (`NTUSER.DAT`).*

---

## English

### Overview
The `UserAssist` registry key tracks GUI-based program executions (execution count and timestamps). Attackers often delete payloads and clear system logs, but `UserAssist` frequently retains the evidence. This tool parses these artifacts and applies threat-hunting heuristics to highlight suspicious activity.

### Features
- **Live & Offline Analysis:** Parse the active registry on Windows, or analyze extracted `NTUSER.DAT` files on Linux/macOS.
- **Anti-Forensics Detection:** Detects if the `NoLog` registry parameter is set to `1` (indicates deliberate log suppression).
- **Threat Hunting Heuristics:**
  - `SUSPICIOUS_PATH`: Execution from Temp, Downloads, or AppData.
  - `MASQUERADING`: Legitimate system binaries running from non-standard paths.
  - `NIGHT_RUN`: Execution between 01:00 and 05:00 UTC.
- **MITRE ATT&CK Mapping:** Tags findings with relevant technique IDs (e.g., T1036, T1029).
- **SIEM Integration:** Outputs findings as JSON Lines (`--jsonl`) for SIEM ingestion.
- **GUI & CLI:** Includes a dark-themed graphical interface and a command-line tool for automation.

### Installation
```bash
git clone https://github.com/NebbishHatter/windows-userassist-parser.git
cd windows-userassist-parser
pip install -r requirements.txt
