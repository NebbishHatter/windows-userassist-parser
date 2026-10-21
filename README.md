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

Usage
GUI:
python app.py

CLI:
# Live analysis
python userassist.py

# Offline analysis (Any OS)
python userassist.py -f /path/to/NTUSER.DAT --save --case CASE-001

# SIEM Integration (JSON Lines)
python userassist.py --jsonl --case INCIDENT-99

Technical Architecture
ROT13 Decoding: UserAssist value names are obfuscated using ROT13; decoded automatically.

Binary Struct Parsing: Extracts execution count (offset 4:8) and FILETIME timestamp (offset 60:68) from the 72-byte binary blob.

Timezone Handling: All timestamps are normalized to UTC.

Rule-Based Detection: Heuristics are loaded from rules.json for customization without code changes.


Русский
Описание
Ключ реестра UserAssist скрыто фиксирует запуски программ через Проводник (количество запусков и время). Злоумышленники часто удаляют файлы и чистят логи, но UserAssist сохраняет следы. Инструмент парсит эти артефакты и применяет эвристики Threat Hunting для выявления аномалий.

Возможности
Живой и офлайн-анализ: Работа с текущим реестром Windows или с изъятыми файлами NTUSER.DAT на Linux/macOS.

Детектор Anti-Forensics: Обнаружение параметра NoLog = 1 (попытка скрыть следы).

Эвристики:

SUSPICIOUS_PATH: Запуск из Temp, Downloads или AppData.

MASQUERADING: Системные процессы, запущенные вне System32.

NIGHT_RUN: Запуск в период с 01:00 до 05:00 UTC.

MITRE ATT&CK: Автоматическая разметка находок техниками (T1036, T1029).

Интеграция с SIEM: Вывод в формате JSON Lines (--jsonl).

GUI и CLI: Темный графический интерфейс и консольная утилита для автоматизации.

Установка
git clone https://github.com/NebbishHatter/windows-userassist-parser.git
cd windows-userassist-parser
pip install -r requirements.txt

Использование
Графический интерфейс:
python app.py

Командная строка:
# Анализ текущей системы
python userassist.py

# Офлайн-анализ дампа реестра
python userassist.py -f /path/to/NTUSER.DAT --save --case CASE-001

# Выгрузка для SIEM
python userassist.py --jsonl --case INCIDENT-99

Технические детали
Декодирование ROT13: Имена значений автоматически расшифровываются.

Парсинг бинарных структур: Извлечение счетчика (смещение 4:8) и метки времени FILETIME (смещение 60:68).

Работа со временем: Все метки времени конвертируются в UTC.

Правила детекции: Эвристики вынесены в rules.json для изменения без правки кода.

License / Лицензия
MIT License. Developed by NebbishHatter.
