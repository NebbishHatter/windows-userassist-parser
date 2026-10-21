# ==============================================================================
# Project: Windows UserAssist Forensic Parser
# Author:  NebbishHatter
# ==============================================================================
import codecs, struct, json, csv, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
import argparse
from typing import Dict, List, Any, Optional

try:
    import winreg
except ImportError:
    winreg = None
try:
    from Registry import Registry
except ImportError:
    Registry = None

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

USER_ASSIST_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
console = Console()

MITRE_MAPPING = {
    "SUSPICIOUS_PATH": "T1036.003", 
    "MASQUERADING": "T1036.005",    
    "NIGHT_RUN": "T1029"            
}

def load_rules() -> Dict[str, List[str]]:
    default_rules = {
        "suspicious_paths": ["\\downloads\\", "\\temp\\", "\\desktop\\", "appdata\\local\\temp"],
        "system_binaries": ["svchost.exe", "lsass.exe", "cmd.exe", "explorer.exe", "winlogon.exe"]
    }
    if Path("rules.json").exists():
        try:
            with open("rules.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default_rules
    return default_rules

RULES = load_rules()

KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "%System32%",
    "{F3BEE67E-CEAC-4667-8A5E-31F82BA3A4F8}": "%ProgramFiles%",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%TaskBar%",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%StartMenu%",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramFiles%",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFilesx64%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFilesx86%"
}

FLAG_COLORS = {
    "SUSPICIOUS_PATH": "[bold red]SUSPICIOUS_PATH[/bold red]",
    "MASQUERADING": "[bold red]MASQUERADING[/bold red]",
    "NIGHT_RUN": "[bold yellow]NIGHT_RUN[/bold yellow]"
}

def decode_rot13(text: str) -> str:
    return codecs.decode(text, 'rot_13')

def filetime_to_dt(ft: int) -> Optional[datetime]:
    if ft == 0: return None
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft / 10)

def resolve_path(decoded_name: str) -> str:
    for guid, folder in KNOWN_FOLDERS.items():
        if guid in decoded_name:
            return decoded_name.replace(guid, folder)
    return decoded_name

def analyze_heuristics(program_path: str, last_run_dt: Optional[datetime]) -> List[str]:
    flags = []
    path_lower = program_path.lower()
    if any(s_dir in path_lower for s_dir in RULES.get("suspicious_paths", [])):
        flags.append("SUSPICIOUS_PATH")
    filename = Path(program_path).name.lower()
    if filename in RULES.get("system_binaries", []):
        if "%system32%" not in path_lower and "\\system32\\" not in path_lower:
            flags.append("MASQUERADING")
    if last_run_dt and (1 <= last_run_dt.hour <= 5):
        flags.append("NIGHT_RUN")
    return flags

def process_raw_data(val_name: str, val_data: bytes) -> Optional[Dict[str, Any]]:
    try:
        decoded_name = decode_rot13(val_name)
    except Exception:
        return None
    if "CTLSESSION" in decoded_name or not decoded_name.strip():
        return None
    if len(val_data) >= 68:
        run_count = struct.unpack('<I', val_data[4:8])[0]
        filetime = struct.unpack('<Q', val_data[60:68])[0]
        last_run_dt = filetime_to_dt(filetime)
        if last_run_dt and run_count > 0:
            clean_path = resolve_path(decoded_name)
            flags = analyze_heuristics(clean_path, last_run_dt)
            mitre_tags = [MITRE_MAPPING[f] for f in flags if f in MITRE_MAPPING]
            return {
                "program": clean_path,
                "run_count": run_count,
                "last_run_utc": last_run_dt.strftime('%Y-%m-%d %H:%M:%S'),
                "flags": flags,
                "mitre_attack": list(set(mitre_tags)),
                "is_suspicious": len(flags) > 0
            }
    return None

def check_anti_cleaning(reg_obj: Any = None, is_live: bool = False) -> bool:
    try:
        if is_live and winreg:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_ASSIST_PATH) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "NoLog")
                    if val == 1: return True
                except FileNotFoundError: pass
        elif reg_obj:
            normalized_path = USER_ASSIST_PATH.replace('\\', '/')
            key = reg_obj.open(normalized_path)
            for val in key.values():
                if val.name() == "NoLog" and val.value() == 1: return True
    except Exception: pass
    return False

def collect_live() -> Optional[List[Dict[str, Any]]]:
    if winreg is None: return None
    results = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, USER_ASSIST_PATH) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, subkey_name) as subkey:
                    try:
                        with winreg.OpenKey(subkey, "Count") as count_key:
                            for k in range(winreg.QueryInfoKey(count_key)[1]):
                                try:
                                    val_name, val_data, _ = winreg.EnumValue(count_key, k)
                                    item = process_raw_data(val_name, val_data)
                                    if item: results.append(item)
                                except OSError: pass
                    except FileNotFoundError: pass
    except FileNotFoundError:
        return []
    return results

def collect_offline(file_path: str) -> Optional[List[Dict[str, Any]]]:
    if Registry is None: return None
    results = []
    try:
        reg = Registry.Registry(file_path)
        normalized_path = USER_ASSIST_PATH.replace('\\', '/')
        key = reg.open(normalized_path)
        for subkey in key.subkeys():
            try:
                count_key = subkey.subkey("Count")
                for value in count_key.values():
                    item = process_raw_data(value.name(), value.value())
                    if item: results.append(item)
            except Registry.RegistryKeyNotFoundException: pass
    except Exception:
        return None
    return results

def print_table(data: List[Dict[str, Any]]) -> None:
    table = Table(title="[bold cyan]UserAssist Forensic Artifacts[/bold cyan]", show_lines=True)
    table.add_column("Program", style="cyan", overflow="fold")
    table.add_column("Run Count", justify="center")
    table.add_column("Last Run (UTC)", justify="center")
    table.add_column("Threat Flags", justify="center")
    table.add_column("MITRE", justify="center")
    for item in data:
        color_flags = [FLAG_COLORS.get(f, f) for f in item['flags']]
        flags_str = " ".join(color_flags) if color_flags else "[green]Clean[/green]"
        mitre_str = "\n".join(item['mitre_attack']) if item['mitre_attack'] else "-"
        table.add_row(item['program'], str(item['run_count']), item['last_run_utc'], flags_str, mitre_str)
    console.print(table)

def save_reports(data: List[Dict[str, Any]], case_id: str, output_dir: str) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_file = output_path / f"{case_id}_{timestamp}.json"
    csv_file = output_path / f"{case_id}_{timestamp}.csv"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump({"case_id": case_id, "data": data}, f, indent=4, ensure_ascii=False)
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Program", "Run Count", "Last Run (UTC)", "Flags", "MITRE ATT&CK"])
        for item in data:
            writer.writerow([item["program"], item["run_count"], item["last_run_utc"], ", ".join(item["flags"]), ", ".join(item["mitre_attack"])])

def main() -> None:
    parser = argparse.ArgumentParser(description="Windows UserAssist Forensic Parser by NebbishHatter")
    parser.add_argument("-f", "--file", type=str, help="Path to NTUSER.DAT for offline analysis")
    parser.add_argument("-c", "--case", type=str, default="CASE-DEFAULT", help="Case ID for the report")
    parser.add_argument("-o", "--output", type=str, default="Reports", help="Output directory")
    parser.add_argument("--save", action="store_true", help="Save results to JSON and CSV files")
    parser.add_argument("--no-console", action="store_true", help="Do not print the table to console")
    parser.add_argument("--jsonl", action="store_true", help="Output stream as JSON Lines (SIEM integration)")
    args = parser.parse_args()

    if not args.jsonl:
        console.print(Panel.fit("[bold magenta]Windows UserAssist Parser v1.1.0[/bold magenta]\n[italic]Developed by NebbishHatter[/italic]", border_style="magenta"))
    
    reg_obj = None
    if args.file:
        if not args.jsonl: console.print(f"[yellow][*] Offline analysis: {args.file}[/yellow]")
        data = collect_offline(args.file)
        try:
            if Registry: reg_obj = Registry.Registry(args.file)
        except Exception: pass
    else:
        if not args.jsonl: console.print("[yellow][*] Extracting from live registry...[/yellow]")
        data = collect_live()

    if data is None: sys.exit(1)
    is_cleaned = check_anti_cleaning(reg_obj=reg_obj, is_live=not args.file)
    if is_cleaned and not args.jsonl:
        console.print("[bold blink red][!] WARNING: NoLog detected. Someone tried to wipe their tracks.[/bold blink red]")
    if not data:
        if not args.jsonl: console.print("[bold yellow][!] No UserAssist records found.[/bold yellow]")
        sys.exit(0)

    data.sort(key=lambda x: x['last_run_utc'], reverse=True)
    data.sort(key=lambda x: x['is_suspicious'], reverse=True)

    if args.jsonl:
        for item in data:
            item["case_id"] = args.case
            item["anti_cleaning_triggered"] = is_cleaned
            del item["is_suspicious"] 
            sys.stdout.write(json.dumps(item, ensure_ascii=False) + "\n")
        sys.exit(0)

    suspicious_count = sum(1 for item in data if item['is_suspicious'])
    console.print(f"[*] Total records: {len(data)}. Suspicious: {suspicious_count}")
    if not args.no_console: print_table(data)
    if args.save:
        save_reports(data, args.case, args.output)
        console.print(f"[bold green][+] Reports saved to: {args.output}[/bold green]")

if __name__ == "__main__":
    main()