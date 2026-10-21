import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
import threading
from userassist import collect_live, check_anti_cleaning

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class UserAssistApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("UserAssist Forensic Parser - by NebbishHatter")
        self.geometry("1000x600")

        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.pack(pady=20, padx=20, fill="x")
        self.scan_btn = ctk.CTkButton(self.top_frame, text="Scan Live System", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=10)
        self.status_label = ctk.CTkLabel(self.top_frame, text="Status: Ready", text_color="gray")
        self.status_label.pack(side="left", padx=20)
        self.warning_label = ctk.CTkLabel(self.top_frame, text="", text_color="red", font=("Arial", 14, "bold"))
        self.warning_label.pack(side="right", padx=10)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", rowheight=30, font=("Consolas", 11))
        style.map('Treeview', background=[('selected', '#1f538d')])
        style.configure("Treeview.Heading", font=("Arial", 12, "bold"))

        self.tree_frame = ctk.CTkFrame(self)
        self.tree_frame.pack(pady=10, padx=20, fill="both", expand=True)
        columns = ("Program", "Run Count", "Last Run (UTC)", "Flags", "MITRE")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings")
        self.tree.heading("Program", text="Program Path")
        self.tree.heading("Run Count", text="Runs")
        self.tree.heading("Last Run (UTC)", text="Last Run (UTC)")
        self.tree.heading("Flags", text="Threat Flags")
        self.tree.heading("MITRE", text="MITRE ATT&CK")
        self.tree.column("Program", width=400)
        self.tree.column("Run Count", width=60, anchor="center")
        self.tree.column("Last Run (UTC)", width=150, anchor="center")
        self.tree.column("Flags", width=150, anchor="center")
        self.tree.column("MITRE", width=100, anchor="center")

        scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def start_scan(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        self.scan_btn.configure(state="disabled")
        self.status_label.configure(text="Status: Scanning registry...")
        self.warning_label.configure(text="")
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        data = collect_live()
        is_cleaned = check_anti_cleaning(is_live=True)
        self.after(0, self.update_ui, data, is_cleaned)

    def update_ui(self, data, is_cleaned):
        self.scan_btn.configure(state="normal")
        if is_cleaned: self.warning_label.configure(text="[!] WARNING: NoLog detected")
        if not data:
            self.status_label.configure(text="Status: No UserAssist records found.")
            return
        data.sort(key=lambda x: x['last_run_utc'], reverse=True)
        data.sort(key=lambda x: x['is_suspicious'], reverse=True)
        suspicious_count = 0
        for item in data:
            flags_str = ", ".join(item['flags']) if item['flags'] else "Clean"
            mitre_str = ", ".join(item['mitre_attack']) if item['mitre_attack'] else "-"
            tags = ('suspicious',) if item['is_suspicious'] else ()
            if item['is_suspicious']: suspicious_count += 1
            self.tree.insert("", "end", values=(item['program'], item['run_count'], item['last_run_utc'], flags_str, mitre_str), tags=tags)
        self.tree.tag_configure('suspicious', foreground='#ff6b6b')
        self.status_label.configure(text=f"Status: Done. Total: {len(data)} | Suspicious: {suspicious_count}")

if __name__ == "__main__":
    app = UserAssistApp()
    app.mainloop()