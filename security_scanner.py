#!/usr/bin/env python3
"""Windows 11 Security Settings Scanner — scan, enable, and disable security features."""

import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk

# ── Admin helpers ─────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate() -> None:
    import ctypes
    args = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    sys.exit(0)


# ── PowerShell runner ─────────────────────────────────────────────────────────

def run_ps(cmd: str) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", -1
    except Exception as exc:
        return "", str(exc), -1


# ── Security settings catalogue ───────────────────────────────────────────────
#
# enabled_check modes:
#   (default)       compare raw output to enabled_value (case-insensitive)
#   "nonzero"       any non-zero integer / non-"false" output → enabled
#   "running"       service status == "Running"
#   "not_disabled"  service StartType != "Disabled"
#   "notempty_nooff" non-empty and not "Off"
#
SETTINGS: list[dict] = [
    # ── Windows Defender ─────────────────────────────────────────────────────
    {
        "name": "Real-Time Protection",
        "category": "Defender",
        "desc": "Scans files as they are accessed",
        "check_cmd": "(Get-MpPreference).DisableRealtimeMonitoring",
        "enabled_value": "False",
        "enable_cmd": "Set-MpPreference -DisableRealtimeMonitoring $false",
        "disable_cmd": "Set-MpPreference -DisableRealtimeMonitoring $true",
    },
    {
        "name": "Behavior Monitoring",
        "category": "Defender",
        "desc": "Monitors running processes for malicious behavior",
        "check_cmd": "(Get-MpPreference).DisableBehaviorMonitoring",
        "enabled_value": "False",
        "enable_cmd": "Set-MpPreference -DisableBehaviorMonitoring $false",
        "disable_cmd": "Set-MpPreference -DisableBehaviorMonitoring $true",
    },
    {
        "name": "Download Scanning (IOAV)",
        "category": "Defender",
        "desc": "Scans files downloaded from the internet",
        "check_cmd": "(Get-MpPreference).DisableIOAVProtection",
        "enabled_value": "False",
        "enable_cmd": "Set-MpPreference -DisableIOAVProtection $false",
        "disable_cmd": "Set-MpPreference -DisableIOAVProtection $true",
    },
    {
        "name": "Script Scanning",
        "category": "Defender",
        "desc": "Scans scripts before they are executed",
        "check_cmd": "(Get-MpPreference).DisableScriptScanning",
        "enabled_value": "False",
        "enable_cmd": "Set-MpPreference -DisableScriptScanning $false",
        "disable_cmd": "Set-MpPreference -DisableScriptScanning $true",
    },
    {
        "name": "Network Protection",
        "category": "Defender",
        "desc": "Blocks connections to known-malicious domains",
        "check_cmd": "[int](Get-MpPreference).EnableNetworkProtection",
        "enabled_check": "nonzero",
        "enable_cmd": "Set-MpPreference -EnableNetworkProtection Enabled",
        "disable_cmd": "Set-MpPreference -EnableNetworkProtection Disabled",
    },
    {
        "name": "Cloud Protection (MAPS)",
        "category": "Defender",
        "desc": "Sends samples to Microsoft cloud for fast analysis",
        "check_cmd": "[int](Get-MpPreference).MAPSReporting",
        "enabled_check": "nonzero",
        "enable_cmd": "Set-MpPreference -MAPSReporting Advanced",
        "disable_cmd": "Set-MpPreference -MAPSReporting Disabled",
    },
    {
        "name": "Controlled Folder Access",
        "category": "Defender",
        "desc": "Protects sensitive folders from ransomware",
        "check_cmd": "[int](Get-MpPreference).EnableControlledFolderAccess",
        "enabled_check": "nonzero",
        "enable_cmd": "Set-MpPreference -EnableControlledFolderAccess Enabled",
        "disable_cmd": "Set-MpPreference -EnableControlledFolderAccess Disabled",
    },
    # ── Firewall ─────────────────────────────────────────────────────────────
    {
        "name": "Firewall - Domain",
        "category": "Firewall",
        "desc": "Firewall for domain / corporate networks",
        "check_cmd": "(Get-NetFirewallProfile -Profile Domain).Enabled",
        "enabled_value": "True",
        "enable_cmd": "Set-NetFirewallProfile -Profile Domain -Enabled True",
        "disable_cmd": "Set-NetFirewallProfile -Profile Domain -Enabled False",
    },
    {
        "name": "Firewall - Private",
        "category": "Firewall",
        "desc": "Firewall for private / home networks",
        "check_cmd": "(Get-NetFirewallProfile -Profile Private).Enabled",
        "enabled_value": "True",
        "enable_cmd": "Set-NetFirewallProfile -Profile Private -Enabled True",
        "disable_cmd": "Set-NetFirewallProfile -Profile Private -Enabled False",
    },
    {
        "name": "Firewall - Public",
        "category": "Firewall",
        "desc": "Firewall for public / unsecured networks",
        "check_cmd": "(Get-NetFirewallProfile -Profile Public).Enabled",
        "enabled_value": "True",
        "enable_cmd": "Set-NetFirewallProfile -Profile Public -Enabled True",
        "disable_cmd": "Set-NetFirewallProfile -Profile Public -Enabled False",
    },
    # ── System ───────────────────────────────────────────────────────────────
    {
        "name": "User Account Control (UAC)",
        "category": "System",
        "desc": "Prompts for elevation when admin rights are needed",
        "check_cmd": "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
        "enabled_value": "1",
        "enable_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0",
    },
    {
        "name": "SmartScreen (Explorer)",
        "category": "System",
        "desc": "Warns about malicious downloads and websites",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -ErrorAction SilentlyContinue).SmartScreenEnabled",
        "enabled_check": "notempty_nooff",
        "enable_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value On",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value Off",
    },
    {
        "name": "Windows Update Service",
        "category": "System",
        "desc": "Downloads and installs Windows security updates",
        "check_cmd": "(Get-Service wuauserv).StartType",
        "enabled_check": "not_disabled",
        "enable_cmd": "Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv -ErrorAction SilentlyContinue",
        "disable_cmd": "Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; Set-Service wuauserv -StartupType Disabled",
    },
    {
        "name": "Windows Defender Service",
        "category": "System",
        "desc": "Core Windows Defender antivirus service",
        "check_cmd": "(Get-Service WinDefend).Status",
        "enabled_check": "running",
        "enable_cmd": "Set-Service WinDefend -StartupType Automatic; Start-Service WinDefend -ErrorAction SilentlyContinue",
        "disable_cmd": "Stop-Service WinDefend -Force -ErrorAction SilentlyContinue; Set-Service WinDefend -StartupType Disabled",
    },
    # ── Remote Access ────────────────────────────────────────────────────────
    {
        "name": "Remote Desktop (RDP)",
        "category": "Remote Access",
        "desc": "Allows incoming remote desktop connections",
        "check_cmd": "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
        "enabled_value": "0",
        "enable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0; Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled True -ErrorAction SilentlyContinue",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1; Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled False -ErrorAction SilentlyContinue",
    },
    {
        "name": "Remote Registry",
        "category": "Remote Access",
        "desc": "Allows remote access to this machine's registry",
        "check_cmd": "(Get-Service RemoteRegistry).Status",
        "enabled_check": "running",
        "enable_cmd": "Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry -ErrorAction SilentlyContinue",
        "disable_cmd": "Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue; Set-Service RemoteRegistry -StartupType Disabled",
    },
]


def check_is_enabled(setting: dict, raw: str) -> bool:
    out = raw.strip()
    mode = setting.get("enabled_check")
    if mode == "nonzero":
        try:
            return int(out) != 0
        except ValueError:
            return out.lower() not in ("0", "false", "disabled", "")
    elif mode == "running":
        return out.lower() == "running"
    elif mode == "notempty_nooff":
        return bool(out) and out.lower() not in ("off", "0", "false", "")
    elif mode == "not_disabled":
        return out.lower() != "disabled"
    else:
        expected = str(setting.get("enabled_value", "True"))
        return out.lower() == expected.lower()


# ── GUI ───────────────────────────────────────────────────────────────────────

class App(tk.Tk):
    COLS = ("Setting", "Category", "Status", "Description")

    # Catppuccin Mocha-inspired palette
    BG     = "#1e1e2e"
    SURFACE = "#181825"
    OVERLAY = "#313244"
    FG     = "#cdd6f4"
    SUBTEXT = "#a6adc8"
    ACCENT = "#cba6f7"
    BLUE   = "#89b4fa"
    GREEN  = "#a6e3a1"
    RED    = "#f38ba8"
    YELLOW = "#f9e2af"

    def __init__(self) -> None:
        super().__init__()
        self.title("Windows 11 Security Settings Scanner")
        self.geometry("980x660")
        self.minsize(720, 480)
        self.configure(bg=self.BG)
        self._build_styles()
        self._build_ui()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _build_styles(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure("TFrame",       background=self.BG)
        s.configure("TLabel",       background=self.BG,      foreground=self.FG,
                    font=("Segoe UI", 10))
        s.configure("Header.TLabel", background=self.BG,     foreground=self.ACCENT,
                    font=("Segoe UI", 14, "bold"))
        s.configure("Sub.TLabel",   background=self.BG,      foreground=self.SUBTEXT,
                    font=("Segoe UI", 9))

        for name, bg, active_bg in (
            ("Scan.TButton",    self.BLUE,  "#7aa2d4"),
            ("Enable.TButton",  self.GREEN, "#89c98b"),
            ("Disable.TButton", self.RED,   "#d4748a"),
        ):
            s.configure(name, font=("Segoe UI", 10, "bold"), foreground=self.SURFACE,
                        background=bg, padding=(14, 7), relief="flat")
            s.map(name, background=[("active", active_bg), ("disabled", "#45475a")])

        s.configure("Treeview",
                    background=self.SURFACE, foreground=self.FG,
                    fieldbackground=self.SURFACE, rowheight=28,
                    font=("Segoe UI", 10), borderwidth=0)
        s.configure("Treeview.Heading",
                    background=self.SURFACE, foreground=self.ACCENT,
                    font=("Segoe UI", 10, "bold"), padding=(4, 6), relief="flat")
        s.map("Treeview",
              background=[("selected", self.OVERLAY)],
              foreground=[("selected", self.FG)])

        s.configure("Vertical.TScrollbar",
                    background=self.OVERLAY, troughcolor=self.SURFACE,
                    arrowcolor=self.SUBTEXT, borderwidth=0)

    # ── UI layout ─────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # Header
        hdr = ttk.Frame(self, padding=(18, 14, 18, 6))
        hdr.pack(fill=tk.X)
        ttk.Label(hdr, text="Windows 11 Security Settings Scanner",
                  style="Header.TLabel").pack(side=tk.LEFT)
        admin_text = ("✓ Running as Administrator" if is_admin()
                      else "⚠  Not Administrator — changes may fail")
        admin_fg = self.GREEN if is_admin() else self.RED
        ttk.Label(hdr, text=admin_text, style="Sub.TLabel",
                  foreground=admin_fg).pack(side=tk.RIGHT)

        # Separator
        tk.Frame(self, bg=self.OVERLAY, height=1).pack(fill=tk.X, padx=18)

        # Toolbar
        tb = ttk.Frame(self, padding=(18, 10, 18, 6))
        tb.pack(fill=tk.X)
        self._scan_btn = ttk.Button(tb, text="  Scan", style="Scan.TButton",
                                    command=self._scan_threaded)
        self._scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        self._enable_btn = ttk.Button(tb, text="  Enable All", style="Enable.TButton",
                                      command=self._confirm_enable_all)
        self._enable_btn.pack(side=tk.LEFT, padx=(0, 10))
        self._disable_btn = ttk.Button(tb, text="  Disable All", style="Disable.TButton",
                                       command=self._confirm_disable_all)
        self._disable_btn.pack(side=tk.LEFT)
        self._ts_lbl = ttk.Label(tb, text="Not scanned yet", style="Sub.TLabel")
        self._ts_lbl.pack(side=tk.RIGHT)

        # Summary counts
        counts_frame = ttk.Frame(self, padding=(18, 0, 18, 6))
        counts_frame.pack(fill=tk.X)
        self._enabled_var  = tk.StringVar(value="Enabled: —")
        self._disabled_var = tk.StringVar(value="Disabled: —")
        self._total_var    = tk.StringVar(value=f"Total: {len(SETTINGS)}")
        for var, fg in (
            (self._enabled_var,  self.GREEN),
            (self._disabled_var, self.RED),
            (self._total_var,    self.SUBTEXT),
        ):
            tk.Label(counts_frame, textvariable=var, bg=self.BG, fg=fg,
                     font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 18))

        # Tree
        tree_frame = ttk.Frame(self, padding=(18, 0))
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self._tree = ttk.Treeview(tree_frame, columns=self.COLS,
                                  show="headings", selectmode="browse")
        for col, width in zip(self.COLS, (220, 110, 90, 0)):
            self._tree.heading(col, text=col)
            if width:
                self._tree.column(col, width=width, minwidth=60, stretch=False)
            else:
                self._tree.column(col, minwidth=120, stretch=True)

        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                            command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._tree.tag_configure("enabled",  foreground=self.GREEN)
        self._tree.tag_configure("disabled", foreground=self.RED)
        self._tree.tag_configure("unknown",  foreground=self.YELLOW)

        for s in SETTINGS:
            self._tree.insert("", tk.END, iid=s["name"],
                              values=(s["name"], s["category"], "?", s["desc"]),
                              tags=("unknown",))

        # Right-click context menu
        self._ctx_menu = tk.Menu(self, tearoff=False, bg=self.OVERLAY,
                                 fg=self.FG, activebackground=self.BLUE,
                                 activeforeground=self.SURFACE)
        self._ctx_menu.add_command(label="Enable this setting",
                                   command=lambda: self._toggle_selected(True))
        self._ctx_menu.add_command(label="Disable this setting",
                                   command=lambda: self._toggle_selected(False))
        self._tree.bind("<Button-3>", self._show_ctx_menu)

        # Log
        log_frame = ttk.Frame(self, padding=(18, 6, 18, 6))
        log_frame.pack(fill=tk.X)
        tk.Label(log_frame, text="Activity Log", bg=self.BG, fg=self.SUBTEXT,
                 font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(0, 3))
        self._log = scrolledtext.ScrolledText(
            log_frame, height=6,
            bg=self.SURFACE, fg=self.FG, insertbackground=self.FG,
            font=("Consolas", 9), relief=tk.FLAT, state=tk.DISABLED,
        )
        self._log.pack(fill=tk.X)

        # Status bar
        self._status_var = tk.StringVar(value="Ready  —  right-click a row to toggle individual settings")
        tk.Label(self, textvariable=self._status_var, bg="#11111b", fg=self.SUBTEXT,
                 anchor=tk.W, padx=18, pady=4,
                 font=("Segoe UI", 9)).pack(fill=tk.X, side=tk.BOTTOM)

    # ── Logging helpers ───────────────────────────────────────────────────────

    def _log_msg(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.configure(state=tk.NORMAL)
        self._log.insert(tk.END, f"[{ts}] {msg}\n")
        self._log.see(tk.END)
        self._log.configure(state=tk.DISABLED)

    def _set_status(self, msg: str) -> None:
        self._status_var.set(msg)

    def _set_buttons(self, active: bool) -> None:
        state = tk.NORMAL if active else tk.DISABLED
        for btn in (self._scan_btn, self._enable_btn, self._disable_btn):
            btn.configure(state=state)

    # ── Row update ────────────────────────────────────────────────────────────

    def _update_row(self, setting: dict, status: str, tag: str) -> None:
        self._tree.item(
            setting["name"],
            values=(setting["name"], setting["category"], status, setting["desc"]),
            tags=(tag,),
        )

    def _refresh_counts(self) -> None:
        enabled = disabled = unknown = 0
        for s in SETTINGS:
            vals = self._tree.item(s["name"], "values")
            if vals:
                st = vals[2]
                if st == "ENABLED":
                    enabled += 1
                elif st == "DISABLED":
                    disabled += 1
                else:
                    unknown += 1
        self._enabled_var.set(f"Enabled: {enabled}")
        self._disabled_var.set(f"Disabled: {disabled}")
        self._total_var.set(f"Total: {len(SETTINGS)}  (Unknown: {unknown})")

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_ctx_menu(self, event: tk.Event) -> None:
        row = self._tree.identify_row(event.y)
        if row:
            self._tree.selection_set(row)
            self._ctx_menu.post(event.x_root, event.y_root)

    def _toggle_selected(self, enable: bool) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        name = sel[0]
        setting = next((s for s in SETTINGS if s["name"] == name), None)
        if setting:
            threading.Thread(
                target=self._apply_one, args=(setting, enable), daemon=True
            ).start()

    # ── Scan ─────────────────────────────────────────────────────────────────

    def _scan_threaded(self) -> None:
        self._set_buttons(False)
        threading.Thread(target=self._scan, daemon=True).start()

    def _scan(self) -> None:
        self._set_status("Scanning…")
        self._log_msg("Starting scan…")
        enabled = disabled = errors = 0

        for s in SETTINGS:
            self._set_status(f"Checking: {s['name']}…")
            out, err, rc = run_ps(s["check_cmd"])
            if rc != 0 and not out:
                self._update_row(s, "Error", "unknown")
                self._log_msg(f"  ✗ {s['name']}: {err[:100]}")
                errors += 1
            elif check_is_enabled(s, out):
                self._update_row(s, "ENABLED", "enabled")
                enabled += 1
            else:
                self._update_row(s, "DISABLED", "disabled")
                disabled += 1

        self._refresh_counts()
        self._ts_lbl.config(text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
        summary = f"Scan complete — {enabled} enabled, {disabled} disabled, {errors} errors"
        self._log_msg(summary)
        self._set_status(summary)
        self._set_buttons(True)

    # ── Enable / Disable all ──────────────────────────────────────────────────

    def _confirm_enable_all(self) -> None:
        if messagebox.askyesno(
            "Enable All",
            "Enable ALL listed security settings?\n\nContinue?",
        ):
            self._set_buttons(False)
            threading.Thread(target=self._apply_all, args=(True,), daemon=True).start()

    def _confirm_disable_all(self) -> None:
        if messagebox.askyesno(
            "Disable All",
            "WARNING: This will DISABLE all listed security settings.\n\n"
            "Only do this in a controlled test / lab environment.\n\nContinue?",
            icon="warning",
        ):
            self._set_buttons(False)
            threading.Thread(target=self._apply_all, args=(False,), daemon=True).start()

    def _apply_all(self, enable: bool) -> None:
        verb = "Enabling" if enable else "Disabling"
        self._log_msg(f"{verb} all settings…")
        ok = fail = 0

        for s in SETTINGS:
            self._set_status(f"{verb}: {s['name']}…")
            cmd = s["enable_cmd"] if enable else s["disable_cmd"]
            _, err, rc = run_ps(cmd)
            if rc == 0:
                tag, status = ("enabled", "ENABLED") if enable else ("disabled", "DISABLED")
                self._update_row(s, status, tag)
                self._log_msg(f"  ✓ {s['name']}")
                ok += 1
            else:
                self._log_msg(f"  ✗ {s['name']}: {err[:100]}")
                fail += 1

        self._refresh_counts()
        summary = f"Done — {ok} succeeded, {fail} failed"
        self._log_msg(summary)
        self._set_status(summary)
        self._set_buttons(True)
        # Refresh actual state after applying
        threading.Thread(target=self._scan, daemon=True).start()

    # ── Single toggle ─────────────────────────────────────────────────────────

    def _apply_one(self, setting: dict, enable: bool) -> None:
        verb = "Enabling" if enable else "Disabling"
        self._set_status(f"{verb}: {setting['name']}…")
        cmd = setting["enable_cmd"] if enable else setting["disable_cmd"]
        _, err, rc = run_ps(cmd)
        if rc == 0:
            tag, status = ("enabled", "ENABLED") if enable else ("disabled", "DISABLED")
            self._update_row(setting, status, tag)
            self._log_msg(f"  ✓ {setting['name']} — {status}")
        else:
            self._log_msg(f"  ✗ {setting['name']}: {err[:100]}")
        self._refresh_counts()
        self._set_status("Ready")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    # Temporary root needed to show messagebox before main window opens
    if not is_admin():
        _tmp = tk.Tk()
        _tmp.withdraw()
        answer = messagebox.askyesno(
            "Administrator Privileges Required",
            "This tool needs Administrator privileges to read and modify security "
            "settings.\n\nRestart as Administrator now?",
        )
        _tmp.destroy()
        if answer:
            elevate()
        # Fall through: run in limited mode if user declines

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
