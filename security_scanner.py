#!/usr/bin/env python3
"""Windows 11 Security Settings Scanner — mirrors Windows Security app layout."""

import ctypes
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext

# ── Admin helpers ─────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def elevate() -> None:
    args = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1)
    sys.exit(0)

def run_ps(cmd: str) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "Timed out", -1
    except Exception as exc:
        return "", str(exc), -1

# ── Catalogue ─────────────────────────────────────────────────────────────────

CATEGORIES = [
    {"id": "virus",          "label": "Virus & threat\nprotection",    "icon": "🛡"},
    {"id": "firewall",       "label": "Firewall &\nnetwork protection", "icon": "🔥"},
    {"id": "appbrowser",     "label": "App & browser\ncontrol",        "icon": "🌐"},
    {"id": "devicesecurity", "label": "Device\nsecurity",              "icon": "💻"},
    {"id": "system",         "label": "System &\nremote access",       "icon": "⚙"},
]

SETTINGS: list[dict] = [
    # ── Virus & threat protection ─────────────────────────────────────────────
    {
        "id": "realtime", "category": "virus",
        "name": "Real-time protection",
        "desc": "Locates and stops malware from installing or running on your device.",
        "check_cmd": "(Get-MpPreference).DisableRealtimeMonitoring",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableRealtimeMonitoring $false",
        "disable_cmd": "Set-MpPreference -DisableRealtimeMonitoring $true",
    },
    {
        "id": "cloudprotection", "category": "virus",
        "name": "Cloud-delivered protection",
        "desc": "Provides increased and faster protection with access to the latest threat data in the cloud.",
        "check_cmd": "[int](Get-MpPreference).MAPSReporting",
        "enabled_check": "nonzero",
        "enable_cmd":  "Set-MpPreference -MAPSReporting Advanced",
        "disable_cmd": "Set-MpPreference -MAPSReporting Disabled",
    },
    {
        "id": "samplesubmission", "category": "virus",
        "name": "Automatic sample submission",
        "desc": "Sends sample files to Microsoft to help protect you and others from potential threats.",
        "check_cmd": "[int](Get-MpPreference).SubmitSamplesConsent",
        "enabled_check": "sampleconsent",
        "enable_cmd":  "Set-MpPreference -SubmitSamplesConsent SendSafeSamples",
        "disable_cmd": "Set-MpPreference -SubmitSamplesConsent NeverSend",
    },
    {
        "id": "tamper", "category": "virus",
        "name": "Tamper Protection",
        "desc": "Prevents others from tampering with important Windows Security settings. Must be changed via Windows Security app — cannot be modified programmatically.",
        "check_cmd": "(Get-MpComputerStatus).IsTamperProtected",
        "enabled_value": "True",
        "enable_cmd":  "Write-Host 'Tamper Protection must be changed in Windows Security app.'",
        "disable_cmd": "Write-Host 'Tamper Protection must be changed in Windows Security app.'",
        "readonly": True,
    },
    {
        "id": "controlledfolder", "category": "virus",
        "name": "Controlled folder access",
        "desc": "Protect files, folders and memory areas on your device from unauthorized changes by unfriendly applications.",
        "check_cmd": "[int](Get-MpPreference).EnableControlledFolderAccess",
        "enabled_check": "nonzero",
        "enable_cmd":  "Set-MpPreference -EnableControlledFolderAccess Enabled",
        "disable_cmd": "Set-MpPreference -EnableControlledFolderAccess Disabled",
    },
    {
        "id": "pua", "category": "virus",
        "name": "Reputation-based protection (PUA)",
        "desc": "Blocks potentially unwanted apps, malicious sites, downloads and web content.",
        "check_cmd": "[int](Get-MpPreference).PUAProtection",
        "enabled_check": "nonzero",
        "enable_cmd":  "Set-MpPreference -PUAProtection Enabled",
        "disable_cmd": "Set-MpPreference -PUAProtection Disabled",
    },
    {
        "id": "networkprotection", "category": "virus",
        "name": "Network protection",
        "desc": "Blocks connections to dangerous domains hosting phishing scams, exploits and malicious content.",
        "check_cmd": "[int](Get-MpPreference).EnableNetworkProtection",
        "enabled_check": "nonzero",
        "enable_cmd":  "Set-MpPreference -EnableNetworkProtection Enabled",
        "disable_cmd": "Set-MpPreference -EnableNetworkProtection Disabled",
    },
    {
        "id": "behaviormonitoring", "category": "virus",
        "name": "Behavior monitoring",
        "desc": "Applies a set of heuristics to detect malicious software based on its behavior on your device.",
        "check_cmd": "(Get-MpPreference).DisableBehaviorMonitoring",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableBehaviorMonitoring $false",
        "disable_cmd": "Set-MpPreference -DisableBehaviorMonitoring $true",
    },
    {
        "id": "scriptscanning", "category": "virus",
        "name": "Script scanning",
        "desc": "Provides additional analysis of scripts to help detect malicious behavior.",
        "check_cmd": "(Get-MpPreference).DisableScriptScanning",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableScriptScanning $false",
        "disable_cmd": "Set-MpPreference -DisableScriptScanning $true",
    },
    {
        "id": "ioav", "category": "virus",
        "name": "Downloaded files and attachments scanning",
        "desc": "Scans all downloaded files and email attachments for malicious content.",
        "check_cmd": "(Get-MpPreference).DisableIOAVProtection",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableIOAVProtection $false",
        "disable_cmd": "Set-MpPreference -DisableIOAVProtection $true",
    },
    {
        "id": "emailscanning", "category": "virus",
        "name": "Email scanning",
        "desc": "Scans email messages and attachments for viruses and other malware.",
        "check_cmd": "(Get-MpPreference).DisableEmailScanning",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableEmailScanning $false",
        "disable_cmd": "Set-MpPreference -DisableEmailScanning $true",
    },
    {
        "id": "removabledrive", "category": "virus",
        "name": "Removable drive scanning",
        "desc": "Scans USB drives and other removable media when they are inserted.",
        "check_cmd": "(Get-MpPreference).DisableRemovableDriveScanning",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableRemovableDriveScanning $false",
        "disable_cmd": "Set-MpPreference -DisableRemovableDriveScanning $true",
    },
    {
        "id": "archivescanning", "category": "virus",
        "name": "Archive scanning",
        "desc": "Scans compressed archives such as .zip and .cab files for malicious content.",
        "check_cmd": "(Get-MpPreference).DisableArchiveScanning",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableArchiveScanning $false",
        "disable_cmd": "Set-MpPreference -DisableArchiveScanning $true",
    },
    {
        "id": "intrusionprevention", "category": "virus",
        "name": "Intrusion prevention system",
        "desc": "Inspects network traffic to detect and block exploitation attempts.",
        "check_cmd": "(Get-MpPreference).DisableIntrusionPreventionSystem",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableIntrusionPreventionSystem $false",
        "disable_cmd": "Set-MpPreference -DisableIntrusionPreventionSystem $true",
    },
    {
        "id": "blockfirstseen", "category": "virus",
        "name": "Block at first sight",
        "desc": "Sends suspicious new files to Microsoft cloud for analysis before allowing them to run, providing near-instant threat detection.",
        "check_cmd": "(Get-MpPreference).DisableBlockAtFirstSeen",
        "enabled_value": "False",
        "enable_cmd":  "Set-MpPreference -DisableBlockAtFirstSeen $false",
        "disable_cmd": "Set-MpPreference -DisableBlockAtFirstSeen $true",
    },
    # ── Firewall & network protection ─────────────────────────────────────────
    {
        "id": "fw_domain", "category": "firewall",
        "name": "Domain network",
        "desc": "Networks at a workplace that are joined to a domain.",
        "check_cmd": "(Get-NetFirewallProfile -Profile Domain).Enabled",
        "enabled_value": "True",
        "enable_cmd":  "Set-NetFirewallProfile -Profile Domain -Enabled True",
        "disable_cmd": "Set-NetFirewallProfile -Profile Domain -Enabled False",
    },
    {
        "id": "fw_private", "category": "firewall",
        "name": "Private network",
        "desc": "Networks at home or work where you know and trust the people and devices on the network.",
        "check_cmd": "(Get-NetFirewallProfile -Profile Private).Enabled",
        "enabled_value": "True",
        "enable_cmd":  "Set-NetFirewallProfile -Profile Private -Enabled True",
        "disable_cmd": "Set-NetFirewallProfile -Profile Private -Enabled False",
    },
    {
        "id": "fw_public", "category": "firewall",
        "name": "Public network",
        "desc": "Networks in public places such as airports and coffee shops.",
        "check_cmd": "(Get-NetFirewallProfile -Profile Public).Enabled",
        "enabled_value": "True",
        "enable_cmd":  "Set-NetFirewallProfile -Profile Public -Enabled True",
        "disable_cmd": "Set-NetFirewallProfile -Profile Public -Enabled False",
    },
    # ── App & browser control ─────────────────────────────────────────────────
    {
        "id": "smartscreen_apps", "category": "appbrowser",
        "name": "Check apps and files",
        "desc": "Windows Defender SmartScreen helps protect your device by checking for unrecognized apps and files from the web.",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -ErrorAction SilentlyContinue).SmartScreenEnabled",
        "enabled_check": "notempty_nooff",
        "enable_cmd":  "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value On",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -Value Off",
    },
    {
        "id": "smartscreen_edge", "category": "appbrowser",
        "name": "SmartScreen for Microsoft Edge",
        "desc": "Microsoft Defender SmartScreen helps protect your device from malicious sites and downloads.",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -ErrorAction SilentlyContinue).SmartScreenEnabled",
        "enabled_check": "edge_smartscreen",
        "enable_cmd":  "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name SmartScreenEnabled -Value 1",
        "disable_cmd": "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge' -Name SmartScreenEnabled -Value 0",
    },
    {
        "id": "smartscreen_store", "category": "appbrowser",
        "name": "SmartScreen for Microsoft Store apps",
        "desc": "Checks web content used by Microsoft Store apps to help protect your device.",
        "check_cmd": "(Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost' -ErrorAction SilentlyContinue).EnableWebContentEvaluation",
        "enabled_value": "1",
        "enable_cmd":  "New-Item -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost' -Force | Out-Null; Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost' -Name EnableWebContentEvaluation -Value 1",
        "disable_cmd": "New-Item -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost' -Force | Out-Null; Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost' -Name EnableWebContentEvaluation -Value 0",
    },
    {
        "id": "phishing", "category": "appbrowser",
        "name": "Phishing protection",
        "desc": "Warns you when you type a password on malicious sites, reuse passwords, or store passwords unsafely. Windows 11 22H2+.",
        "check_cmd": "(Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\WTDS\\Components' -ErrorAction SilentlyContinue).ServiceEnabled",
        "enabled_value": "1",
        "enable_cmd":  "New-Item -Path 'HKCU:\\SOFTWARE\\Microsoft\\WTDS\\Components' -Force | Out-Null; Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\WTDS\\Components' -Name ServiceEnabled -Value 1",
        "disable_cmd": "Set-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\WTDS\\Components' -Name ServiceEnabled -Value 0 -ErrorAction SilentlyContinue",
    },
    {
        "id": "appguard", "category": "appbrowser",
        "name": "Microsoft Defender Application Guard",
        "desc": "Opens Microsoft Edge in an isolated container to protect against malicious websites. Requires Windows 10/11 Enterprise or Pro. A restart is required after changing.",
        "check_cmd": "if ((Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -ErrorAction SilentlyContinue).State -like 'Enabled*') { 'True' } else { 'False' }",
        "enabled_value": "True",
        "enable_cmd":  "Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart",
        "disable_cmd": "Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart",
    },
    {
        "id": "exploitprotection", "category": "appbrowser",
        "name": "Exploit protection — DEP",
        "desc": "Data Execution Prevention marks memory regions non-executable so code cannot run from data areas.",
        "check_cmd": "(Get-ProcessMitigation -System).DEP.Enable",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable DEP",
        "disable_cmd": "Set-ProcessMitigation -System -Disable DEP",
    },
    {
        "id": "cfg", "category": "appbrowser",
        "name": "Exploit protection — Control Flow Guard",
        "desc": "Restricts where code can jump during execution to prevent attackers from redirecting program flow to malicious code.",
        "check_cmd": "(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).CFG.Enable",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable CFG",
        "disable_cmd": "Set-ProcessMitigation -System -Disable CFG",
    },
    {
        "id": "aslr_force", "category": "appbrowser",
        "name": "Exploit protection — Force randomization for images",
        "desc": "Forcibly re-bases images not compiled with ASLR at startup, randomizing their memory location.",
        "check_cmd": "(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).ASLR.ForceRelocateImages",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable ForceRelocateImages",
        "disable_cmd": "Set-ProcessMitigation -System -Disable ForceRelocateImages",
    },
    {
        "id": "aslr_bottomup", "category": "appbrowser",
        "name": "Exploit protection — Randomize memory allocations",
        "desc": "Randomizes the location of virtual memory allocations (Bottom-up ASLR) for processes, heaps, stacks, and other OS structures.",
        "check_cmd": "(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).ASLR.EnableBottomUpASLR",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable BottomUp",
        "disable_cmd": "Set-ProcessMitigation -System -Disable BottomUp",
    },
    {
        "id": "aslr_highentropy", "category": "appbrowser",
        "name": "Exploit protection — High-entropy ASLR",
        "desc": "Uses a larger range for memory randomization, greatly increasing the number of possible memory locations and making ASLR bypass harder.",
        "check_cmd": "(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).ASLR.EnableHighEntropy",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable HighEntropy",
        "disable_cmd": "Set-ProcessMitigation -System -Disable HighEntropy",
    },
    {
        "id": "sehop", "category": "appbrowser",
        "name": "Exploit protection — Validate exception chains",
        "desc": "Structured Exception Handler Overwrite Protection (SEHOP) blocks exploits that hijack the exception handler chain.",
        "check_cmd": "(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).SEHOP.Enable",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable SEHOP",
        "disable_cmd": "Set-ProcessMitigation -System -Disable SEHOP",
    },
    {
        "id": "heapintegrity", "category": "appbrowser",
        "name": "Exploit protection — Validate heap integrity",
        "desc": "Terminates a process when heap corruption is detected, preventing attackers from exploiting heap vulnerabilities.",
        "check_cmd": "(Get-ProcessMitigation -System -ErrorAction SilentlyContinue).Heap.TerminateOnError",
        "enabled_value": "ON",
        "enable_cmd":  "Set-ProcessMitigation -System -Enable TerminateOnHeapError",
        "disable_cmd": "Set-ProcessMitigation -System -Disable TerminateOnHeapError",
    },
    # ── Device security ───────────────────────────────────────────────────────
    {
        "id": "hvci", "category": "devicesecurity",
        "name": "Memory integrity",
        "desc": "Prevents attacks from inserting malicious code into high-security processes. A restart is required after changing.",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue).Enabled",
        "enabled_value": "1",
        "enable_cmd":  "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 1",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name Enabled -Value 0 -ErrorAction SilentlyContinue",
    },
    {
        "id": "secureboot", "category": "devicesecurity",
        "name": "Secure Boot",
        "desc": "Prevents sophisticated low-level malware like rootkits from loading during startup. Managed by firmware — read only.",
        "check_cmd": "[bool](Confirm-SecureBootUEFI)",
        "enabled_value": "True",
        "enable_cmd":  "Write-Host 'Secure Boot is controlled by your device firmware (BIOS/UEFI).'",
        "disable_cmd": "Write-Host 'Secure Boot is controlled by your device firmware (BIOS/UEFI).'",
        "readonly": True,
    },
    {
        "id": "kernelshadowstacks", "category": "devicesecurity",
        "name": "Kernel-mode Hardware-enforced Stack Protection",
        "desc": "Prevents attacks that substitute return addresses in kernel-mode memory. Requires Memory integrity to be enabled first.",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks' -ErrorAction SilentlyContinue).Enabled",
        "enabled_value": "1",
        "enable_cmd":  "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks' -Name Enabled -Value 1",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelShadowStacks' -Name Enabled -Value 0 -ErrorAction SilentlyContinue",
    },
    {
        "id": "dmaprotection", "category": "devicesecurity",
        "name": "Memory access protection",
        "desc": "Protects your device's memory from attacks by malicious external devices (Kernel DMA Protection). Controlled by device firmware — read only.",
        "check_cmd": "(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue).DmaProtectionStatus",
        "enabled_check": "nonzero",
        "enable_cmd":  "Write-Host 'Memory access protection is controlled by your device firmware (UEFI/BIOS).'",
        "disable_cmd": "Write-Host 'Memory access protection is controlled by your device firmware (UEFI/BIOS).'",
        "readonly": True,
    },
    {
        "id": "driverblock", "category": "devicesecurity",
        "name": "Microsoft Vulnerable Driver Blocklist",
        "desc": "Blocks drivers with known security vulnerabilities from loading.",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable",
        "enabled_value": "1",
        "enable_cmd":  "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name VulnerableDriverBlocklistEnable -Value 1 -Force",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name VulnerableDriverBlocklistEnable -Value 0 -Force",
    },
    {
        "id": "lsa", "category": "devicesecurity",
        "name": "Local Security Authority protection",
        "desc": "Helps protect user credentials by preventing unsigned drivers and plugins from loading into the Local Security Authority.",
        "check_cmd": "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).RunAsPPL",
        "enabled_check": "nonzero",
        "enable_cmd":  "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 1",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RunAsPPL -Value 0",
    },
    {
        "id": "tpm", "category": "devicesecurity",
        "name": "Security processor (TPM)",
        "desc": "Trusted Platform Module provides hardware-based security functions including encryption key storage. Managed by firmware — read only.",
        "check_cmd": "try { $t = Get-Tpm -ErrorAction Stop; if ($t.TpmPresent -and $t.TpmEnabled) { 'True' } else { 'False' } } catch { 'False' }",
        "enabled_value": "True",
        "enable_cmd":  "Write-Host 'TPM is managed by your device firmware (BIOS/UEFI).'",
        "disable_cmd": "Write-Host 'TPM is managed by your device firmware (BIOS/UEFI).'",
        "readonly": True,
    },
    # ── System & remote access ────────────────────────────────────────────────
    {
        "id": "uac", "category": "system",
        "name": "User Account Control (UAC)",
        "desc": "Helps prevent unauthorized changes to your device by asking for permission or an administrator password.",
        "check_cmd": "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA",
        "enabled_value": "1",
        "enable_cmd":  "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 0",
    },
    {
        "id": "windowsupdate", "category": "system",
        "name": "Windows Update",
        "desc": "Keeps Windows up to date with the latest security patches and improvements.",
        "check_cmd": "(Get-Service wuauserv).StartType",
        "enabled_check": "not_disabled",
        "enable_cmd":  "Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv -ErrorAction SilentlyContinue",
        "disable_cmd": "Stop-Service wuauserv -Force -ErrorAction SilentlyContinue; Set-Service wuauserv -StartupType Disabled",
    },
    {
        "id": "defenderservice", "category": "system",
        "name": "Windows Defender Antivirus Service",
        "desc": "Provides real-time protection against viruses, malware and other security threats.",
        "check_cmd": "(Get-Service WinDefend).Status",
        "enabled_check": "running",
        "enable_cmd":  "Set-Service WinDefend -StartupType Automatic; Start-Service WinDefend -ErrorAction SilentlyContinue",
        "disable_cmd": "Stop-Service WinDefend -Force -ErrorAction SilentlyContinue; Set-Service WinDefend -StartupType Disabled",
    },
    {
        "id": "rdp", "category": "system",
        "name": "Remote Desktop",
        "desc": "Allow your PC to be controlled from another device over a network connection.",
        "check_cmd": "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections",
        "enabled_value": "0",
        "enable_cmd":  "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0",
        "disable_cmd": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
    },
    {
        "id": "remoteregistry", "category": "system",
        "name": "Remote Registry",
        "desc": "Allows remote users to modify registry settings on this computer.",
        "check_cmd": "(Get-Service RemoteRegistry).Status",
        "enabled_check": "running",
        "enable_cmd":  "Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry -ErrorAction SilentlyContinue",
        "disable_cmd": "Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue; Set-Service RemoteRegistry -StartupType Disabled",
    },
]


def is_setting_enabled(setting: dict, raw: str) -> bool | None:
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
    elif mode == "sampleconsent":
        try:
            return int(out) != 2  # 2 = NeverSend (disabled)
        except ValueError:
            return None
    elif mode == "edge_smartscreen":
        if not out:
            return True  # not set → default on
        try:
            return int(out) == 1
        except ValueError:
            return None
    else:
        expected = str(setting.get("enabled_value", "True"))
        return out.lower() == expected.lower()


# ── Toggle widget ─────────────────────────────────────────────────────────────

class Toggle(tk.Canvas):
    W, H = 48, 26

    def __init__(self, parent, command=None, readonly=False, **kw):
        bg = kw.pop("bg", C.CARD)
        super().__init__(parent, width=self.W, height=self.H,
                         highlightthickness=0, bg=bg, **kw)
        self._state: bool | None = None
        self._command = command
        self._readonly = readonly
        if not readonly:
            self.bind("<Button-1>", self._click)
            self.configure(cursor="hand2")
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h, r = self.W, self.H, self.H // 2
        if self._state is True:
            color, knob_x = C.ACCENT, w - h + 3
        elif self._state is False:
            color, knob_x = "#ababab", 3
        else:
            color, knob_x = "#d0d0d0", r - 8  # unknown / loading
        # pill track
        self.create_arc(0, 0, h, h, start=90, extent=180,
                        fill=color, outline=color, style=tk.CHORD)
        self.create_arc(w - h, 0, w, h, start=270, extent=180,
                        fill=color, outline=color, style=tk.CHORD)
        self.create_rectangle(r, 0, w - r, h, fill=color, outline=color)
        # knob
        pad = 4
        self.create_oval(knob_x, pad, knob_x + h - 2 * pad, h - pad,
                         fill="white", outline="white")

    def _click(self, _=None):
        self.set(not bool(self._state))
        if self._command:
            self._command(self._state)

    def set(self, value: bool | None):
        self._state = value
        self._draw()

    def get(self) -> bool | None:
        return self._state


# ── Colour palette (Windows 11 light) ────────────────────────────────────────

class C:
    BG      = "#f3f3f3"
    SIDEBAR = "#eeeeee"
    CARD    = "#ffffff"
    ACCENT  = "#0078d4"
    TEXT    = "#1a1a1a"
    SUBTEXT = "#616161"
    DIVIDER = "#e0e0e0"
    SEL_BG  = "#e5f1fb"
    SEL_BAR = "#0078d4"
    HOVER   = "#e8e8e8"
    GREEN   = "#107c10"
    RED     = "#c42b1c"
    AMBER   = "#9d5d00"


# ── Main application ──────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Windows Security")
        self.geometry("1000x680")
        self.minsize(760, 520)
        self.configure(bg=C.BG)

        self._active_cat: str = CATEGORIES[0]["id"]
        self._toggles:    dict[str, Toggle]   = {}
        self._status_labels: dict[str, tk.Label] = {}
        self._results:    dict[str, bool | None] = {}  # survives category switches

        self._build_ui()
        self._select_category(CATEGORIES[0]["id"])

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Title bar ────────────────────────────────────────────────────────
        title_bar = tk.Frame(self, bg=C.BG)
        title_bar.pack(fill=tk.X, padx=20, pady=(16, 0))

        tk.Label(title_bar, text="🛡  Windows Security",
                 font=("Segoe UI", 18, "bold"), bg=C.BG, fg=C.TEXT).pack(side=tk.LEFT)

        admin_text = "✓ Administrator" if is_admin() else "⚠  Not Administrator — changes may fail"
        admin_color = C.GREEN if is_admin() else C.RED
        tk.Label(title_bar, text=admin_text, font=("Segoe UI", 9),
                 bg=C.BG, fg=admin_color).pack(side=tk.RIGHT, padx=4)

        # ── Toolbar ──────────────────────────────────────────────────────────
        toolbar = tk.Frame(self, bg=C.BG)
        toolbar.pack(fill=tk.X, padx=20, pady=(10, 12))

        for label, cmd, fg, hov in (
            ("  Scan All",      self._scan_all,     C.ACCENT,  "#005a9e"),
            ("  Enable All",  self._confirm_enable, C.GREEN,   "#0b5e0b"),
            ("  Disable All", self._confirm_disable, C.RED,    "#9a1f1a"),
        ):
            btn = tk.Button(toolbar, text=label, font=("Segoe UI", 10, "bold"),
                            bg=C.CARD, fg=fg, activebackground=hov,
                            activeforeground="white", relief=tk.FLAT,
                            bd=0, padx=16, pady=7, cursor="hand2",
                            highlightthickness=1, highlightbackground=C.DIVIDER,
                            command=cmd)
            btn.pack(side=tk.LEFT, padx=(0, 8))

        self._ts_lbl = tk.Label(toolbar, text="", font=("Segoe UI", 9),
                                bg=C.BG, fg=C.SUBTEXT)
        self._ts_lbl.pack(side=tk.RIGHT)

        # ── Divider ──────────────────────────────────────────────────────────
        tk.Frame(self, bg=C.DIVIDER, height=1).pack(fill=tk.X)

        # ── Body (sidebar + content) ──────────────────────────────────────────
        body = tk.Frame(self, bg=C.BG)
        body.pack(fill=tk.BOTH, expand=True)

        self._sidebar = tk.Frame(body, bg=C.SIDEBAR, width=210)
        self._sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self._sidebar.pack_propagate(False)

        tk.Frame(body, bg=C.DIVIDER, width=1).pack(side=tk.LEFT, fill=tk.Y)

        # scrollable content panel
        content_outer = tk.Frame(body, bg=C.BG)
        content_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(content_outer, bg=C.BG,
                                 highlightthickness=0, bd=0)
        vsb = tk.Scrollbar(content_outer, orient=tk.VERTICAL,
                           command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._content = tk.Frame(self._canvas, bg=C.BG)
        self._cwin = self._canvas.create_window(
            (0, 0), window=self._content, anchor="nw")

        self._content.bind("<Configure>", self._on_content_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._canvas.bind("<MouseWheel>",
                          lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        # ── Sidebar categories ────────────────────────────────────────────────
        self._cat_frames: dict[str, tk.Frame] = {}
        for cat in CATEGORIES:
            frm = tk.Frame(self._sidebar, bg=C.SIDEBAR, cursor="hand2")
            frm.pack(fill=tk.X)

            bar = tk.Frame(frm, bg=C.SIDEBAR, width=4)
            bar.pack(side=tk.LEFT, fill=tk.Y)

            inner = tk.Frame(frm, bg=C.SIDEBAR, pady=10, padx=12)
            inner.pack(side=tk.LEFT, fill=tk.X, expand=True)

            tk.Label(inner, text=cat["icon"], font=("Segoe UI Emoji", 20),
                     bg=C.SIDEBAR, fg=C.TEXT).pack(side=tk.LEFT, padx=(0, 10))
            tk.Label(inner, text=cat["label"], font=("Segoe UI", 10),
                     bg=C.SIDEBAR, fg=C.TEXT, justify=tk.LEFT,
                     anchor="w").pack(side=tk.LEFT, fill=tk.X)

            self._cat_frames[cat["id"]] = (frm, bar, inner)

            for widget in (frm, bar, inner) + tuple(inner.winfo_children()):
                widget.bind("<Button-1>",
                            lambda _, cid=cat["id"]: self._select_category(cid))
                widget.bind("<Enter>",
                            lambda _, f=frm, b=bar, i=inner: self._hover(f, b, i, True))
                widget.bind("<Leave>",
                            lambda _, f=frm, b=bar, i=inner: self._hover(f, b, i, False))

        # ── Log area ──────────────────────────────────────────────────────────
        tk.Frame(self, bg=C.DIVIDER, height=1).pack(fill=tk.X)
        log_frame = tk.Frame(self, bg=C.CARD)
        log_frame.pack(fill=tk.X, side=tk.BOTTOM)

        tk.Label(log_frame, text="Activity log", font=("Segoe UI", 9, "bold"),
                 bg=C.CARD, fg=C.SUBTEXT, padx=14, pady=4).pack(anchor=tk.W)

        self._log = scrolledtext.ScrolledText(
            log_frame, height=5, bg=C.CARD, fg=C.TEXT,
            font=("Consolas", 9), relief=tk.FLAT, state=tk.DISABLED,
            insertbackground=C.TEXT, padx=14,
        )
        self._log.pack(fill=tk.X)

        # status bar
        self._status_var = tk.StringVar(value="Ready")
        tk.Label(self, textvariable=self._status_var, bg=C.DIVIDER, fg=C.SUBTEXT,
                 anchor=tk.W, padx=14, pady=3, font=("Segoe UI", 9)
                 ).pack(fill=tk.X, side=tk.BOTTOM)

    # ── Canvas resize helpers ─────────────────────────────────────────────────

    def _on_content_configure(self, _=None):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig(self._cwin, width=event.width)

    # ── Sidebar interaction ───────────────────────────────────────────────────

    def _hover(self, frm, bar, inner, entering: bool):
        if self._active_cat == self._cat_id_for(frm):
            return
        bg = C.HOVER if entering else C.SIDEBAR
        for w in (frm, bar, inner):
            w.configure(bg=bg)
        for w in inner.winfo_children():
            w.configure(bg=bg)

    def _cat_id_for(self, frm) -> str:
        for cid, (f, *_) in self._cat_frames.items():
            if f is frm:
                return cid
        return ""

    def _select_category(self, cat_id: str) -> None:
        # Deselect old
        if self._active_cat in self._cat_frames:
            frm, bar, inner = self._cat_frames[self._active_cat]
            for w in (frm, bar, inner):
                w.configure(bg=C.SIDEBAR)
            for w in inner.winfo_children():
                w.configure(bg=C.SIDEBAR)

        self._active_cat = cat_id
        frm, bar, inner = self._cat_frames[cat_id]
        for w in (frm, inner):
            w.configure(bg=C.SEL_BG)
        bar.configure(bg=C.SEL_BAR)
        for w in inner.winfo_children():
            w.configure(bg=C.SEL_BG)

        self._build_content(cat_id)
        self._canvas.yview_moveto(0)

    # ── Content panel ─────────────────────────────────────────────────────────

    def _build_content(self, cat_id: str) -> None:
        for w in self._content.winfo_children():
            w.destroy()

        cat = next(c for c in CATEGORIES if c["id"] == cat_id)
        settings = [s for s in SETTINGS if s["category"] == cat_id]

        # Section header
        hdr = tk.Frame(self._content, bg=C.BG)
        hdr.pack(fill=tk.X, padx=24, pady=(20, 6))
        tk.Label(hdr, text=f"{cat['icon']}  {cat['label'].replace(chr(10), ' ')}",
                 font=("Segoe UI", 16, "bold"), bg=C.BG, fg=C.TEXT).pack(side=tk.LEFT)

        for i, s in enumerate(settings):
            self._setting_row(self._content, s, i < len(settings) - 1)

        # Restore any results we already have so switching category never wipes state
        for s in settings:
            if s["id"] in self._results:
                self._apply_result(s, self._results[s["id"]])

        # padding at bottom
        tk.Frame(self._content, bg=C.BG, height=20).pack()

    def _setting_row(self, parent, s: dict, divider: bool) -> None:
        card = tk.Frame(parent, bg=C.CARD,
                        highlightthickness=1, highlightbackground=C.DIVIDER)
        card.pack(fill=tk.X, padx=24, pady=(0, 8))

        inner = tk.Frame(card, bg=C.CARD, padx=16, pady=14)
        inner.pack(fill=tk.X)

        # Left: text
        text_col = tk.Frame(inner, bg=C.CARD)
        text_col.pack(side=tk.LEFT, fill=tk.X, expand=True)

        name_row = tk.Frame(text_col, bg=C.CARD)
        name_row.pack(fill=tk.X)

        tk.Label(name_row, text=s["name"], font=("Segoe UI", 11, "bold"),
                 bg=C.CARD, fg=C.TEXT, anchor="w").pack(side=tk.LEFT)

        if s.get("readonly"):
            tk.Label(name_row, text="  read only", font=("Segoe UI", 9),
                     bg=C.CARD, fg=C.SUBTEXT).pack(side=tk.LEFT)

        lbl = tk.Label(text_col, text="Checking…", font=("Segoe UI", 9),
                       bg=C.CARD, fg=C.SUBTEXT, anchor="w")
        lbl.pack(fill=tk.X)
        self._status_labels[s["id"]] = lbl

        tk.Label(text_col, text=s["desc"], font=("Segoe UI", 9),
                 bg=C.CARD, fg=C.SUBTEXT, anchor="w",
                 wraplength=580, justify=tk.LEFT).pack(fill=tk.X, pady=(4, 0))

        # Right: toggle
        toggle = Toggle(inner, readonly=s.get("readonly", False), bg=C.CARD,
                        command=lambda v, setting=s: self._on_toggle(setting, v))
        toggle.pack(side=tk.RIGHT, padx=(16, 0))
        self._toggles[s["id"]] = toggle

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_msg(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.configure(state=tk.NORMAL)
        self._log.insert(tk.END, f"[{ts}] {msg}\n")
        self._log.see(tk.END)
        self._log.configure(state=tk.DISABLED)

    def _set_status(self, msg: str) -> None:
        self._status_var.set(msg)

    # ── Per-setting update ────────────────────────────────────────────────────

    def _apply_result(self, s: dict, enabled: bool | None) -> None:
        self._results[s["id"]] = enabled          # persist across category switches
        toggle = self._toggles.get(s["id"])
        label  = self._status_labels.get(s["id"])
        if toggle:
            toggle.set(enabled)
        if label:
            if enabled is True:
                label.configure(text="On", fg=C.GREEN)
            elif enabled is False:
                label.configure(text="Off", fg=C.RED)
            else:
                label.configure(text="Unknown / error", fg=C.AMBER)

    # ── Toggle callback ───────────────────────────────────────────────────────

    def _on_toggle(self, s: dict, new_state: bool) -> None:
        def _apply():
            cmd = s["enable_cmd"] if new_state else s["disable_cmd"]
            self.after(0, self._set_status,
                       f"{'Enabling' if new_state else 'Disabling'}: {s['name']}…")
            _, err, rc = run_ps(cmd)
            if rc == 0:
                self.after(0, self._apply_result, s, new_state)
                self.after(0, self._log_msg,
                           f"{'✓ Enabled' if new_state else '✓ Disabled'}: {s['name']}")
            else:
                # revert toggle on failure
                self.after(0, self._apply_result, s, not new_state)
                self.after(0, self._log_msg, f"Skipped {s['name']}: {err[:120]}")
            self.after(0, self._set_status, "Ready")
        threading.Thread(target=_apply, daemon=True).start()

    # ── Scan all ──────────────────────────────────────────────────────────────

    def _scan_all(self) -> None:
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self) -> None:
        import json as _json

        self._set_status("Scanning…")
        self._log_msg("Starting scan…")

        # Build ONE PowerShell script that checks every setting and emits JSON.
        # This replaces 27 separate process launches with a single call.
        lines = [
            "$ErrorActionPreference = 'SilentlyContinue'",
            "$r = [ordered]@{}",
        ]
        for s in SETTINGS:
            lines.append(f"$r['{s['id']}'] = try {{ {s['check_cmd']} }} catch {{ $null }}")
        lines.append("$r | ConvertTo-Json -Compress -Depth 2")

        out, err, rc = run_ps("\n".join(lines))

        if not out:
            self._log_msg(f"Scan error: {err[:200]}")
            self._set_status("Scan failed — see log")
            return

        try:
            data = _json.loads(out)
        except _json.JSONDecodeError:
            self._log_msg(f"Parse error: {out[:200]}")
            self._set_status("Scan failed — see log")
            return

        ok = errors = 0
        for s in SETTINGS:
            if s["id"] not in data:
                # Key missing entirely — JSON truncation or script error
                enabled: bool | None = None
                errors += 1
            elif data[s["id"]] is None:
                # PowerShell returned $null — setting not configured; treat as unknown
                enabled = None
            else:
                # PowerShell booleans arrive as Python bool; cast to str for checker
                enabled = is_setting_enabled(s, str(data[s["id"]]))
                ok += 1
            # schedule UI update on main thread (safe from background thread)
            self.after(0, self._apply_result, s, enabled)

        self.after(0, self._ts_lbl.configure,
                   {"text": f"Last scan: {datetime.now().strftime('%H:%M:%S')}"})
        summary = f"Scan complete — {ok} read" + (f", {errors} errors" if errors else "")
        self.after(0, self._log_msg, summary)
        self.after(0, self._set_status, summary)

    # ── Enable / Disable all ──────────────────────────────────────────────────

    def _confirm_enable(self) -> None:
        if messagebox.askyesno("Enable All",
                               "Enable ALL security settings?\n\nContinue?"):
            threading.Thread(target=self._apply_all, args=(True,), daemon=True).start()

    def _confirm_disable(self) -> None:
        if messagebox.askyesno("Disable All",
                               "WARNING: This will DISABLE all security settings.\n\n"
                               "Only use this in a controlled test environment.\n\nContinue?",
                               icon="warning"):
            threading.Thread(target=self._apply_all, args=(False,), daemon=True).start()

    def _apply_all(self, enable: bool) -> None:
        import json as _json
        verb = "Enabling" if enable else "Disabling"
        self.after(0, self._log_msg, f"{verb} all settings…")
        ok = 0
        skipped: list[str] = []

        # Batch all Set-MpPreference calls into one PowerShell process to avoid
        # Defender WMI provider hang when invoked in rapid succession.
        # Each command gets its own try/catch so one failure doesn't kill the rest.
        mp_settings = [
            s for s in SETTINGS
            if not s.get("readonly")
            and "MpPreference" in (s["enable_cmd"] if enable else s["disable_cmd"])
        ]
        other_settings = [
            s for s in SETTINGS
            if not s.get("readonly")
            and "MpPreference" not in (s["enable_cmd"] if enable else s["disable_cmd"])
        ]

        if mp_settings:
            self.after(0, self._set_status, f"{verb}: Defender scan settings…")
            lines = ["$r = [ordered]@{}"]
            for s in mp_settings:
                cmd = s["enable_cmd"] if enable else s["disable_cmd"]
                lines.append(
                    f"$r['{s['id']}'] = try {{ {cmd}; 'ok' }}"
                    f" catch {{ $_.Exception.Message }}"
                )
            lines.append("$r | ConvertTo-Json -Compress")
            out, _, _ = run_ps("\n".join(lines))
            try:
                results = _json.loads(out) if out else {}
            except _json.JSONDecodeError:
                results = {}
            for s in mp_settings:
                result = results.get(s["id"])
                if result == "ok":
                    self.after(0, self._apply_result, s, enable)
                    self.after(0, self._log_msg, f"  ✓ {s['name']}")
                    ok += 1
                else:
                    reason = str(result)[:80] if result else "no response"
                    self.after(0, self._log_msg, f"  Skipped {s['name']}: {reason}")
                    skipped.append(s["name"])

        for s in other_settings:
            cmd = s["enable_cmd"] if enable else s["disable_cmd"]
            self.after(0, self._set_status, f"{verb}: {s['name']}…")
            _, err2, rc2 = run_ps(cmd)
            if rc2 == 0:
                self.after(0, self._apply_result, s, enable)
                self.after(0, self._log_msg, f"  ✓ {s['name']}")
                ok += 1
            else:
                self.after(0, self._log_msg, f"  Skipped {s['name']}: {err2[:80]}")
                skipped.append(s["name"])

        if skipped:
            self.after(0, self._log_msg,
                       f"Skipped ({len(skipped)}): {', '.join(skipped)}")
            if not enable:
                self.after(0, self._log_msg,
                           "Tip: Turn off Tamper Protection in Windows Security first"
                           " to allow disabling Defender settings.")
        summary = f"Done — {ok} succeeded, {len(skipped)} skipped"
        self.after(0, self._log_msg, summary)
        self.after(0, self._set_status, summary)
        threading.Thread(target=self._do_scan, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if not is_admin():
        _tmp = tk.Tk()
        _tmp.withdraw()
        if messagebox.askyesno(
            "Administrator Required",
            "This tool needs Administrator privileges to read and modify "
            "security settings.\n\nRestart as Administrator now?",
        ):
            _tmp.destroy()
            elevate()
        _tmp.destroy()

    app = App()
    # Auto-scan on launch
    app.after(300, app._scan_all)
    app.mainloop()


if __name__ == "__main__":
    main()
