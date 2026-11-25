"""Storage Cleaner - see what fills your drives, which apps hoard cache, what is installed,
what uninstalled apps left behind, and what is safe to delete.

Run:  python cleaner.py                 (GUI)
      python cleaner.py --scan          (list junk in the terminal; --clean-safe deletes the Safe part)
      python cleaner.py --duplicates    (identical files in your user folder)
      python cleaner.py --schedule weekly   (automatic Safe cleanup via Task Scheduler)
      python cleaner.py --test          (self-check)   ... see --help for the rest

Every item gets a safety level:
  SAFE       rebuildable data (temp, caches, logs, dumps); apps recreate it.
  CAUTION    deletable, but you lose something (Recycle Bin, Downloads, package caches, leftovers).
  PROTECTED  system / personal data; shown so you know what it is, never deleted.

Rules come from Windows' own Disk Cleanup handlers (registry VolumeCaches: folder, file
pattern, minimum age), BleachBit/Winapp2-style app cache detection, and the registry
Uninstall keys (installed apps, broken entries, leftover folders).
Double-click any row to open that exact file/folder in Explorer.
"""
import argparse, ctypes, fnmatch, hashlib, json, multiprocessing, os, queue, re, shutil, subprocess, sys, tempfile, threading, time
import tkinter as tk
from collections import namedtuple
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from ctypes import wintypes
from tkinter import messagebox, ttk

HOME = os.path.expanduser("~")
LOCAL = os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local"))
ROAMING = os.environ.get("APPDATA", os.path.join(HOME, "AppData", "Roaming"))
WINDIR = os.environ.get("WINDIR", r"C:\Windows")
SYSDRIVE = os.path.splitdrive(WINDIR)[0] or "C:"
PROGDATA = os.environ.get("PROGRAMDATA", SYSDRIVE + r"\ProgramData")
PROGFILES = os.environ.get("ProgramFiles", SYSDRIVE + r"\Program Files")
PROGFILES86 = os.environ.get("ProgramFiles(x86)", SYSDRIVE + r"\Program Files (x86)")
SAFE, CAUTION, PROTECTED = "Safe", "Caution", "Protected"
DAY = 86400
MB = 1024 * 1024
HISTORY = os.path.join(LOCAL, "StorageCleaner", "history.jsonl")
TASK = "StorageCleaner Safe cleanup"
NO_WINDOW = 0x08000000
DIRECTORY = 0x10  # FILE_ATTRIBUTE_* bits from the directory listing
CLOUD_ONLY = 0x400000 | 0x40000 | 0x1000  # recall on data access / on open, offline: not on this disk
CHUNK = 64 * 1024

Rule = namedtuple("Rule", "level category label folder patterns days note")
ALL = ("*",)

# Folder names that only hold rebuildable cache (Chromium/Electron apps, browsers, Store apps).
CACHE_NAMES = {"cache", "cache2", "code cache", "gpucache", "dawncache", "grshadercache",
               "shadercache", "cacheddata", "cachedextensionvsixs", "inetcache",
               "cachestorage", "crashpad", "crashdumps", "logs", "temp", "tmp"}
# Not "LocalCache": Store apps (e.g. Microsoft Store Python) keep real installed data there.
GROUPERS = {"microsoft", "google", "packages", "programs", "mozilla", "jetbrains"}

# Extra rules Windows' Disk Cleanup does not cover.
EXTRA = [
    Rule(SAFE, "System", "Crash dumps", os.path.join(LOCAL, "CrashDumps"), ALL, 0, "App crash reports"),
    Rule(SAFE, "System", "Thumbnail & icon cache", os.path.join(LOCAL, r"Microsoft\Windows\Explorer"),
         ("thumbcache*.db", "iconcache*.db"), 0, "Rebuilt automatically; in-use files skipped"),
    Rule(SAFE, "System", "User error reports", os.path.join(LOCAL, r"Microsoft\Windows\WER"), ALL, 0, "Crash report copies"),
    Rule(CAUTION, "System", "Windows Update downloads (admin)", os.path.join(WINDIR, r"SoftwareDistribution\Download"),
         ALL, 0, "Already-installed updates; pending ones re-download"),
    Rule(CAUTION, "Developer", "npm cache", os.path.join(LOCAL, "npm-cache"), ALL, 0, "Packages re-download on next install"),
    Rule(CAUTION, "Developer", "pip cache", os.path.join(LOCAL, r"pip\cache"), ALL, 0, "Packages re-download on next install"),
    Rule(CAUTION, "Developer", "uv cache", os.path.join(LOCAL, r"uv\cache"), ALL, 0, "Packages re-download on next install"),
    Rule(CAUTION, "Developer", "yarn cache", os.path.join(LOCAL, r"Yarn\Cache"), ALL, 0, "Packages re-download on next install"),
    Rule(CAUTION, "Developer", "pnpm store", os.path.join(LOCAL, r"pnpm\store"), ALL, 0, "Linked projects need reinstall"),
    Rule(CAUTION, "Developer", "NuGet http cache", os.path.join(LOCAL, r"NuGet\v3-cache"), ALL, 0, "Packages re-download"),
    Rule(CAUTION, "Developer", "Gradle caches", os.path.join(HOME, r".gradle\caches"), ALL, 0, "Next build is slow"),
    Rule(CAUTION, "Developer", "Go build cache", os.path.join(LOCAL, "go-build"), ALL, 0, "Next build is slow"),
]

norm = lambda p: os.path.normcase(os.path.normpath(p))

# Never deleted as a whole, whatever a rule says.
PROTECTED_DIRS = {norm(p) for p in (
    SYSDRIVE + "\\", WINDIR, os.path.join(WINDIR, "System32"), os.path.join(WINDIR, "SysWOW64"),
    os.path.join(WINDIR, "WinSxS"), PROGDATA, SYSDRIVE + r"\Users", HOME, LOCAL, ROAMING, PROGFILES, PROGFILES86,
    *(os.path.join(HOME, d) for d in ("Documents", "Desktop", "Pictures", "Videos", "Music", "OneDrive")))}
# Inside Windows, only these folder names may be wiped completely.
WIN_WIPE_OK = {"temp", "systemtemp", "logs", "logfiles", "minidump", "download", "msdownld.tmp"}

# Drive map meanings: name -> (level, explanation)
ROOT_INFO = {
    "windows": (PROTECTED, "Windows itself. Use 'Windows Disk Cleanup' for update leftovers"),
    "program files": (PROTECTED, "Installed apps. Uninstall from Settings > Apps"),
    "program files (x86)": (PROTECTED, "Installed 32-bit apps. Uninstall from Settings > Apps"),
    "programdata": (PROTECTED, "Shared app data and settings"),
    "users": (PROTECTED, "User profiles - see your folder breakdown"),
    "pagefile.sys": (PROTECTED, "Virtual memory. Managed by Windows"),
    "swapfile.sys": (PROTECTED, "Store-app memory swap. Managed by Windows"),
    "hiberfil.sys": (PROTECTED, "Hibernation file. Admin 'powercfg /h off' removes it (disables hibernate & fast startup)"),
    "system volume information": (PROTECTED, "Restore points. Manage in System Protection"),
    "recovery": (PROTECTED, "Windows recovery tools"),
    "$recycle.bin": (CAUTION, "Recycle Bin - empty it from the Junk tab"),
    "windows.old": (CAUTION, "Previous Windows install. Remove via Disk Cleanup > Previous installations"),
    "$winreagent": (PROTECTED, "Windows update recovery agent. Windows removes it itself"),
    "$windows.~bt": (CAUTION, "Windows upgrade leftovers. Remove via Disk Cleanup"),
    "$windows.~ws": (CAUTION, "Windows upgrade leftovers. Remove via Disk Cleanup"),
    "swsetup": (CAUTION, "Laptop maker's (HP) driver installers. Deletable, but needed to reinstall drivers"),
    "drivers": (CAUTION, "Driver installers from the laptop maker. Keep if you may reinstall drivers"),
    "perflogs": (SAFE, "Performance logs. Usually empty"),
    "boot": (PROTECTED, "Boot files"), "efi": (PROTECTED, "Boot files"),
    "tmp": (CAUTION, "Temporary folder - check contents"), "temp": (CAUTION, "Temporary folder - check contents"),
}
HOME_INFO = {
    "appdata": (PROTECTED, "App settings + caches. Caches are listed in the Junk tab"),
    "downloads": (CAUTION, "Your downloads - review, delete what you don't need"),
    "documents": (PROTECTED, "Your personal files"), "desktop": (PROTECTED, "Your personal files"),
    "pictures": (PROTECTED, "Your personal files"), "videos": (PROTECTED, "Your personal files"),
    "music": (PROTECTED, "Your personal files"), "onedrive": (PROTECTED, "Synced cloud files"),
    ".cache": (CAUTION, "Tool caches (AI models, HuggingFace, uv...). Re-download can be large"),
    ".vscode": (CAUTION, "VS Code extensions. Deleting removes them"),
    ".m2": (CAUTION, "Maven package cache. Re-downloads on next build"),
    ".gradle": (CAUTION, "Gradle caches. Re-downloads on next build"),
    ".jdks": (CAUTION, "Java JDKs installed by IntelliJ. Projects using them break"),
}

# Folders under AppData / ProgramData / Program Files that belong to Windows, drivers or tools, not to apps.
LEFTOVER_IGNORE = {
    "microsoft", "windows", "packages", "temp", "tmp", "programs", "crashdumps", "d3dscache", "connecteddevicesplatform",
    "comms", "publishers", "virtualstore", "placeholdertilelogofolder", "package cache", "common files", "windowsapps",
    "modifiablewindowsapps", "windows nt", "windows defender", "windows defender advanced threat protection",
    "windows mail", "windows media player", "windows photo viewer", "windows portable devices", "windows security",
    "windows sidebar", "windowspowershell", "internet explorer", "reference assemblies", "msbuild", "dotnet",
    "uninstall information", "ssh", "usoshared", "usoprivate", "softwaredistribution", "history", "cache", "npm",
    "npm-cache", "pip", "uv", "pnpm", "yarn", "nuget", "go-build", "node-gyp", "pypa", "jedi", "python", "intel",
    "nvidia", "nvidia corporation", "amd", "realtek", "hp", "hp inc", "dell", "lenovo", "asus", "acer", "oem",
    "fontcache", "identities", "desktop.ini", "regid.1991-06.com.microsoft", "ms-playwright", "deviceSync".lower(),
    "peerdistrepub", "sun", "java", "mozilla", "google", "jetbrains", "github", "electron", "squirreltemp",
    "application data", "start menu", "templates", "sendto", "recent", "network", "printers", "libraries",
    "wsl", "winget", "chocolateyhttpcache",
}


def fmt(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def is_link(entry):
    try:
        return entry.is_symlink() or entry.is_junction()
    except OSError:
        return True


def dir_stats(path):
    """(total bytes, newest file mtime) under path; never follows symlinks or junctions."""
    total, newest, stack = 0, 0.0, [path]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if is_link(e):
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            st = e.stat(follow_symlinks=False)
                            total += st.st_size
                            newest = max(newest, st.st_mtime)
                    except OSError:
                        pass
        except OSError:
            pass
    return total, newest


def dir_size(path):
    return dir_stats(path)[0]


def safe_to_wipe(folder, patterns):
    """Refuse wiping system / personal roots completely. Specific patterns (e.g. *.dmp) are fine."""
    p = norm(folder)
    if tuple(patterns) != ALL:
        return not p.startswith((norm(PROGFILES), norm(PROGFILES86)))
    if p in PROTECTED_DIRS:
        return False
    return not p.startswith(norm(WINDIR) + os.sep) or os.path.basename(p) in WIN_WIPE_OK


def process(rule, delete=False):
    """Bytes matching rule (files older than rule.days). With delete=True, removes them.
    Recurses only for '*' rules; never follows links; files in use are skipped."""
    if not os.path.isdir(rule.folder) or (delete and not safe_to_wipe(rule.folder, rule.patterns)):
        return 0
    cutoff = time.time() - rule.days * DAY
    recursive = tuple(rule.patterns) == ALL
    total = 0

    def walk(d):
        nonlocal total
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        for e in entries:
            try:
                if is_link(e):
                    continue
                if e.is_dir(follow_symlinks=False):
                    if recursive:
                        walk(e.path)
                        if delete:
                            try:
                                os.rmdir(e.path)  # only succeeds if now empty
                            except OSError:
                                pass
                    continue
                if not any(fnmatch.fnmatch(e.name.lower(), p) for p in rule.patterns):
                    continue
                st = e.stat(follow_symlinks=False)
                if st.st_mtime > cutoff:
                    continue
                if delete:
                    os.remove(e.path)
                total += st.st_size
            except OSError:
                pass

    walk(rule.folder)
    return total


def load_string(s):
    """Resolve '@dll,-123' resource strings from the registry."""
    if not s or not s.startswith("@"):
        return s
    buf = ctypes.create_unicode_buffer(260)
    ok = ctypes.windll.shlwapi.SHLoadIndirectString(s, buf, 260, None) == 0
    return buf.value if ok else ""


def reg_values(key):
    import winreg
    vals = {}
    for j in range(winreg.QueryInfoKey(key)[1]):
        try:
            n, v, _ = winreg.EnumValue(key, j)
            vals[n.lower()] = v
        except OSError:
            pass
    return vals


def windows_cleanup_rules():
    """Read Windows' own Disk Cleanup handlers that name a folder + file pattern."""
    import winreg
    rules = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches")
    except OSError:
        return rules
    for i in range(winreg.QueryInfoKey(root)[0]):
        name = winreg.EnumKey(root, i)
        try:
            with winreg.OpenKey(root, name) as k:
                vals = reg_values(k)
        except OSError:
            continue
        folders, files = vals.get("folder"), vals.get("filelist")
        if not folders or not files:
            continue  # COM-only handler: run via Windows Disk Cleanup button
        days = vals.get("lastaccess", 0)
        days = int.from_bytes(days[:4], "little") if isinstance(days, bytes) else int(days or 0)
        patterns = tuple("*" if p in ("*.*", "*") else p.lower() for p in files.split("|"))
        label = load_string(vals.get("display", "")) or name
        downloads = name.lower() == "downloadsfolder"
        for f in folders.split("|"):
            f = os.path.expandvars(f.replace("?:", SYSDRIVE)).rstrip("\\")
            admin = norm(f).startswith((norm(WINDIR), norm(PROGDATA)))
            rules.append(Rule(
                CAUTION if downloads else SAFE, "Windows Disk Cleanup",
                f"{label}{' (admin)' if admin else ''}", f, ALL if downloads else patterns, days,
                "Your downloaded files - review first!" if downloads else
                f"Windows-approved{f', files older than {days} days' if days else ''}"))
    return rules


def find_app_caches(base, max_depth=5):
    """Yield (app_name, cache_path) for cache-named folders under base.
    Uses the directory listing's cached attributes: no extra system call per folder (5x faster than os.walk + islink)."""
    stack = [(os.path.normpath(base), ())]
    while stack:
        d, rel = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            try:
                if not e.stat(follow_symlinks=False).st_file_attributes & DIRECTORY or is_link(e):
                    continue
            except OSError:
                continue
            if rel and e.name.lower() in CACHE_NAMES:
                yield (os.path.join(*rel[:2]) if rel[0].lower() in GROUPERS and len(rel) > 1 else rel[0]), e.path
            elif len(rel) < max_depth:
                stack.append((e.path, rel + (e.name,)))


# ---------- installed apps & leftovers (registry Uninstall keys) ----------

App_ = namedtuple("App_", "name version publisher size location status uninstall")
key_of = lambda s: re.sub(r"[^a-z0-9]", "", (s or "").lower())


def exe_from_command(cmd):
    """Path of the executable in an uninstall command line, or None (msiexec / unparseable)."""
    cmd = os.path.expandvars((cmd or "").strip())
    if cmd.startswith('"'):
        exe = cmd[1:].split('"')[0]
    else:
        m = re.match(r"(.+?\.exe)\b", cmd, re.I)
        exe = m.group(1) if m else ""
    if not exe or "\\" not in exe or os.path.basename(exe).lower() in ("msiexec.exe", "rundll32.exe"):
        return None
    return exe


def installed_apps():
    """Apps from the registry Uninstall keys (64-bit, 32-bit, per-user), with health status."""
    import winreg
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    hives = [(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY), (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
             (winreg.HKEY_CURRENT_USER, 0)]
    apps, seen = [], set()
    for hive, flag in hives:
        try:
            root = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                with winreg.OpenKey(root, winreg.EnumKey(root, i)) as k:
                    v = reg_values(k)
            except OSError:
                continue
            name = v.get("displayname")
            if not name or v.get("systemcomponent") == 1 or v.get("parentkeyname") or (name, v.get("displayversion")) in seen:
                continue
            seen.add((name, v.get("displayversion")))
            loc = (v.get("installlocation") or "").strip().strip('"').rstrip("\\")
            if not loc:  # fall back to the folder of the app's icon
                icon = (v.get("displayicon") or "").split(",")[0].strip('"')
                if icon and "\\" in icon and not norm(icon).startswith(norm(WINDIR)):
                    loc = os.path.dirname(icon)
            exe = exe_from_command(v.get("uninstallstring"))
            if loc and not os.path.exists(loc):
                status = "Broken: install folder missing"
            elif exe and not os.path.exists(exe):
                status = "Broken: uninstaller missing"
            else:
                status = "Installed"
            size = int(v.get("estimatedsize") or 0) * 1024
            if not size and loc and os.path.isdir(loc) and norm(loc) not in PROTECTED_DIRS:
                size = dir_size(loc)
            apps.append(App_(name, v.get("displayversion") or "", v.get("publisher") or "", size, loc, status,
                             v.get("uninstallstring") or ""))
    return apps


def store_apps():
    """Microsoft Store / MSIX apps (not in the Uninstall keys). Framework packages are skipped."""
    import json
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-AppxPackage | Where-Object { -not $_.IsFramework } | "
                              "Select-Object Name,Version,PublisherId,InstallLocation,SignatureKind | ConvertTo-Json"],
                             capture_output=True, text=True, timeout=60, creationflags=0x08000000).stdout
        pkgs = json.loads(out or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    pkgs = [pkgs] if isinstance(pkgs, dict) else pkgs
    return [App_(p["Name"], p.get("Version") or "", "System app" if p.get("SignatureKind") == 4 else "Store app",
                 0, p.get("InstallLocation") or "", "Installed (Store app)", "") for p in pkgs]


def app_tokens(apps):
    """Name fragments that identify installed apps, for leftover matching."""
    toks = set()
    for a in apps:
        for s in (a.name, a.publisher, os.path.basename(a.location), os.path.basename(os.path.dirname(a.location)),
                  *a.name.split(".")):  # Store names look like "SpotifyAB.SpotifyMusic"
            k = key_of(s)
            if len(k) >= 3:
                toks.add(k)
        first = key_of(a.name.split()[0]) if a.name.split() else ""
        if len(first) >= 4:
            toks.add(first)
    return toks


def belongs_to_installed(folder, tokens, locations):
    fk = key_of(os.path.basename(folder))
    nf = norm(folder)
    if any(loc == nf or loc.startswith(nf + os.sep) or nf.startswith(loc + os.sep) for loc in locations):
        return True
    # short names must match a whole token / its start ("code" must not match "avcencoder")
    return any(fk == t or t.startswith(fk) or (len(fk) >= 6 and fk in t) or (len(t) >= 4 and t in fk) for t in tokens)


def find_leftovers(apps, skip_paths=(), min_idle_days=30):
    """Folders in AppData / ProgramData / Program Files that match no installed app and haven't
    been touched for min_idle_days -> probably left by an uninstalled app."""
    tokens = app_tokens(apps)
    locations = [norm(a.location) for a in apps if a.location]
    skip = [norm(p) for p in skip_paths]
    cutoff = time.time() - min_idle_days * DAY
    out = []
    for base, where in ((LOCAL, "AppData\\Local"), (ROAMING, "AppData\\Roaming"), (PROGDATA, "ProgramData"),
                        (PROGFILES, "Program Files"), (PROGFILES86, "Program Files (x86)")):
        try:
            entries = list(os.scandir(base))
        except OSError:
            continue
        for e in entries:
            n = e.name.lower()
            if (is_link(e) or not e.is_dir(follow_symlinks=False) or n in LEFTOVER_IGNORE
                    or n.startswith(("{", ".", "s-1-", "microsoft", "windows")) or len(key_of(n)) < 3
                    or any(norm(e.path) == s or s.startswith(norm(e.path) + os.sep) for s in skip)
                    or belongs_to_installed(e.path, tokens, locations)):
                continue
            size, newest = dir_stats(e.path)
            if newest > cutoff or size < 1024 * 1024:
                continue  # recently used -> still in use (portable tool), or tiny
            out.append((e.name, where, size, newest, e.path))
    return sorted(out, key=lambda r: -r[2])


def recycle(path):
    return recycle_many([path]) == [path]


def recycle_many(paths):
    """Send paths to the Recycle Bin (undoable) in one shell call; one call per item is slow for hundreds.
    Refuses protected roots and anything inside Windows. Returns the paths that are gone."""
    ok = [p for p in paths if not (norm(p) in PROTECTED_DIRS or norm(p).startswith(norm(WINDIR) + os.sep) or len(norm(p)) <= 3)]
    if not ok:
        return []

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", wintypes.LPCWSTR),
                    ("pTo", wintypes.LPCWSTR), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                    ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR)]
    def shell_recycle(ps):
        op = SHFILEOPSTRUCTW(None, 3, "\0".join(ps) + "\0", None, 0x40 | 0x10 | 0x400 | 0x4, False, None, None)
        ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))

    shell_recycle(ok)
    if len(ok) > 1:  # the batch stops at the first locked item: retry the rest one by one
        for p in [p for p in ok if os.path.exists(p)]:
            shell_recycle([p])
    return [p for p in ok if not os.path.exists(p)]


# ---------- drives ----------

class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]


def recycle_bin_size():
    info = SHQUERYRBINFO(ctypes.sizeof(SHQUERYRBINFO), 0, 0)
    ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    return info.i64Size


def empty_recycle_bin():
    size = recycle_bin_size()
    ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)  # no confirm, no progress, no sound
    return size


def fixed_drives():
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    return [f"{chr(65 + i)}:\\" for i in range(26)
            if mask >> i & 1 and ctypes.windll.kernel32.GetDriveTypeW(f"{chr(65 + i)}:\\") == 3]


def classify_file(path):
    p = os.path.normcase(path)
    if p.startswith(norm(os.path.join(HOME, "Downloads"))):
        return CAUTION, "Downloaded file - delete if no longer needed"
    if p.endswith((".iso", ".zip", ".rar", ".7z", ".msi", ".exe")):
        return CAUTION, "Installer / archive - often safe once used"
    if p.endswith((".vhdx", ".vmdk", ".vdi")):
        return PROTECTED, "Virtual machine disk - deleting loses that VM"
    if p.endswith((".tmp", ".log", ".dmp", ".old", ".bak")):
        return CAUTION, "Temp / log / backup file - usually safe if old"
    return PROTECTED, "Personal file - only you can decide"


def classify(path, is_dir, parent_level=None):
    """(level, meaning) for one entry in the drive map."""
    name, parent = os.path.basename(path).lower(), norm(os.path.dirname(path))
    if parent == norm(SYSDRIVE + "\\") and name in ROOT_INFO:
        return ROOT_INFO[name]
    if len(parent) <= 3 and name in ("$recycle.bin", "system volume information", "tmp", "temp"):
        return ROOT_INFO[name]
    if len(parent) <= 3 and name in ("download", "downloads"):
        return CAUTION, "Downloads - review, delete what you don't need"
    if parent == norm(HOME):
        if name in HOME_INFO:
            return HOME_INFO[name]
        if name.startswith(".") and is_dir:
            return CAUTION, "Tool config / cache folder (dev tools)"
    p = norm(path)
    if p.startswith((norm(WINDIR), norm(PROGFILES), norm(PROGFILES86), norm(PROGDATA))):
        return PROTECTED, "System / installed program files"
    if is_dir and name in CACHE_NAMES:
        return SAFE, "Cache folder - see the Junk tab to clean"
    if not is_dir:
        return classify_file(path)
    if parent_level:
        return parent_level, ""
    if len(parent) <= 3:
        return (CAUTION, "Unknown folder - check what app made it") if parent == norm(SYSDRIVE + "\\") \
            else (PROTECTED, "Your files on this drive - review manually")
    return PROTECTED, ""


def list_dir(path, parent_level=None, min_size=1024 * 1024, limit=300):
    """[(name, size, level, meaning, full_path, is_dir)] for the children of path, biggest first."""
    rows = []
    try:
        entries = list(os.scandir(path))
    except OSError:
        return rows
    for e in entries:
        try:
            if is_link(e):
                continue
            is_dir = e.is_dir(follow_symlinks=False)
            if is_dir and norm(e.path) == norm(SYSDRIVE + r"\Users"):
                size = None  # broken down in "Your folder"
            else:
                size = dir_size(e.path) if is_dir else e.stat(follow_symlinks=False).st_size
        except OSError:
            continue
        if size is None or size >= min_size:
            level, meaning = classify(e.path, is_dir, parent_level)
            rows.append((e.name, size, level, meaning, e.path, is_dir))
    return sorted(rows, key=lambda r: -(r[1] or 0))[:limit]


SKIP_WALK = {"appdata", "$recycle.bin", "system volume information", "windows", "program files",
             "program files (x86)", "programdata", "node_modules"}


def survey(roots, min_size=MB):
    """One pass over roots -> (files >= min_size as [(size, path)], top-most empty folders).
    Skips AppData, system folders and dot-folders; links count as content and are never followed."""
    files, empty = [], []

    def visit(d):  # True if there is no file anywhere under d
        try:
            entries = list(os.scandir(d))
        except OSError:
            return False
        content, empty_kids = False, []
        for e in entries:
            try:
                if is_link(e) or not e.is_dir(follow_symlinks=False):
                    content = True
                    st = None if is_link(e) else e.stat(follow_symlinks=False)
                    # online-only cloud files (OneDrive...) use no disk, and reading one to hash it would download it
                    if st and st.st_size >= min_size and not st.st_file_attributes & CLOUD_ONLY:
                        files.append((st.st_size, e.path))
                elif e.name.startswith(".") or e.name.lower() in SKIP_WALK or not visit(e.path):
                    content = True
                else:
                    empty_kids.append(e.path)
            except OSError:
                content = True
        if content:  # an empty parent already covers its empty children
            empty.extend(p for p in empty_kids if norm(p) not in PROTECTED_DIRS)
        return not content

    for r in roots:
        visit(r)
    return files, empty


def long_path(p):
    """Paths over 260 characters only open with the \\\\?\\ prefix."""
    return "\\\\?\\" + p if len(p) >= 260 and not p.startswith("\\\\") else p


def file_hash(path, part="all"):
    """Digest of the file's first 64 KB ("head"), last 64 KB ("tail") or whole content; None if unreadable."""
    try:
        with open(long_path(path), "rb") as f:
            if part == "all":
                return hashlib.file_digest(f, "blake2b").digest()
            if part == "tail":
                f.seek(max(0, os.fstat(f.fileno()).st_size - CHUNK))
            return hashlib.blake2b(f.read(CHUNK)).digest()
    except OSError:
        return None


def mtime(p):
    try:
        return os.path.getmtime(long_path(p))
    except OSError:
        return 0


def find_duplicates(files, limit=300):
    """[(size, [paths, oldest first])] of identical files, most wasted space first.
    Same size -> same first 64 KB -> same last 64 KB -> same full hash, so most files are never read in full.
    Hashing runs on 8 threads: file reads and hashlib release the GIL."""
    # ponytail: hard links look like duplicates but recycling one frees nothing; compare st_ino if that shows up
    size = dict((p, s) for s, p in files)
    by_size = {}
    for s, p in files:
        by_size.setdefault(s, []).append(p)
    groups = [g for g in by_size.values() if len(g) > 1]
    with ThreadPoolExecutor(8) as pool:
        def split(groups, part):
            flat = [p for g in groups for p in g]
            keys = dict(zip(flat, pool.map(lambda p: file_hash(p, part), flat)))
            out = []
            for g in groups:
                by_key = {}
                for p in g:
                    if keys[p] is not None:
                        by_key.setdefault(keys[p], []).append(p)
                out += [x for x in by_key.values() if len(x) > 1]
            return out

        groups = split(split(groups, "head"), "tail")
        small = [g for g in groups if size[g[0]] <= 2 * CHUNK]  # head + tail already cover the whole file
        groups = small + split([g for g in groups if size[g[0]] > 2 * CHUNK], "all")
    out = [(size[g[0]], sorted(g, key=mtime)) for g in groups]
    return sorted(out, key=lambda g: -g[0] * (len(g[1]) - 1))[:limit]


# ---------- history & schedule ----------

def log_cleanup(what, freed, items, source="app", path=HISTORY):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M"), "what": what, "freed": freed,
                            "items": list(items)[:50], "source": source}) + "\n")


def read_history(path=HISTORY):
    """Past cleanups, newest first."""
    try:
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()][::-1]
    except (OSError, ValueError):
        return []


def task_command():
    if getattr(sys, "frozen", False):  # the PyInstaller exe
        return f'"{sys.executable}" --clean-safe --yes --scheduled'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")  # no console window
    return f'"{pyw if os.path.exists(pyw) else sys.executable}" "{os.path.abspath(__file__)}" --clean-safe --yes --scheduled'


def set_schedule(when):
    """'daily' / 'weekly' Safe-only cleanup in Task Scheduler, or 'off'. True on success."""
    args = (["schtasks", "/Delete", "/TN", TASK, "/F"] if when == "off" else
            ["schtasks", "/Create", "/TN", TASK, "/SC", when.upper(), "/ST", "12:00", "/TR", task_command(), "/F"])
    return subprocess.run(args, capture_output=True, creationflags=NO_WINDOW).returncode == 0


def schedule_on():
    return subprocess.run(["schtasks", "/Query", "/TN", TASK], capture_output=True, creationflags=NO_WINDOW).returncode == 0


def all_apps():
    return installed_apps() + store_apps()


def scan_junk():
    """[(level, category, label, note, rules, total, sizes)]: Windows Disk Cleanup rules, extra rules,
    per-app caches and the Recycle Bin. rules may be ["RECYCLE"]."""
    rules = windows_cleanup_rules()
    seen = {norm(r.folder) for r in rules}
    rules += [r for r in EXTRA if norm(r.folder) not in seen]
    merged = {}  # one row per label (e.g. "Temporary Files" spans 8 folders)
    for r in rules:
        merged.setdefault((r.level, r.category, r.label, r.note), []).append(r)
    rows = []
    for k, rs in merged.items():
        sizes = [process(r) for r in rs]
        rows.append((*k, rs, sum(sizes), sizes))
    known = [norm(r.folder) for r in rules]
    apps = {}
    for base in (LOCAL, ROAMING):
        for app, p in find_app_caches(base):
            if not any(norm(p).startswith(k) for k in known):
                apps.setdefault(app, []).append(Rule(SAFE, "App caches", app, p, ALL, 0, ""))
    for app, rs in apps.items():
        sizes = [process(r) for r in rs]
        rows.append((SAFE, "App caches", app, f"{len(rs)} cache folder(s); app rebuilds them", rs, sum(sizes), sizes))
    bin_size = recycle_bin_size()
    rows.append((CAUTION, "System", "Recycle Bin", "Files you deleted - can't be restored after this",
                 ["RECYCLE"], bin_size, [bin_size]))
    return rows, known


def reveal(path):
    """Open the exact folder, or the parent folder with the file selected."""
    if os.path.isdir(path):
        subprocess.Popen(["explorer", os.path.normpath(path)])
    elif os.path.exists(path):
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
    else:
        messagebox.showwarning("Not found", f"This no longer exists:\n{path}")


# ---------- GUI ----------

ICON = {SAFE: "\u25cf  Safe", CAUTION: "\u25b2  Caution", PROTECTED: "\u25a0  Protected"}
# Windows 11 semantic colours, readable on each theme
COLORS = {"dark": {SAFE: "#6ccb5f", CAUTION: "#fce100", PROTECTED: "#ff99a4", "muted": "#9a9a9a"},
          "light": {SAFE: "#0f7b0f", CAUTION: "#9d5d00", PROTECTED: "#c42b1c", "muted": "#6b6b6b"}}
TINTS = {"dark": {SAFE: "#1e2b1f", CAUTION: "#2e2a17", PROTECTED: "#2e1f21"},  # calm row backgrounds
         "light": {SAFE: "#eef7ee", CAUTION: "#fdf6e3", PROTECTED: "#fcefee"}}
LEVEL_HEAD = {SAFE: ("Safe to delete", "Apps rebuild this automatically"),
              CAUTION: ("Review first", "Deletable, but you lose something \u2014 read each note")}
DUMMY = "\u2026loading"
FONT = "Segoe UI Variable Text"
try:
    import sv_ttk  # Windows 11 "Sun Valley" theme
except ImportError:
    sv_ttk = None


def dark_title_bar(win, on):
    """Match the Windows title bar to the theme (DWMWA_USE_IMMERSIVE_DARK_MODE)."""
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1 if on else 0)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(val), 4)
        win.withdraw(), win.deiconify()  # repaint the frame
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Storage Cleaner")
        self.geometry("1320x800")
        self.minsize(1000, 600)
        self.q = queue.Queue()
        self.rules = {}  # junk iid -> list of Rule (or "RECYCLE")
        self.level = {}  # junk iid -> level
        self.paths = {}  # (tree, iid) -> filesystem path, for double-click / Open location
        self.size = {}  # (tree, iid) -> bytes, for item rows
        self.scanning = False
        self.trees = []
        self.totals = {SAFE: 0, CAUTION: 0}
        self.theme = "dark" if sv_ttk else "light"  # without the theme, Tk is light-only
        if sv_ttk:
            sv_ttk.set_theme(self.theme)
        self.style = ttk.Style(self)

        # ----- header -----
        head = ttk.Frame(self, padding=(20, 16, 20, 8))
        head.pack(fill="x")
        titles = ttk.Frame(head)
        titles.pack(side="left")
        ttk.Label(titles, text="Storage Cleaner", font=(FONT, 22, "bold")).pack(anchor="w")
        self.subtitle = ttk.Label(titles, text="Find junk, app caches and leftovers \u2014 and know what's safe to delete",
                                  font=(FONT, 10))
        self.subtitle.pack(anchor="w")
        self.scan_btn = ttk.Button(head, text="\u21bb  Scan now", style="Accent.TButton", command=self.scan, width=14)
        self.scan_btn.pack(side="right", ipady=4)
        self.theme_btn = ttk.Button(head, text="\u2600  Light", command=self.toggle_theme)
        if sv_ttk:
            self.theme_btn.pack(side="right", padx=8)
        tools = ttk.Menubutton(head, text="Windows tools")
        menu = tk.Menu(tools, tearoff=False)
        menu.add_command(label="Disk Cleanup", command=lambda: subprocess.Popen(["cleanmgr", "/d", SYSDRIVE]))
        menu.add_command(label="Uninstall apps (Settings)", command=lambda: os.startfile("ms-settings:appsfeatures"))
        menu.add_command(label="Storage settings", command=lambda: os.startfile("ms-settings:storagesense"))
        tools["menu"] = menu
        tools.pack(side="right")
        more = ttk.Menubutton(head, text="More")
        mm = tk.Menu(more, tearoff=False)
        mm.add_command(label="Cleanup history\u2026", command=self.show_history_window)
        self.sched = tk.BooleanVar(value=False)
        mm.add_checkbutton(label="Weekly automatic Safe cleanup", variable=self.sched, command=self.toggle_schedule)
        more["menu"] = mm
        more.pack(side="right", padx=(0, 8))
        threading.Thread(target=lambda: self.q.put(("sched", schedule_on())), daemon=True).start()

        # ----- summary cards -----
        cards = ttk.Frame(self, padding=(20, 4, 20, 8))
        cards.pack(fill="x")
        self.card_val = {}
        for key, title, hint in ((SAFE, "Safe to delete", "caches, temp, logs"),
                                 (CAUTION, "Needs review", "downloads, bin, packages"),
                                 ("left", "Leftovers", "from uninstalled apps"),
                                 ("dupes", "Duplicates", "extra copies of files"),
                                 ("apps", "Installed apps", "desktop + Store")):
            c = ttk.Frame(cards, style="Card.TFrame", padding=(16, 10))
            c.pack(side="left", fill="both", expand=True, padx=(0, 10))
            ttk.Label(c, text=title, font=(FONT, 10)).pack(anchor="w")
            v = ttk.Label(c, text="\u2014", font=(FONT, 20, "bold"))
            v.pack(anchor="w")
            ttk.Label(c, text=hint, font=(FONT, 9), foreground=COLORS[self.theme]["muted"]).pack(anchor="w")
            self.card_val[key] = v
        self.drive_box = ttk.Frame(cards, style="Card.TFrame", padding=(16, 10))
        self.drive_box.pack(side="left", fill="both", expand=True)

        # ----- tabs -----
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=20)
        self.junk = self._tree("\U0001f9f9  Junk & caches", ("level", "size", "note", "path"))
        self.apps = self._tree("\U0001f4e6  Installed apps", ("status", "size", "version", "publisher", "path"))
        self.left = self._tree("\U0001f47b  Leftovers", ("level", "size", "unused", "where", "path"))
        self.map = self._tree("\U0001f5fa  Drive map", ("level", "size", "note", "path"))
        self.big = self._tree("\U0001f4c1  Large files", ("level", "size", "note", "path"))
        self.dupes = self._tree("\U0001f46f  Duplicates", ("level", "size", "note", "path"))
        self.empty = self._tree("\U0001f4c2  Empty folders", ("level", "size", "note", "path"))
        self.map.bind("<<TreeviewOpen>>", self.expand_map)

        # ----- bottom bar -----
        bottom = ttk.Frame(self, padding=(20, 10, 20, 14))
        bottom.pack(fill="x")
        self.spinner = ttk.Progressbar(bottom, mode="indeterminate", length=120)
        self.status = ttk.Label(bottom, text="Press Scan now to start. Double-click any row to open it in Explorer.",
                                font=(FONT, 10))
        self.status.pack(side="left")
        ttk.Button(bottom, text="\U0001f5d1  Clean selected", style="Accent.TButton", command=self.clean).pack(side="right", ipady=2)
        ttk.Button(bottom, text="\u2713  Select suggested", command=self.select_suggested).pack(side="right", padx=8)
        ttk.Button(bottom, text="\U0001f4c2  Open location", command=self.open_selected).pack(side="right")

        self.apply_colors()
        self.update_disk()
        self.after(100, self.poll)

    def _tree(self, title, cols):
        frame = ttk.Frame(self.nb, padding=(0, 8, 0, 0))
        self.nb.add(frame, text=title)
        t = ttk.Treeview(frame, columns=cols, selectmode="extended")
        widths = {"level": 110, "status": 200, "size": 90, "note": 380, "path": 400, "version": 100,
                  "publisher": 170, "unused": 110, "where": 140}
        t.heading("#0", text="Item", anchor="w")
        t.column("#0", width=320)
        for c in cols:
            t.heading(c, text={"unused": "Unused for", "path": "Location  (double-click to open)",
                               "level": "Safety", "size": "Size   "}.get(c, c.title()), anchor="e" if c == "size" else "w")
            t.column(c, width=widths[c], anchor="e" if c == "size" else "w")
        sb = ttk.Scrollbar(frame, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(fill="both", expand=True)
        t.bind("<Double-1>", lambda e, t=t: self.on_double(t, e))
        self.trees.append(t)
        return t

    def apply_colors(self):
        col = COLORS[self.theme]
        for t in self.trees:
            for lvl in (SAFE, CAUTION, PROTECTED):
                t.tag_configure(lvl, background=TINTS[self.theme][lvl], foreground="")
                t.tag_configure("head-" + lvl, foreground=col[lvl])
            t.tag_configure("group", font=(FONT, 10, "bold"))
        for key in (SAFE, CAUTION):
            self.card_val[key].configure(foreground=col[key])
        self.subtitle.configure(foreground=col["muted"])
        self.style.configure("Treeview", rowheight=30, font=(FONT, 10))
        self.style.configure("Treeview.Heading", font=(FONT, 10, "bold"))
        self.style.configure("TNotebook.Tab", font=(FONT, 10), padding=(14, 6))
        self.style.configure("Accent.TButton", font=(FONT, 10, "bold"))
        self.style.configure("TButton", font=(FONT, 10))
        dark_title_bar(self, self.theme == "dark")

    def toggle_theme(self):
        self.theme = "light" if self.theme == "dark" else "dark"
        if sv_ttk:
            sv_ttk.set_theme(self.theme)
        self.theme_btn.configure(text="\u2600  Light" if self.theme == "dark" else "\u263e  Dark")
        self.apply_colors()
        self.update_disk()

    def _add(self, tree, parent, text, values=(), level=None, path=None, open_=False, group=False, size=None):
        # group rows: coloured bold text; item rows: soft tint by safety level
        tags = ("group", "head-" + level) if group and level else ("group",) if group else (level,) if level else ()
        iid = tree.insert(parent, "end", text=text, values=values, tags=tags, open=open_)
        if path:
            self.paths[(tree, iid)] = path
        if size is not None:
            self.size[(tree, iid)] = size  # lets a cleanup update totals without rescanning
        return iid

    def update_disk(self):
        for w in self.drive_box.winfo_children():
            w.destroy()
        ttk.Label(self.drive_box, text="Drives", font=(FONT, 10)).pack(anchor="w")
        for d in fixed_drives():
            u = shutil.disk_usage(d)
            row = ttk.Frame(self.drive_box, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=d[:2], font=(FONT, 10, "bold"), width=3).pack(side="left")
            bar = ttk.Progressbar(row, maximum=100, value=u.used / u.total * 100, length=140)
            bar.pack(side="left", padx=6, fill="x", expand=True)
            ttk.Label(row, text=f"{fmt(u.free)} free of {fmt(u.total)}", font=(FONT, 9)).pack(side="left")

    def busy(self, on):
        self.scanning = on
        if on:
            self.spinner.pack(side="left", padx=(0, 10), before=self.status)
            self.spinner.start(12)
            self.scan_btn.state(["disabled"])
        else:
            self.spinner.stop()
            self.spinner.pack_forget()
            self.scan_btn.state(["!disabled"])

    # ----- scanning -----
    def scan(self):
        for t in self.trees:
            t.delete(*t.get_children())
        self.rules.clear(), self.level.clear(), self.paths.clear(), self.size.clear()
        for v in self.card_val.values():
            v.configure(text="…")
        self.busy(True)
        self.status.config(text="Scanning junk, apps, drives and files in parallel...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        """Independent parts run in separate processes (folder walks are CPU-bound Python, so threads
        would queue on the GIL); results show up as each part finishes."""
        drives = fixed_drives()
        others = [d for d in drives if norm(d) != norm(SYSDRIVE + "\\")]
        parts = {"junk": (scan_junk,), "apps": (all_apps,), "survey": (survey, [HOME] + others),
                 **{("map", f"Drive {d}", d): (list_dir, d) for d in drives},
                 ("map", f"Your folder ({HOME})", HOME): (list_dir, HOME)}
        got, t0 = {}, time.time()
        with ProcessPoolExecutor(min(len(parts) + 1, os.cpu_count() or 2)) as ex:
            futures = {ex.submit(*job): key for key, job in parts.items()}
            dupes = None
            for n, f in enumerate(as_completed(futures), 1):
                key = futures[f]
                try:
                    res = f.result()
                except Exception:  # a worker process died: do that part here instead
                    res = parts[key][0](*parts[key][1:])
                if key[0] == "map":
                    self.q.put(("map", (key[1], key[2], res)))
                elif key == "junk":
                    got["known"] = res[1]
                    self.q.put(("junk", res[0]))
                elif key == "apps":
                    got["apps"] = res
                    self.q.put(("apps", res))
                else:  # survey
                    files, empty = res
                    self.q.put(("big", sorted(((s, p) for s, p in files if s >= 200 * MB), reverse=True)[:150]))
                    self.q.put(("empty", empty))
                    dupes = ex.submit(find_duplicates, files)  # hashes while the drive maps finish
                if key in ("junk", "apps") and "known" in got and "apps" in got:
                    self.q.put(("left", find_leftovers(got["apps"], skip_paths=got["known"])))
                self.q.put(("say", f"Scanning... {n} of {len(parts)} parts done"))
            self.q.put(("say", "Comparing files to find duplicates..."))
            try:
                self.q.put(("dupes", dupes.result()))
            except Exception:
                self.q.put(("dupes", []))
        self.q.put(("say", f"Scan done in {time.time() - t0:.0f}s. Double-click any row to open it."))

    def poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                getattr(self, "show_" + kind)(data)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def show_say(self, text):
        if text.startswith("Scan done"):
            self.busy(False)
            text = f"{text}   Safe to delete: {fmt(self.totals[SAFE])}   Caution: {fmt(self.totals[CAUTION])}"
        self.status.config(text=text)

    def show_junk(self, rows):
        totals = {SAFE: 0, CAUTION: 0}
        groups = {}
        for level, cat, label, note, rules, size, sizes in sorted(rows, key=lambda r: -r[5]):
            if size < 1024 * 1024:
                continue  # hide < 1 MB noise
            if (level, cat) not in groups:
                if level not in groups:
                    groups[level] = self._add(self.junk, "", LEVEL_HEAD[level][0], level=level, open_=True, group=True,
                                              values=("", "", LEVEL_HEAD[level][1], ""))
                groups[(level, cat)] = self._add(self.junk, groups[level], cat, open_=True, group=True)
            recycle_bin = rules[0] == "RECYCLE"
            folder = None if recycle_bin else rules[0].folder
            iid = self._add(self.junk, groups[(level, cat)], label, level=level, path=folder, size=size,
                            values=(ICON[level], fmt(size), note, "" if recycle_bin else folder + (" ..." if len(rules) > 1 else "")))
            if len(rules) > 1 and not recycle_bin:  # show each folder, each double-clickable
                for r, s in sorted(zip(rules, sizes), key=lambda x: -x[1]):
                    if s >= 1024 * 1024:
                        self._add(self.junk, iid, os.path.basename(r.folder), level=level, path=r.folder,
                                  values=(ICON[level], fmt(s), "", r.folder))
            self.rules[iid], self.level[iid] = rules, level
            totals[level] += size
        self.totals = totals
        self.card_val[SAFE].configure(text=fmt(totals[SAFE]))
        self.card_val[CAUTION].configure(text=fmt(totals[CAUTION]))
        self.status.config(text=f"Safe to delete: {fmt(totals[SAFE])}   Caution: {fmt(totals[CAUTION])}   - still scanning...")

    def show_apps(self, apps):
        broken = [a for a in apps if a.status.startswith("Broken")]
        desktop = [a for a in apps if a.status == "Installed"]
        store = [a for a in apps if a.status.startswith("Installed (") and a.publisher != "System app"]
        self.card_val["apps"].configure(text=f"{len(desktop) + len(store)}" + (f"  ·  {len(broken)} broken" if broken else ""))
        for title, group, level in ((f"Broken registry entries ({len(broken)}) — app files gone, entry left behind", broken, CAUTION),
                                    (f"Desktop apps ({len(desktop)})", desktop, SAFE),
                                    (f"Store apps ({len(store)})", store, SAFE)):
            if not group:
                continue
            g = self._add(self.apps, "", title, level=level, open_=True, group=True)
            for a in sorted(group, key=lambda a: -a.size):
                self._add(self.apps, g, a.name, level=level, path=a.location or None,
                          values=(a.status, fmt(a.size) if a.size else "?", a.version, a.publisher, a.location))

    def show_left(self, rows):
        self.card_val["left"].configure(text=f"{fmt(sum(r[2] for r in rows))}  ·  {len(rows)}" if rows else "None")
        if not rows:
            self._add(self.left, "", "No leftovers found")
            return
        g = self._add(self.left, "", "Probably left by uninstalled apps", level=CAUTION, open_=True, group=True,
                      values=("", fmt(sum(r[2] for r in rows)), "", "",
                              "No installed app matches · unused 30+ days · check before recycling"))
        for name, where, size, newest, path in rows:
            days = int((time.time() - newest) / DAY) if newest else 0
            self._add(self.left, g, name, level=CAUTION, path=path, size=size,
                      values=(ICON[CAUTION], fmt(size), f"{days} days" if newest else "?", where, path))

    def show_map(self, data):
        title, path, rows = data
        g = self._add(self.map, "", title, path=path, open_=True, group=True)
        self._fill_map(g, rows)

    def _fill_map(self, parent, rows):
        for name, size, level, meaning, path, is_dir in rows:
            iid = self._add(self.map, parent, name, level=level, path=path,
                            values=(ICON[level], "" if size is None else fmt(size), meaning, path))
            if is_dir and size:
                self.map.insert(iid, "end", text=DUMMY)  # expandable: load children on open
        if not rows:
            self.map.insert(parent, "end", text="(nothing over 1 MB)")

    def expand_map(self, _):
        iid = self.map.focus()
        kids = self.map.get_children(iid)
        if len(kids) == 1 and self.map.item(kids[0], "text") == DUMMY:
            path = self.paths.get((self.map, iid))
            tags = self.map.item(iid, "tags")
            level = tags[0] if tags else None
            self.map.item(kids[0], text=DUMMY + " (measuring folder sizes)")
            threading.Thread(target=lambda: self.q.put(("children", (iid, list_dir(path, level)))), daemon=True).start()

    def show_children(self, data):
        iid, rows = data
        self.map.delete(*self.map.get_children(iid))
        self._fill_map(iid, rows)

    def show_big(self, data):
        for s, p in data:
            level, note = classify_file(p)
            self._add(self.big, "", os.path.basename(p), level=level, path=p, values=(ICON[level], fmt(s), note, p))

    def show_dupes(self, groups):
        waste = sum(s * (len(ps) - 1) for s, ps in groups)
        self.card_val["dupes"].configure(text=f"{fmt(waste)}  \u00b7  {len(groups)}" if groups else "None")
        if not groups:
            return self._add(self.dupes, "", "No identical files over 1 MB found")
        for s, paths in groups:
            g = self._add(self.dupes, "", f"{os.path.basename(paths[0])}   \u00d7{len(paths)}", level=CAUTION, group=True,
                          values=("", fmt(s * (len(paths) - 1)), "Identical copies \u2014 'Select suggested' keeps the oldest", ""))
            for i, p in enumerate(paths):
                self._add(self.dupes, g, os.path.basename(p), level=CAUTION if i else None, path=p, size=s,
                          values=(ICON[CAUTION] if i else "Keep", fmt(s), "Extra copy" if i else "Oldest copy", p))

    def show_empty(self, paths):
        if not paths:
            return self._add(self.empty, "", "No empty folders found")
        for p in sorted(paths):
            self._add(self.empty, "", os.path.basename(p), level=SAFE, path=p,
                      values=(ICON[SAFE], "", "Contains no files (only empty sub-folders, if any)", p))

    def show_sched(self, on):
        self.sched.set(on)

    def toggle_schedule(self):
        on = self.sched.get()
        if not set_schedule("weekly" if on else "off"):
            self.sched.set(not on)
            return messagebox.showerror("Schedule", "Windows Task Scheduler refused the change.")
        messagebox.showinfo("Schedule", "Every week at noon, Safe items are cleaned automatically.\n"
                            "Each run is listed in More > Cleanup history." if on else "Automatic cleanup is off.")

    def show_history_window(self):
        rows = read_history()
        win = tk.Toplevel(self)
        win.title("Cleanup history")
        win.geometry("820x440")
        ttk.Label(win, text=f"Freed {fmt(sum(r.get('freed', 0) for r in rows))} in {len(rows)} cleanups",
                  font=(FONT, 12, "bold"), padding=(16, 12)).pack(anchor="w")
        t = ttk.Treeview(win, columns=("what", "freed", "source"))
        for c, title, w in (("#0", "When", 150), ("what", "What", 480), ("freed", "Freed", 90), ("source", "By", 90)):
            t.heading(c, text=title, anchor="w")
            t.column(c, width=w)
        for r in rows:
            t.insert("", "end", text=r.get("time", ""), values=(
                f"{r.get('what', '')}: " + ", ".join(r.get("items", [])[:6]), fmt(r.get("freed", 0)), r.get("source", "")))
        t.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        dark_title_bar(win, self.theme == "dark")

    def show_cleaned(self, data):
        """Update only what was cleaned: a full rescan takes minutes."""
        msg, tree, update = data
        if tree is self.junk:  # update = {iid: bytes still there (in use / too new)}
            for iid, remaining in update.items():
                level = self.level[iid]
                self.totals[level] -= self.size[(tree, iid)] - remaining
                if remaining < MB:
                    parent = tree.parent(iid)
                    tree.delete(iid)
                    del self.rules[iid], self.level[iid]
                    if not tree.get_children(parent):
                        tree.delete(parent)  # empty category
                else:
                    self.size[(tree, iid)] = remaining
                    tree.delete(*tree.get_children(iid))  # per-folder sizes are stale
                    tree.set(iid, "size", fmt(remaining))
            for key in (SAFE, CAUTION):
                self.card_val[key].configure(text=fmt(self.totals[key]))
        else:  # update = paths now in the Recycle Bin
            done = set(update)
            for (t, iid), p in list(self.paths.items()):
                if t is tree and p in done and tree.exists(iid):
                    parent = tree.parent(iid)
                    tree.delete(iid)
                    if tree is self.dupes and parent and len(tree.get_children(parent)) < 2:
                        tree.delete(parent)  # one copy left: no longer a duplicate
            self.refresh_cards()
        self.update_disk()
        messagebox.showinfo("Done", msg)

    def refresh_cards(self):
        """Recompute the Leftovers / Duplicates cards and group totals from the rows still listed."""
        left = []
        for g in self.left.get_children():
            sizes = [self.size[(self.left, i)] for i in self.left.get_children(g) if (self.left, i) in self.size]
            left += sizes
            self.left.set(g, "size", fmt(sum(sizes)))
        self.card_val["left"].configure(text=f"{fmt(sum(left))}  \u00b7  {len(left)}" if left else "None")
        waste = groups = 0
        for g in self.dupes.get_children():
            kids = self.dupes.get_children(g)
            if kids and (self.dupes, kids[0]) in self.size:
                w = self.size[(self.dupes, kids[0])] * (len(kids) - 1)
                self.dupes.set(g, "size", fmt(w))
                waste, groups = waste + w, groups + 1
        self.card_val["dupes"].configure(text=f"{fmt(waste)}  \u00b7  {groups}" if groups else "None")

    # ----- actions -----
    def current(self):
        return self.trees[self.nb.index(self.nb.select())]

    def on_double(self, tree, event):
        iid = tree.identify_row(event.y)
        path = self.paths.get((tree, iid))
        if path:  # expanding a row is done with its arrow
            reveal(path)

    def open_selected(self):
        t = self.current()
        paths = [self.paths[(t, i)] for i in t.selection() if (t, i) in self.paths]
        if not paths:
            return messagebox.showinfo("Open location", "Select a row that has a location.")
        for p in paths[:10]:
            reveal(p)

    def _junk_items(self, iids):
        out = []
        for i in iids:
            if i in self.rules:
                out.append(i)
            elif self.junk.parent(i) and self.junk.parent(i) in self.rules:
                out.append(self.junk.parent(i))
            else:
                out += self._junk_items(self.junk.get_children(i))
        return list(dict.fromkeys(out))

    def select_suggested(self):
        t = self.current()
        if t is self.dupes:  # every copy except the oldest
            t.selection_set([k for g in t.get_children() for k in t.get_children(g)[1:]])
        elif t is self.empty:
            t.selection_set([i for i in t.get_children() if (t, i) in self.paths])
        else:
            self.nb.select(0)
            self.junk.selection_set([i for i, lvl in self.level.items() if lvl == SAFE])

    def clean(self):
        if self.scanning:
            return messagebox.showinfo("Scan in progress", "Wait for the scan to finish, then clean.")
        t = self.current()
        if t in (self.left, self.dupes, self.empty):
            return self.recycle_selected(t)
        if t is not self.junk:
            return messagebox.showinfo("Review only", "This tab is for review: double-click to open in Explorer.\n"
                                       "Cleaning works in the Junk, Leftovers, Duplicates and Empty folders tabs.\n"
                                       "To remove an installed app use 'Uninstall apps (Settings)'.")
        sel = self._junk_items(self.junk.selection())
        if not sel:
            return messagebox.showwarning("Nothing selected", "Select items or a group in the Junk tab.")
        lines = [f"{ICON[self.level[i]]}  {self.junk.item(i, 'text')}  ({self.junk.item(i, 'values')[1]})" for i in sel]
        caution = [i for i in sel if self.level[i] == CAUTION]
        msg = "Delete the following?\n\n" + "\n".join(lines[:20]) + ("\n..." if len(lines) > 20 else "")
        if caution:
            msg += "\n\n\u26a0 CAUTION items included:\n" + "\n".join(
                f"- {self.junk.item(i, 'text')}: {self.junk.item(i, 'values')[2]}" for i in caution)
        if not messagebox.askyesno("Confirm", msg + "\n\nThis cannot be undone. Continue?",
                                   icon="warning" if caution else "question"):
            return
        jobs = [r for i in sel for r in self.rules[i]]
        labels = [self.junk.item(i, "text") for i in sel]
        self.status.config(text="Cleaning...")

        rules = {i: self.rules[i] for i in sel}

        def work():
            freed = sum(empty_recycle_bin() if r == "RECYCLE" else process(r, delete=True) for r in jobs)
            log_cleanup("Junk & caches", freed, labels)
            left = {i: sum(0 if r == "RECYCLE" else process(r) for r in rs) for i, rs in rules.items()}  # re-measure only these
            self.q.put(("cleaned", (f"Freed {fmt(freed)}.\nFiles in use or too new were skipped.", self.junk, left)))
        threading.Thread(target=work, daemon=True).start()

    def recycle_selected(self, tree):
        what = {self.left: "leftover folders", self.dupes: "duplicate files", self.empty: "empty folders"}[tree]
        sel = [i for i in tree.selection() if (tree, i) in self.paths]
        if not sel:
            return messagebox.showwarning("Nothing selected", f"Select {what} first ('Select suggested' helps).")
        if tree is self.dupes:
            for g in {tree.parent(i) for i in sel}:
                if set(tree.get_children(g)) <= set(sel):
                    return messagebox.showwarning("Keep one copy", f"Every copy of '{tree.item(g, 'text')}' is selected.\n"
                                                  "Leave at least one unselected.")
        names = "\n".join(f"- {tree.item(i, 'text')}  {tree.item(i, 'values')[1]}" for i in sel[:20])
        more = "\n..." if len(sel) > 20 else ""
        if not messagebox.askyesno("Move to Recycle Bin", f"Move these {len(sel)} {what} to the Recycle Bin?\n\n{names}{more}"
                                   "\n\nYou can restore them from the Recycle Bin.", icon="warning"):
            return
        paths = [self.paths[(tree, i)] for i in sel]

        def work():
            sizes = {p: dir_size(p) if os.path.isdir(p) else os.path.getsize(p) for p in paths if os.path.exists(p)}
            done = recycle_many(list(sizes))
            moved = sum(sizes[p] for p in done)
            log_cleanup(what.capitalize(), moved, [os.path.basename(p) for p in done])
            self.q.put(("cleaned", (f"Moved {len(done)} of {len(paths)} {what} ({fmt(moved)}) to the Recycle Bin.\n"
                                    "Empty the Recycle Bin to free the space. Items in use or needing admin were skipped.",
                                    tree, done)))
        threading.Thread(target=work, daemon=True).start()


def selftest():
    with tempfile.TemporaryDirectory() as t:
        j = lambda *p: os.path.join(t, *p)
        for d in (r"Discord\Cache\x", r"Google\Chrome\User Data\Default\Code Cache", r"MyApp\data", "outside"):
            os.makedirs(j(d))
        for name, data in ((r"Discord\Cache\x\f.bin", 1000), (r"MyApp\data\keep.txt", 4), ("outside\\precious.txt", 7)):
            with open(j(name), "wb") as f:
                f.write(b"0" * data)
        # junction inside a cache pointing outside must never be followed
        subprocess.run(["cmd", "/c", "mklink", "/J", j(r"Discord\Cache\link"), j("outside")], capture_output=True)

        found = dict(find_app_caches(t))
        assert set(found) == {"Discord", os.path.join("Google", "Chrome")}, found
        rule = Rule(SAFE, "", "", found["Discord"], ALL, 0, "")
        assert process(rule) == 1000
        assert process(rule, delete=True) == 1000
        assert os.path.exists(j(r"outside\precious.txt")), "followed a junction!"
        assert os.path.exists(j(r"MyApp\data\keep.txt"))

        # age filter: new files are kept
        os.makedirs(j("tmp"))
        with open(j(r"tmp\new.log"), "w") as f:
            f.write("x")
        with open(j(r"tmp\old.log"), "w") as f:
            f.write("xx")
        os.utime(j(r"tmp\old.log"), (time.time() - 10 * DAY,) * 2)
        assert process(Rule(SAFE, "", "", j("tmp"), ("*.log",), 7, ""), delete=True) == 2
        assert os.listdir(j("tmp")) == ["new.log"]

        # survey: top-most empty folder only; dot-folders count as content
        for d in (r"S\a\b\c", r"S\keep", r"S\.hidden\x"):
            os.makedirs(j(d))
        payload, big = os.urandom(70_000), os.urandom(300_000)
        middle = big[:150_000] + b"x" + big[150_001:]  # same size, head and tail: only the full hash differs
        for name, data in ((r"S\keep\one.bin", payload), (r"S\two.bin", payload), (r"S\keep\three.bin", payload),
                           (r"S\near.bin", payload[:65536] + os.urandom(70_000 - 65536)),  # same head, different tail
                           (r"S\big1.bin", big), (r"S\keep\big2.bin", big), (r"S\mid.bin", middle)):
            with open(j(name), "wb") as f:
                f.write(data)
        files, empty = survey([j("S")], min_size=1)
        assert empty == [j(r"S\a")], empty
        assert len(files) == 7
        dupes = {s: set(ps) for s, ps in find_duplicates(files)}
        assert dupes == {70_000: {j(r"S\keep\one.bin"), j(r"S\two.bin"), j(r"S\keep\three.bin")},
                         300_000: {j(r"S\big1.bin"), j(r"S\keep\big2.bin")}}, dupes

        # history round-trip, newest first
        h = j("history.jsonl")
        log_cleanup("a", 5, ["x"], path=h), log_cleanup("b", 7, ["y"], path=h)
        assert [r["what"] for r in read_history(h)] == ["b", "a"] and read_history(j("none.jsonl")) == []
        assert "--clean-safe --yes --scheduled" in task_command()

        # recycle bin move works and is refused for protected roots
        assert recycle(j("MyApp")) and not os.path.exists(j("MyApp"))
        assert recycle_many([j(r"S\a"), j(r"S\two.bin"), HOME]) == [j(r"S\a"), j(r"S\two.bin")]  # batch skips protected
        assert os.path.isdir(HOME)
    for p in (HOME, WINDIR, os.path.join(WINDIR, "System32"), SYSDRIVE + "\\", os.path.join(HOME, "Documents")):
        assert not safe_to_wipe(p, ALL), p
        assert not recycle(p), p
    assert safe_to_wipe(os.path.join(WINDIR, "Temp"), ALL)
    assert safe_to_wipe(WINDIR, ("*.dmp",))
    assert not safe_to_wipe(os.path.join(WINDIR, "System32", "config"), ALL)

    # registry helpers
    assert exe_from_command(r'"C:\Program Files\Foo\unins000.exe" /SILENT') == r"C:\Program Files\Foo\unins000.exe"
    assert exe_from_command(r"C:\Apps\Bar\uninstall.exe --x") == r"C:\Apps\Bar\uninstall.exe"
    assert exe_from_command("MsiExec.exe /X{123}") is None
    fake = [App_("Discord", "1", "Discord Inc.", 0, "", "Installed", ""),
            App_("Visual Studio Code", "1", "Microsoft Corporation", 0, r"C:\Apps\VSCode", "Installed", "")]
    toks, locs = app_tokens(fake), [norm(r"C:\Apps\VSCode")]
    assert belongs_to_installed(r"C:\x\Discord", toks, locs)
    assert belongs_to_installed(r"C:\Apps", toks, locs)  # parent of an install location
    assert not belongs_to_installed(r"C:\x\OldGameStudio", toks, locs)
    assert not belongs_to_installed(r"C:\x\Code", app_tokens([App_("Microsoft.AVCEncoderVideoExtension", "", "", 0, "", "", "")]), [])
    print("selftest ok")


def cli(a):
    if a.schedule:
        ok = set_schedule(a.schedule)
        print(("Scheduled " + a.schedule + " Safe cleanup at noon." if a.schedule != "off" else "Schedule removed.")
              if ok else "Task Scheduler refused the change (try an admin terminal).")
        return 0 if ok else 1
    if a.history:
        rows = read_history()
        for r in rows:
            print(f"{r['time']}  {fmt(r['freed']):>10}  {r['source']:<12}  {r['what']}: {', '.join(r['items'][:6])}")
        print(f"Total freed: {fmt(sum(r['freed'] for r in rows))} in {len(rows)} cleanups")
        return 0
    if a.duplicates is not None:
        groups = find_duplicates(survey(a.duplicates or [HOME])[0])
        if a.json:
            print(json.dumps([{"size": s, "paths": ps} for s, ps in groups], indent=1))
            return 0
        for s, ps in groups:
            print(f"\n{fmt(s * (len(ps) - 1))} wasted - {len(ps)} copies of {fmt(s)}:")
            print("\n".join(("  keep  " if i == 0 else "  extra ") + p for i, p in enumerate(ps)))
        print(f"\n{len(groups)} groups, {fmt(sum(s * (len(ps) - 1) for s, ps in groups))} in extra copies")
        return 0
    rows = [r for r in scan_junk()[0] if r[5] >= MB]
    rows.sort(key=lambda r: (r[0] != SAFE, -r[5]))
    safe = [r for r in rows if r[0] == SAFE]
    if a.json:
        print(json.dumps([{"level": r[0], "category": r[1], "label": r[2], "note": r[3], "bytes": r[5],
                           "folders": [x.folder for x in r[4] if x != "RECYCLE"]} for r in rows], indent=1))
    elif not a.scheduled:
        for level, cat, label, note, _, size, _ in rows:
            print(f"{level:<8} {fmt(size):>10}  {cat} / {label}  - {note}")
        print(f"\nSafe: {fmt(sum(r[5] for r in safe))}   Caution: {fmt(sum(r[5] for r in rows if r[0] == CAUTION))}")
    if not a.clean_safe:
        return 0
    if not a.yes and input(f"Delete the {len(safe)} Safe items above? [y/N] ").strip().lower() != "y":
        return 1
    freed = sum(process(r, delete=True) for row in safe for r in row[4])
    log_cleanup("Safe junk", freed, [r[2] for r in safe], "scheduled" if a.scheduled else "command line")
    print(f"Freed {fmt(freed)}. Files in use or too new were skipped.")
    return 0


def main():
    multiprocessing.freeze_support()  # the PyInstaller exe starts its scan workers through this
    ap = argparse.ArgumentParser(description="Storage Cleaner. With no options, opens the app.")
    ap.add_argument("--scan", action="store_true", help="list junk & caches with their safety level")
    ap.add_argument("--clean-safe", action="store_true", help="delete every Safe item (asks first unless --yes)")
    ap.add_argument("--yes", action="store_true", help="don't ask before deleting")
    ap.add_argument("--json", action="store_true", help="JSON output for --scan / --duplicates")
    ap.add_argument("--duplicates", nargs="*", metavar="FOLDER", help="list identical files (default: your user folder)")
    ap.add_argument("--history", action="store_true", help="show past cleanups")
    ap.add_argument("--schedule", choices=("daily", "weekly", "off"), help="automatic Safe cleanup via Task Scheduler")
    ap.add_argument("--test", action="store_true", help="run the self-check")
    ap.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)  # set by the scheduled task
    a = ap.parse_args()
    if a.test:
        return selftest()
    if a.scan or a.clean_safe or a.history or a.schedule or a.duplicates is not None:
        sys.exit(cli(a))
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on high-DPI screens
    except Exception:
        pass
    App().mainloop()


if __name__ == "__main__":
    main()
