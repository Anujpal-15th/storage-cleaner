"""Storage Cleaner - see what fills your drives, which apps hoard cache, what is installed,
what uninstalled apps left behind, and what is safe to delete.

Run:  python cleaner.py          (GUI)
      python cleaner.py --test   (self-check)

Every item gets a safety level:
  SAFE       rebuildable data (temp, caches, logs, dumps); apps recreate it.
  CAUTION    deletable, but you lose something (Recycle Bin, Downloads, package caches, leftovers).
  PROTECTED  system / personal data; shown so you know what it is, never deleted.

Rules come from Windows' own Disk Cleanup handlers (registry VolumeCaches: folder, file
pattern, minimum age), BleachBit/Winapp2-style app cache detection, and the registry
Uninstall keys (installed apps, broken entries, leftover folders).
Double-click any row to open that exact file/folder in Explorer.
"""
import ctypes, fnmatch, os, queue, re, shutil, subprocess, sys, tempfile, threading, time
import tkinter as tk
from collections import namedtuple
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
    """Yield (app_name, cache_path) for cache-named folders under base."""
    base = os.path.normpath(base)
    for root, dirs, _ in os.walk(base):
        rel = os.path.relpath(root, base)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        keep = []
        for d in dirs:
            full = os.path.join(root, d)
            if os.path.islink(full) or os.path.isjunction(full):
                continue
            if d.lower() in CACHE_NAMES and depth > 0:
                parts = rel.split(os.sep)
                app = os.path.join(*parts[:2]) if parts[0].lower() in GROUPERS and len(parts) > 1 else parts[0]
                yield app, full
            elif depth < max_depth:
                keep.append(d)
        dirs[:] = keep


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
    """Send path to the Recycle Bin (undoable). Refuses protected roots and anything inside Windows."""
    p = norm(path)
    if p in PROTECTED_DIRS or p.startswith(norm(WINDIR) + os.sep) or len(p) <= 3:
        return False

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", wintypes.LPCWSTR),
                    ("pTo", wintypes.LPCWSTR), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                    ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", wintypes.LPCWSTR)]
    op = SHFILEOPSTRUCTW(None, 3, path + "\0", None, 0x40 | 0x10 | 0x400 | 0x4, False, None, None)
    return ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) == 0 and not os.path.exists(path)


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


def big_files(roots, min_mb=200, limit=150):
    out, min_b = [], min_mb * 1024 * 1024
    skip = {"appdata", "$recycle.bin", "system volume information", "windows", "program files",
            "program files (x86)", "programdata"}
    for root in roots:
        for r, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d.lower() not in skip
                       and not os.path.isjunction(os.path.join(r, d))]
            for f in files:
                p = os.path.join(r, f)
                try:
                    s = os.path.getsize(p)
                except OSError:
                    continue
                if s >= min_b:
                    out.append((s, p))
    return sorted(out, reverse=True)[:limit]


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

        # ----- summary cards -----
        cards = ttk.Frame(self, padding=(20, 4, 20, 8))
        cards.pack(fill="x")
        self.card_val = {}
        for key, title, hint in ((SAFE, "Safe to delete", "caches, temp, logs"),
                                 (CAUTION, "Needs review", "downloads, bin, packages"),
                                 ("left", "Leftovers", "from uninstalled apps"),
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
        self.map.bind("<<TreeviewOpen>>", self.expand_map)

        # ----- bottom bar -----
        bottom = ttk.Frame(self, padding=(20, 10, 20, 14))
        bottom.pack(fill="x")
        self.spinner = ttk.Progressbar(bottom, mode="indeterminate", length=120)
        self.status = ttk.Label(bottom, text="Press Scan now to start. Double-click any row to open it in Explorer.",
                                font=(FONT, 10))
        self.status.pack(side="left")
        ttk.Button(bottom, text="\U0001f5d1  Clean selected", style="Accent.TButton", command=self.clean).pack(side="right", ipady=2)
        ttk.Button(bottom, text="\u2713  Select all Safe", command=self.select_safe).pack(side="right", padx=8)
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

    def _add(self, tree, parent, text, values=(), level=None, path=None, open_=False, group=False):
        # group rows: coloured bold text; item rows: soft tint by safety level
        tags = ("group", "head-" + level) if group and level else ("group",) if group else (level,) if level else ()
        iid = tree.insert(parent, "end", text=text, values=values, tags=tags, open=open_)
        if path:
            self.paths[(tree, iid)] = path
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
        for t in (self.junk, self.apps, self.left, self.map, self.big):
            t.delete(*t.get_children())
        self.rules.clear(), self.level.clear(), self.paths.clear()
        for v in self.card_val.values():
            v.configure(text="…")
        self.busy(True)
        self.status.config(text="Scanning junk and app caches...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
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
            rows.append((SAFE, "App caches", app, f"{len(rs)} cache folder(s); app rebuilds them",
                         rs, sum(sizes), sizes))
        bin_size = recycle_bin_size()
        rows.append((CAUTION, "System", "Recycle Bin", "Files you deleted - can't be restored after this",
                     ["RECYCLE"], bin_size, [bin_size]))
        self.q.put(("junk", rows))

        self.q.put(("say", "Reading installed apps from the registry..."))
        inst = installed_apps() + store_apps()
        self.q.put(("apps", inst))
        self.q.put(("say", "Looking for leftovers of uninstalled apps..."))
        self.q.put(("left", find_leftovers(inst, skip_paths=known)))

        drives = fixed_drives()
        for d in drives:
            self.q.put(("say", f"Mapping drive {d} (big drives take a minute)..."))
            self.q.put(("map", (f"Drive {d}", d, list_dir(d))))
        self.q.put(("map", (f"Your folder ({HOME})", HOME, list_dir(HOME))))
        self.q.put(("say", "Finding large files..."))
        self.q.put(("big", big_files([HOME] + [d for d in drives if norm(d) != norm(SYSDRIVE + "\\")])))
        self.q.put(("say", f"Scan done. Safe to delete: {fmt(self.totals[SAFE])}   Caution: {fmt(self.totals[CAUTION])}. "
                           "Double-click any row to open it."))

    def poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                getattr(self, "show_" + kind)(data)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def show_say(self, text):
        self.status.config(text=text)
        if text.startswith("Scan done"):
            self.busy(False)

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
            iid = self._add(self.junk, groups[(level, cat)], label, level=level, path=folder,
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
            self._add(self.left, g, name, level=CAUTION, path=path,
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

    def show_cleaned(self, msg):
        self.update_disk()
        messagebox.showinfo("Done", msg)
        self.scan()

    # ----- actions -----
    def current(self):
        return [self.junk, self.apps, self.left, self.map, self.big][self.nb.index(self.nb.select())]

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

    def select_safe(self):
        self.nb.select(0)
        self.junk.selection_set([i for i, lvl in self.level.items() if lvl == SAFE])

    def clean(self):
        t = self.current()
        if t is self.left:
            return self.recycle_leftovers()
        if t is not self.junk:
            return messagebox.showinfo("Review only", "This tab is for review: double-click to open in Explorer.\n"
                                       "Cleaning works in the 'Junk & caches' and 'Leftovers' tabs.\n"
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
        self.status.config(text="Cleaning...")
        threading.Thread(target=lambda: self.q.put(("cleaned", "Freed {}.\nFiles in use or too new were skipped.".format(fmt(sum(
            empty_recycle_bin() if r == "RECYCLE" else process(r, delete=True) for r in jobs))))), daemon=True).start()

    def recycle_leftovers(self):
        sel = [i for i in self.left.selection() if (self.left, i) in self.paths]
        if not sel:
            return messagebox.showwarning("Nothing selected", "Select leftover folders first.")
        names = "\n".join(f"- {self.left.item(i, 'text')}  ({self.left.item(i, 'values')[1]})" for i in sel[:20])
        if not messagebox.askyesno("Move to Recycle Bin", f"Move these folders to the Recycle Bin?\n\n{names}\n\n"
                                   "You can restore them from the Recycle Bin if an app needed them.", icon="warning"):
            return
        paths = [self.paths[(self.left, i)] for i in sel]
        threading.Thread(target=lambda: self.q.put(("cleaned", "Moved {} of {} folders to the Recycle Bin.\n"
                                                    "Folders in use or needing admin rights were skipped.".format(
            sum(recycle(p) for p in paths), len(paths)))), daemon=True).start()


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

        # recycle bin move works and is refused for protected roots
        assert recycle(j("MyApp")) and not os.path.exists(j("MyApp"))
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


if __name__ == "__main__":
    if "--test" in sys.argv:
        selftest()
    else:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on high-DPI screens
        except Exception:
            pass
        App().mainloop()
