# Storage Cleaner

A free, open-source Windows desktop app that shows **what is filling your drives** and **what is actually safe to delete** — junk files, app caches, leftovers from uninstalled apps, and large files — with a modern Windows 11 look (dark & light themes).

It never guesses silently: every item is labelled with a safety level and a plain-English note.

| Level | Meaning | Examples |
|---|---|---|
| 🟢 **Safe** | Rebuildable data — apps recreate it automatically | Browser / Electron app caches, temp files, logs, crash dumps, thumbnail cache |
| 🟡 **Caution** | Deletable, but you lose something (the note says what) | Recycle Bin, Downloads, npm/pip/uv caches, Windows Update downloads, leftover folders |
| 🔴 **Protected** | System or personal data — shown so you know what it is, **never deleted** | Windows, Program Files, pagefile.sys, hiberfil.sys, Documents, your photos |

## Features

- **🧹 Junk & caches** — Uses **Windows' own Disk Cleanup rules** (read live from the registry: folder, file pattern, minimum file age), plus automatic detection of app caches (Chrome, Edge, Discord, Spotify, VS Code, JetBrains IDEs, Store apps…) grouped per app, plus developer caches (npm, pip, uv, yarn, pnpm, NuGet, Gradle, Go).
- **📦 Installed apps** — Every installed desktop and Microsoft Store app from the registry, with size, version, publisher and install folder. Flags **broken registry entries** (app files gone, entry left behind).
- **👻 Leftovers** — Folders in AppData / ProgramData / Program Files that match **no installed app** and haven't been used for 30+ days — usually left behind by uninstalled apps. Removed to the **Recycle Bin**, so it's undoable.
- **🗺 Drive map** — All fixed drives (C:, D:, …) and your user folder, biggest folders first, each explained ("Virtual memory", "Hibernation file", "Your personal files"…). Expand any folder to drill down.
- **📁 Large files** — Files over 200 MB in your user folder and other drives.
- **Double-click any row** to open that exact file or folder in Explorer.
- Shortcuts to Windows **Disk Cleanup**, **Apps & features** and **Storage settings** for what only Windows can safely remove (old updates, previous Windows installs).

## Download & run

**Easiest:** download `StorageCleaner.exe` from the [Releases](../../releases) page and double-click it. No install, no Python needed.

> Windows SmartScreen may warn because the exe isn't code-signed: click **More info → Run anyway**.
> Right-click → **Run as administrator** to also clean Windows-level temp and update files.

**From source** (Python 3.12+ on Windows):

```bash
pip install -r requirements.txt
python cleaner.py
```

Run the built-in self-check:

```bash
python cleaner.py --test
```

Build your own exe:

```bash
pip install pyinstaller
python -m PyInstaller --onefile --windowed --name StorageCleaner --collect-data sv_ttk cleaner.py
```

## How it stays safe

- Only deletes what a rule points at; never "everything in AppData".
- Hard guard: refuses to wipe Windows, System32, Program Files, your user folder, Documents, Desktop, etc., even if a rule asks.
- Never follows symlinks / junctions (a link inside a cache can't lead the cleaner elsewhere).
- Respects Windows' minimum-age rules (e.g. temp files only after 7 days); files in use are skipped.
- Leftovers go to the Recycle Bin, not permanent deletion. Store apps' `LocalCache` (real data for some apps) is never treated as cache.
- **The registry is read, never modified.** "Registry cleaners" free almost no space and are a common way to break Windows.
- Shows a confirmation listing every item — and every Caution note — before deleting.

Leftover detection matches folder names against installed app names, so it's a best guess: it leans towards *not* flagging a folder. Always glance at a leftover (double-click it) before recycling.

## Credits

Cleaning rules informed by [BleachBit](https://www.bleachbit.org/), the community [Winapp2](https://github.com/MoscaDotTo/Winapp2) database, and Windows' built-in Disk Cleanup handlers. Theme: [Sun Valley ttk theme (sv-ttk)](https://github.com/rdbende/Sun-Valley-ttk-theme).

## License

[MIT](LICENSE) — free to use, modify and share. Provided as-is, without warranty: review what you delete.
