import sys as _sys
if _sys.stdout is None or _sys.stderr is None:
    # Started with pythonw (no console): send print/progress output to a log file
    # instead of crashing on writes to a missing stdout/stderr.
    try:
        _console_log = open(__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), 'AV1_reencoder_console.log'), 'w', encoding='utf-8', buffering=1)
    except OSError:
        _console_log = open(__import__('os').devnull, 'w')
    _sys.stdout = _sys.stdout or _console_log
    _sys.stderr = _sys.stderr or _console_log
import os
import shutil
import subprocess
import threading
import queue
import time
import json
import ctypes
from ctypes import wintypes
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import psutil
except Exception:
    psutil = None

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
except Exception:
    TkinterDnD = None
    DND_FILES = None

APP_TITLE = "AV1_reencoder v18 — 動画 再エンコード・安全置換ツール"
VIDEO_EXTS = {".mp4", ".m4v", ".mkv"}

CODEC_PRESETS = {
    "x265 (HEVC)": {
        "アニメ": {"crf": "22", "preset": "slow",   "tune": "animation", "tenbit": True},
        "実写":   {"crf": "24", "preset": "medium", "tune": "",          "tenbit": True},
    },
    "AV1 (SVT-AV1)": {
        # x265側と同程度の見た目を狙う初期値。
        # CRF値は規格/エンコーダー間で直接対応しないため、完全な等価ではありません。
        "アニメ": {"crf": "28", "preset": "6", "tune": "", "tenbit": True},
        "実写":   {"crf": "30", "preset": "7", "tune": "", "tenbit": True},
    },
}

X265_PRESET_VALUES = [
    "ultrafast","superfast","veryfast","faster","fast",
    "medium","slow","slower","veryslow"
]
SVTAV1_PRESET_VALUES = [str(i) for i in range(14)]

DEFAULT_WAIT_PROCESSES = "AmatsukazeCLI.exe;x265.exe;SvtAv1EncApp.exe;SvtAv1EncApp64.exe;NVEncC64.exe;NVEncC.exe;QSVEncC64.exe;QSVEncC.exe;VCEEncC64.exe;VCEEncC.exe"

def human_size(n):
    try:
        n = float(n)
    except Exception:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units)-1:
        n /= 1024
        i += 1
    return f"{n:.2f} {units[i]}"

def human_elapsed(seconds):
    if seconds is None:
        return "-"
    try:
        total = max(0, int(round(float(seconds))))
    except Exception:
        return "-"
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def safe_unlink(p: Path):
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]

def win_process_tree(root_pid):
    """子→親の順でプロセスツリーのPIDを返す。"""
    if os.name != "nt":
        return [int(root_pid)]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snap == invalid_handle:
        return [int(root_pid)]

    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    parent_map = {}
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            parent_map.setdefault(int(pe.th32ParentProcessID), []).append(int(pe.th32ProcessID))
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)

    result = []
    seen = set()
    def walk(pid):
        if pid in seen:
            return
        seen.add(pid)
        for child in parent_map.get(pid, []):
            walk(child)
        result.append(pid)
    walk(int(root_pid))
    return result


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]

def win_process_snapshot():
    """[{pid, ppid, name}] を返す。"""
    if os.name != "nt":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snap == invalid_handle:
        return []

    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    result = []
    try:
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            result.append({
                "pid": int(pe.th32ProcessID),
                "ppid": int(pe.th32ParentProcessID),
                "name": str(pe.szExeFile).lower(),
            })
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    return result

def _filetime_to_int(ft):
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)

def win_process_activity_counters(pid):
    """(cpu_100ns, io_bytes) を返す。取得不能なら None。"""
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    try:
        creation = wintypes.FILETIME()
        exit_ft = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_ft),
            ctypes.byref(kernel),
            ctypes.byref(user)
        ):
            return None

        io = IO_COUNTERS()
        io_bytes = 0
        if kernel32.GetProcessIoCounters(handle, ctypes.byref(io)):
            io_bytes = (
                int(io.ReadTransferCount)
                + int(io.WriteTransferCount)
                + int(io.OtherTransferCount)
            )

        cpu = _filetime_to_int(kernel) + _filetime_to_int(user)
        return cpu, io_bytes
    finally:
        kernel32.CloseHandle(handle)

def win_suspend_pid(pid):
    if os.name != "nt":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return False
    try:
        return ntdll.NtSuspendProcess(handle) == 0
    finally:
        kernel32.CloseHandle(handle)

def win_resume_pid(pid):
    if os.name != "nt":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    handle = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return False
    try:
        return ntdll.NtResumeProcess(handle) == 0
    finally:
        kernel32.CloseHandle(handle)


def app_state_dir():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        base = str(Path.home())
    d = Path(base) / "MP4_x265_Reencoder"
    d.mkdir(parents=True, exist_ok=True)
    return d

STATE_FILE = app_state_dir() / "session_v16.json"
LEGACY_STATE_FILES = [
    app_state_dir() / "session_v15.json",
    app_state_dir() / "session_v14.json",
    app_state_dir() / "session_v13.json",
    app_state_dir() / "session_v12.json",
    app_state_dir() / "session_v10.json",
    app_state_dir() / "session_v9.json",
]
PROCESSED_PATHS_FILE = app_state_dir() / "processed_paths.txt"

def file_signature(path):
    try:
        st = Path(path).stat()
        return {"size": int(st.st_size), "mtime_ns": int(st.st_mtime_ns)}
    except OSError:
        return None


class App:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1280x900")
        self.root.minsize(1040, 720)

        self.items = {}
        self.running = False
        self.stop_requested = False
        self.pause_requested = False
        self.proc = None
        self.suspended_pids = []
        self.resume_waiting = False
        self.auto_pause_active = False
        self.auto_pause_thread = None
        self.process_activity_cache = {}
        self.current_settings = None
        self.current_encode_started = None
        self.current_encode_pause_started = None
        self.current_encode_pause_accum = 0.0
        self.current_encode_item = None
        self.q = queue.Queue()
        self.history = {}
        self.processed_paths = {}
        self.state_loading = False
        self.sort_column = None
        self.sort_reverse = False

        self.ffmpeg_var = tk.StringVar(value=shutil.which("ffmpeg") or "")
        self.codec_var = tk.StringVar(value="x265 (HEVC)")
        self.profile_var = tk.StringVar(value="アニメ")
        self.crf_var = tk.StringVar(value="22")
        self.preset_var = tk.StringVar(value="slow")
        self.tune_var = tk.StringVar(value="animation")
        self.tenbit_var = tk.BooleanVar(value=True)

        self.replace_var = tk.BooleanVar(value=True)
        self.backup_var = tk.BooleanVar(value=False)
        self.recursive_var = tk.BooleanVar(value=True)

        self.wait_amatsukaze_var = tk.BooleanVar(value=True)
        self.auto_pause_amatsukaze_var = tk.BooleanVar(value=True)
        self.wait_processes_var = tk.StringVar(value=DEFAULT_WAIT_PROCESSES)
        self.wait_stable_seconds_var = tk.StringVar(value="5")
        self.wait_poll_seconds_var = tk.StringVar(value="5")

        self.free_space_multiplier_var = tk.StringVar(value="1.10")

        self.status_var = tk.StringVar(value="待機中")
        self.current_var = tk.StringVar(value="")
        self.detail_var = tk.StringVar(value="")
        self.current_progress_var = tk.DoubleVar(value=0)
        self.overall_progress_var = tk.DoubleVar(value=0)

        self.build_ui()
        self.setup_dnd()
        self.load_processed_paths()
        self.load_state()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(150, self.poll_queue)

    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        box = ttk.LabelFrame(main, text="FFmpeg")
        box.pack(fill="x", pady=(0,8))
        box.columnconfigure(1, weight=1)
        ttk.Label(box, text="ffmpeg.exe").grid(row=0,column=0,padx=6,pady=6)
        ttk.Entry(box, textvariable=self.ffmpeg_var).grid(row=0,column=1,padx=6,pady=6,sticky="ew")
        ttk.Button(box, text="参照", command=self.select_ffmpeg).grid(row=0,column=2,padx=6,pady=6)
        ttk.Button(box, text="動作確認", command=self.check_ffmpeg).grid(row=0,column=3,padx=6,pady=6)
        ttk.Label(
            box,
            text="※ここに表示されている ffmpeg.exe を実際に使用します。AV1には libsvtav1 対応FFmpegが必要です。"
        ).grid(row=1,column=0,columnspan=4,padx=6,pady=(0,6),sticky="w")

        box = ttk.LabelFrame(main, text="入力")
        box.pack(fill="x", pady=(0,8))
        ttk.Button(box, text="ファイルを追加", command=self.add_files_dialog).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="フォルダを追加", command=self.add_folder_dialog).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="選択行を削除", command=self.remove_selected).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="選択を未処理に戻す", command=self.reset_selected_history).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="選択を処理済みに登録", command=self.mark_selected_processed).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="処理済みTXT取込", command=self.import_processed_txt).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="選択行に現在設定を適用", command=self.apply_current_settings_to_selected).pack(side="left", padx=6, pady=6)
        ttk.Button(box, text="↑ 上へ", command=lambda: self.move_selected(-1)).pack(side="left", padx=3, pady=6)
        ttk.Button(box, text="↓ 下へ", command=lambda: self.move_selected(1)).pack(side="left", padx=3, pady=6)
        ttk.Button(box, text="一覧をクリア", command=self.clear_items).pack(side="left", padx=6, pady=6)
        ttk.Checkbutton(box, text="サブフォルダも検索", variable=self.recursive_var).pack(side="left", padx=12)
        ttk.Label(box, text="複数選択・ファイル/フォルダD&D対応").pack(side="right", padx=8)

        frm = ttk.Frame(main)
        frm.pack(fill="both", expand=True, pady=(0,8))
        cols = ("status","codec","profile","name","before","after","saved","path","elapsed")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", selectmode="extended")
        heads = {
            "status":"状態","codec":"コーデック","profile":"プリセット",
            "name":"ファイル名","before":"元サイズ","after":"変換後","saved":"削減",
            "path":"パス","elapsed":"エンコード時間"
        }
        widths = {
            "status":115,"codec":90,"profile":165,"name":255,
            "before":90,"after":90,"saved":90,"path":390,"elapsed":105
        }
        self.tree_headings = heads.copy()
        for c in cols:
            self.tree.heading(c, text=heads[c], command=lambda col=c: self.sort_tree(col))
            self.tree.column(c, width=widths[c], anchor="e" if c in {"before","after","saved"} else "w")
        self.tree.column("status", anchor="center")
        self.tree.column("codec", anchor="center")
        self.tree.column("profile", anchor="center")
        self.tree.column("elapsed", anchor="center")
        self.tree["displaycolumns"] = ("status","codec","profile","name","before","after","saved","elapsed","path")
        ys = ttk.Scrollbar(frm, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(frm, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0,column=0,sticky="nsew")
        ys.grid(row=0,column=1,sticky="ns")
        xs.grid(row=1,column=0,sticky="ew")
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)

        box = ttk.LabelFrame(main, text="映像エンコード設定")
        box.pack(fill="x", pady=(0,8))

        ttk.Label(box, text="コーデック").grid(row=0,column=0,padx=(8,4),pady=6)
        self.codec_combo = ttk.Combobox(
            box,
            textvariable=self.codec_var,
            values=["x265 (HEVC)", "AV1 (SVT-AV1)"],
            state="readonly",
            width=15
        )
        self.codec_combo.grid(row=0,column=1,padx=(0,14))
        self.codec_combo.bind("<<ComboboxSelected>>", self.on_codec_changed)

        ttk.Label(box, text="プリセット").grid(row=0,column=2,padx=(4,4),pady=6)
        combo = ttk.Combobox(
            box,
            textvariable=self.profile_var,
            values=["アニメ","実写","カスタム"],
            state="readonly",
            width=10
        )
        combo.grid(row=0,column=3,padx=(0,14))
        combo.bind("<<ComboboxSelected>>", self.on_profile_changed)

        ttk.Label(box, text="CRF").grid(row=0,column=4,padx=4)
        ttk.Entry(box, textvariable=self.crf_var, width=6).grid(row=0,column=5,padx=(0,12))

        ttk.Label(box, text="Encoder Preset").grid(row=0,column=6,padx=4)
        self.encoder_preset_combo = ttk.Combobox(
            box,
            textvariable=self.preset_var,
            values=X265_PRESET_VALUES,
            state="readonly",
            width=10
        )
        self.encoder_preset_combo.grid(row=0,column=7,padx=(0,12))

        ttk.Label(box, text="Tune").grid(row=0,column=8,padx=4)
        self.tune_combo = ttk.Combobox(
            box,
            textvariable=self.tune_var,
            values=["","animation","film","grain","fastdecode","zerolatency"],
            state="readonly",
            width=10
        )
        self.tune_combo.grid(row=0,column=9,padx=(0,12))

        ttk.Checkbutton(box, text="10bit", variable=self.tenbit_var).grid(row=0,column=10,padx=8)
        ttk.Checkbutton(box, text="成功時に元ファイルへ置換", variable=self.replace_var).grid(row=0,column=11,padx=8)
        ttk.Checkbutton(box, text="置換前に .bak を残す", variable=self.backup_var).grid(row=0,column=12,padx=8)

        self.codec_help_var = tk.StringVar(
            value="x265 アニメ: 10bit / slow / tune animation / CRF22　　実写: 10bit / medium / CRF24"
        )
        ttk.Label(box, textvariable=self.codec_help_var)\
            .grid(row=1,column=0,columnspan=13,padx=8,pady=(0,6),sticky="w")

        box = ttk.LabelFrame(main, text="Amatsukaze待機")
        box.pack(fill="x", pady=(0,8))
        ttk.Checkbutton(box, text="各ファイル開始前にAmatsukazeのエンコード状態を確認", variable=self.wait_amatsukaze_var)\
            .grid(row=0,column=0,columnspan=7,padx=8,pady=(6,2),sticky="w")

        ttk.Checkbutton(
            box,
            text="再エンコード中にAmatsukazeが始まったら自動一時停止 → 終了後に自動再開",
            variable=self.auto_pause_amatsukaze_var
        ).grid(row=1,column=0,columnspan=7,padx=8,pady=(0,6),sticky="w")

        ttk.Label(box, text="監視プロセス").grid(row=2,column=0,padx=(8,4),pady=(0,6),sticky="w")
        ttk.Entry(box, textvariable=self.wait_processes_var).grid(row=2,column=1,columnspan=3,padx=(0,8),pady=(0,6),sticky="ew")
        box.columnconfigure(1,weight=1)

        ttk.Label(box, text="確認間隔").grid(row=2,column=4,padx=(8,4),pady=(0,6))
        ttk.Entry(box, textvariable=self.wait_poll_seconds_var, width=5).grid(row=2,column=5,padx=(0,2),pady=(0,6))
        ttk.Label(box, text="秒").grid(row=2,column=6,padx=(0,8),pady=(0,6))

        ttk.Label(box, text="連続不在時間").grid(row=3,column=4,padx=(8,4),pady=(0,6))
        ttk.Entry(box, textvariable=self.wait_stable_seconds_var, width=5).grid(row=3,column=5,padx=(0,2),pady=(0,6))
        ttk.Label(box, text="秒").grid(row=3,column=6,padx=(0,8),pady=(0,6))

        ttk.Label(
            box,
            text="AmatsukazeCLI.exe は常駐していても、CPU/I/O活動または子プロセスがある時だけ『処理中』と判定します。"
        ).grid(row=3,column=0,columnspan=4,padx=8,pady=(0,6),sticky="w")

        box = ttk.LabelFrame(main, text="空き容量チェック")
        box.pack(fill="x", pady=(0,8))
        ttk.Label(box, text="開始前に必要空き容量を確認：元ファイルサイズ ×").pack(side="left", padx=(8,4), pady=6)
        ttk.Entry(box, textvariable=self.free_space_multiplier_var, width=6).pack(side="left", pady=6)
        ttk.Label(box, text="（既定 1.10。不足時はそのファイルを開始せず停止）").pack(side="left", padx=8)

        box = ttk.LabelFrame(main, text="進捗")
        box.pack(fill="x", pady=(0,8))
        ttk.Label(box, textvariable=self.current_var).pack(fill="x", padx=8, pady=(6,2))
        ttk.Label(box, textvariable=self.detail_var).pack(fill="x", padx=8, pady=(0,2))
        ttk.Progressbar(box, variable=self.current_progress_var, maximum=100).pack(fill="x", padx=8, pady=2)
        ttk.Progressbar(box, variable=self.overall_progress_var, maximum=100).pack(fill="x", padx=8, pady=(2,6))

        bottom = ttk.Frame(main)
        bottom.pack(fill="x")
        self.start_btn = ttk.Button(bottom, text="開始", command=self.start)
        self.start_btn.pack(side="left", padx=(0,6))
        self.pause_btn = ttk.Button(bottom, text="一時停止", command=self.toggle_pause, state="disabled")
        self.pause_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(bottom, text="停止", command=self.request_stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left", padx=12)

    def path_key(self, path):
        try:
            return os.path.normcase(os.path.abspath(os.path.normpath(str(path))))
        except Exception:
            return str(path).lower()

    def load_processed_paths(self):
        self.processed_paths = {}
        if not PROCESSED_PATHS_FILE.exists():
            return
        try:
            for raw in PROCESSED_PATHS_FILE.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                s = raw.strip()
                if not s or s.startswith("#"):
                    continue
                key = self.path_key(s)
                self.processed_paths[key] = s
        except Exception:
            self.processed_paths = {}

    def save_processed_paths(self):
        try:
            PROCESSED_PATHS_FILE.parent.mkdir(parents=True, exist_ok=True)
            lines = [
                "# 動画 再エンコードツール 処理済みパス一覧",
                "# 1行1ファイル。手動編集可能です。",
                "# このTXTにあるパスは、ファイル内容が変わっていても処理済みとして扱います。",
                "",
            ]
            values = sorted(self.processed_paths.values(), key=lambda x: x.lower())
            lines.extend(values)
            tmp = PROCESSED_PATHS_FILE.with_suffix(".tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            os.replace(tmp, PROCESSED_PATHS_FILE)
        except Exception:
            pass

    def is_path_processed(self, path):
        return self.path_key(path) in self.processed_paths

    def add_processed_path(self, path):
        p = str(Path(path))
        self.processed_paths[self.path_key(p)] = p
        self.save_processed_paths()

    def remove_processed_path(self, path):
        self.processed_paths.pop(self.path_key(path), None)
        self.save_processed_paths()

    def apply_processed_status_to_loaded_items(self):
        changed = 0
        for key, item in self.items.items():
            p = item["path"]
            if not self.is_path_processed(p):
                continue
            item["done"] = True
            if item.get("status") not in ("完了", "縮小せず", "完了済み"):
                item["status"] = "完了済み(登録)"
            vals = list(self.tree.item(item["iid"], "values"))
            vals[0] = item["status"]
            self.tree.item(item["iid"], values=vals)
            changed += 1
        self.save_state()
        return changed

    def mark_selected_processed(self):
        if self.running:
            return
        selected = self.tree.selection()
        if not selected:
            return
        count = 0
        for iid in selected:
            vals = self.tree.item(iid, "values")
            if len(vals) < 8:
                continue
            p = Path(vals[7])
            key = self.path_key(p)
            self.processed_paths[key] = str(p)
            item = self.items.get(key)
            if item is None:
                # itemsのキーが旧方式(lower)の場合にも対応
                item = self.items.get(str(p).lower())
            if item:
                item["done"] = True
                item["status"] = "完了済み(登録)"
                vals = list(vals)
                vals[0] = "完了済み(登録)"
                self.tree.item(iid, values=vals)
            count += 1
        self.save_processed_paths()
        self.save_state()
        if count:
            self.status_var.set(f"{count}件を処理済みとして登録しました")

    def import_processed_txt(self):
        if self.running:
            return
        path = filedialog.askopenfilename(
            title="処理済みパスTXTを選択",
            filetypes=[("テキストファイル", "*.txt"), ("すべて", "*.*")]
        )
        if not path:
            return
        added = 0
        try:
            for raw in Path(path).read_text(encoding="utf-8-sig", errors="replace").splitlines():
                s = raw.strip().strip('"')
                if not s or s.startswith("#"):
                    continue
                key = self.path_key(s)
                if key not in self.processed_paths:
                    added += 1
                self.processed_paths[key] = s
            self.save_processed_paths()
            updated = self.apply_processed_status_to_loaded_items()
            self.status_var.set(f"処理済みTXTを取り込みました: 新規 {added}件 / 一覧反映 {updated}件")
        except Exception as e:
            messagebox.showerror("処理済みTXT取込", str(e))

    def save_state(self):
        if self.state_loading:
            return
        self.save_processed_paths()
        try:
            items = []
            for iid in self.tree.get_children():
                vals = self.tree.item(iid, "values")
                if len(vals) < 8:
                    continue
                p = str(vals[7])
                key = self.path_key(p)
                item = self.items.get(key)
                if not item:
                    continue
                items.append({
                    "path": p,
                    "status": item.get("status", str(vals[0])),
                    "orig_size": int(item.get("orig_size", 0) or 0),
                    "after_size": item.get("after_size"),
                    "saved_size": item.get("saved_size"),
                    "done": bool(item.get("done", False)),
                    "codec": item.get("codec", "x265 (HEVC)"),
                    "profile": item.get("profile", "アニメ"),
                    "enc_crf": item.get("enc_crf", "22"),
                    "enc_preset": item.get("enc_preset", "slow"),
                    "enc_tune": item.get("enc_tune", "animation"),
                    "enc_tenbit": bool(item.get("enc_tenbit", True)),
                    "elapsed_seconds": item.get("elapsed_seconds"),
                })

            settings = {
                "ffmpeg": self.ffmpeg_var.get(),
                "codec": self.codec_var.get(),
                "profile": self.profile_var.get(),
                "crf": self.crf_var.get(),
                "preset": self.preset_var.get(),
                "tune": self.tune_var.get(),
                "tenbit": bool(self.tenbit_var.get()),
                "replace": bool(self.replace_var.get()),
                "backup": bool(self.backup_var.get()),
                "recursive": bool(self.recursive_var.get()),
                "wait_amatsukaze": bool(self.wait_amatsukaze_var.get()),
                "auto_pause_amatsukaze": bool(self.auto_pause_amatsukaze_var.get()),
                "wait_processes": self.wait_processes_var.get(),
                "wait_stable_seconds": self.wait_stable_seconds_var.get(),
                "wait_poll_seconds": self.wait_poll_seconds_var.get(),
                "free_space_multiplier": self.free_space_multiplier_var.get(),
            }

            data = {
                "version": 3,
                "items": items,
                "history": self.history,
                "settings": settings,
            }

            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = STATE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(tmp, STATE_FILE)
        except Exception:
            pass

    def history_is_current(self, entry):
        if not entry:
            return False
        out = entry.get("output_path")
        if not out:
            return False
        sig = file_signature(out)
        if not sig:
            return False
        return (
            int(entry.get("output_size", -1)) == sig["size"]
            and int(entry.get("output_mtime_ns", -1)) == sig["mtime_ns"]
        )

    def register_history(self, item, status, orig_size, output_path, after_size, saved_size, elapsed_seconds=None):
        p = Path(item["path"])
        key = self.path_key(p)
        sig = file_signature(output_path)
        if not sig:
            return
        self.history[key] = {
            "source_path": str(p),
            "status": status,
            "before_size": int(orig_size),
            "after_size": int(after_size),
            "saved_size": int(saved_size),
            "output_path": str(output_path),
            "output_size": int(sig["size"]),
            "output_mtime_ns": int(sig["mtime_ns"]),
            "completed_at": int(time.time()),
            "codec": item.get("codec", "x265 (HEVC)"),
            "profile": item.get("profile", "アニメ"),
            "elapsed_seconds": float(elapsed_seconds) if elapsed_seconds is not None else item.get("elapsed_seconds"),
        }
        item["done"] = True
        item["status"] = status
        item["after_size"] = int(after_size)
        item["saved_size"] = int(saved_size)
        item["elapsed_seconds"] = float(elapsed_seconds) if elapsed_seconds is not None else item.get("elapsed_seconds")
        self.processed_paths[key] = str(p)
        self.save_processed_paths()

    def load_state(self):
        source_state = STATE_FILE if STATE_FILE.exists() else None
        if source_state is None:
            for candidate in LEGACY_STATE_FILES:
                if candidate.exists():
                    source_state = candidate
                    break
        if source_state is None:
            return
        self.state_loading = True
        try:
            data = json.loads(source_state.read_text(encoding="utf-8"))
            self.history = data.get("history") or {}

            s = data.get("settings") or {}
            if s.get("ffmpeg"):
                self.ffmpeg_var.set(s["ffmpeg"])
            if s.get("codec") in CODEC_PRESETS:
                self.codec_var.set(s["codec"])
                self.configure_codec_widgets(apply_profile=False)
            if s.get("profile"):
                self.profile_var.set(s["profile"])
            if s.get("crf") is not None:
                self.crf_var.set(str(s["crf"]))
            if s.get("preset"):
                self.preset_var.set(s["preset"])
            if s.get("tune") is not None:
                self.tune_var.set(s["tune"])
            if "tenbit" in s:
                self.tenbit_var.set(bool(s["tenbit"]))
            if "replace" in s:
                self.replace_var.set(bool(s["replace"]))
            if "backup" in s:
                self.backup_var.set(bool(s["backup"]))
            if "recursive" in s:
                self.recursive_var.set(bool(s["recursive"]))
            if "wait_amatsukaze" in s:
                self.wait_amatsukaze_var.set(bool(s["wait_amatsukaze"]))
            if "auto_pause_amatsukaze" in s:
                self.auto_pause_amatsukaze_var.set(bool(s["auto_pause_amatsukaze"]))
            if s.get("wait_processes"):
                self.wait_processes_var.set(s["wait_processes"])
            if s.get("wait_stable_seconds") is not None:
                self.wait_stable_seconds_var.set(str(s["wait_stable_seconds"]))
            if s.get("wait_poll_seconds") is not None:
                self.wait_poll_seconds_var.set(str(s["wait_poll_seconds"]))
            if s.get("free_space_multiplier") is not None:
                self.free_space_multiplier_var.set(str(s["free_space_multiplier"]))

            restored = 0
            completed = 0
            for rec in data.get("items") or []:
                p = Path(rec.get("path", ""))
                if not str(p):
                    continue
                key = self.path_key(p)
                if key in self.items:
                    continue

                hist = self.history.get(key)
                path_registered = self.is_path_processed(p)
                done = bool(path_registered or (hist and self.history_is_current(hist)))
                if done:
                    if hist and self.history_is_current(hist):
                        status = "完了済み" if hist.get("status") == "完了" else hist.get("status", "完了済み")
                        orig_size = int(hist.get("before_size", rec.get("orig_size", 0)) or 0)
                        after_size = int(hist.get("after_size", 0) or 0)
                        saved_size = int(hist.get("saved_size", 0) or 0)
                    else:
                        status = "完了済み(登録)"
                        try:
                            orig_size = p.stat().st_size
                        except OSError:
                            orig_size = int(rec.get("orig_size", 0) or 0)
                        after_size = None
                        saved_size = None
                    completed += 1
                else:
                    # PC再起動・強制終了時に「処理中」だったものも安全に未処理へ戻す
                    status = "待機"
                    try:
                        orig_size = p.stat().st_size
                    except OSError:
                        orig_size = int(rec.get("orig_size", 0) or 0)
                    after_size = None
                    saved_size = None
                    if hist and not path_registered and not self.history_is_current(hist):
                        self.history.pop(key, None)

                # 既存履歴にエンコード時間があれば復元する。
                if hist and hist.get("elapsed_seconds") is not None:
                    elapsed_seconds = float(hist.get("elapsed_seconds"))
                elif rec.get("elapsed_seconds") is not None:
                    elapsed_seconds = float(rec.get("elapsed_seconds"))
                else:
                    elapsed_seconds = None

                # v13以前の一覧は当時の全体設定を各キューへ引き継ぐ。
                item_codec = rec.get("codec") or s.get("codec") or "x265 (HEVC)"
                item_profile = rec.get("profile") or s.get("profile") or "アニメ"

                if rec.get("enc_crf") is not None:
                    enc_crf = str(rec.get("enc_crf"))
                    enc_preset = str(rec.get("enc_preset", "slow"))
                    enc_tune = str(rec.get("enc_tune", ""))
                    enc_tenbit = bool(rec.get("enc_tenbit", True))
                else:
                    preset_def = CODEC_PRESETS.get(item_codec, {}).get(item_profile)
                    if preset_def:
                        enc_crf = preset_def["crf"]
                        enc_preset = preset_def["preset"]
                        enc_tune = preset_def["tune"]
                        enc_tenbit = preset_def["tenbit"]
                    else:
                        enc_crf = str(s.get("crf", "22"))
                        enc_preset = str(s.get("preset", "slow"))
                        enc_tune = str(s.get("tune", ""))
                        enc_tenbit = bool(s.get("tenbit", True))

                iid = self.tree.insert(
                    "", "end",
                    values=(
                        status,
                        self.codec_short_name(item_codec),
                        self.queue_profile_label(item_profile, enc_preset, enc_crf),
                        p.name,
                        human_size(orig_size),
                        human_size(after_size) if after_size is not None else "-",
                        human_size(saved_size) if saved_size is not None else "-",
                        str(p),
                        human_elapsed(elapsed_seconds),
                    )
                )
                self.items[key] = {
                    "path": p,
                    "iid": iid,
                    "orig_size": orig_size,
                    "status": status,
                    "after_size": after_size,
                    "saved_size": saved_size,
                    "done": done,
                    "codec": item_codec,
                    "profile": item_profile,
                    "enc_crf": enc_crf,
                    "enc_preset": enc_preset,
                    "enc_tune": enc_tune,
                    "enc_tenbit": enc_tenbit,
                    "elapsed_seconds": elapsed_seconds,
                }
                restored += 1

            if restored:
                self.status_var.set(f"前回一覧を復元: {restored}件（処理済み {completed}件）")
                if restored:
                    self.overall_progress_var.set(completed / restored * 100)
        except Exception:
            self.history = {}
        finally:
            self.state_loading = False
            self.configure_codec_widgets(apply_profile=False)
            if not self.items and self.processed_paths:
                self.status_var.set(f"処理済み履歴を読込済み: {len(self.processed_paths)}件")

    def on_close(self):
        self.save_state()
        self.root.destroy()

    def reset_selected_history(self):
        if self.running:
            return
        count = 0
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if len(vals) < 8:
                continue
            p = Path(vals[7])
            key = self.path_key(p)
            item = self.items.get(key)
            self.history.pop(key, None)
            self.processed_paths.pop(self.path_key(p), None)
            if item:
                try:
                    size = p.stat().st_size
                except OSError:
                    size = item.get("orig_size", 0)
                item["orig_size"] = size
                item["done"] = False
                item["status"] = "待機"
                item["after_size"] = None
                item["saved_size"] = None
                item["elapsed_seconds"] = None
                self.tree.item(
                    iid,
                    values=(
                        "待機",
                        self.codec_short_name(item.get("codec", "x265 (HEVC)")),
                        self.queue_profile_label(
                            item.get("profile", "アニメ"),
                            item.get("enc_preset", "slow"),
                            item.get("enc_crf", "22")
                        ),
                        p.name,
                        human_size(size),
                        "-",
                        "-",
                        str(p),
                        "-"
                    )
                )
                count += 1
        self.save_processed_paths()
        self.save_state()
        if count:
            self.status_var.set(f"{count}件を未処理に戻しました")

    def configure_codec_widgets(self, apply_profile=True):
        codec = self.codec_var.get()

        if codec == "AV1 (SVT-AV1)":
            self.encoder_preset_combo.configure(values=SVTAV1_PRESET_VALUES)
            self.tune_var.set("")
            self.tune_combo.configure(values=[""], state="disabled")
            self.codec_help_var.set(
                "AV1目安（x265と同程度の見た目を狙う初期値）: "
                "アニメ 10bit / SVT preset 6 / CRF28　　実写 10bit / SVT preset 7 / CRF30"
            )
        else:
            self.encoder_preset_combo.configure(values=X265_PRESET_VALUES)
            self.tune_combo.configure(
                values=["","animation","film","grain","fastdecode","zerolatency"],
                state="readonly"
            )
            self.codec_help_var.set(
                "x265 アニメ: 10bit / slow / tune animation / CRF22　　"
                "実写: 10bit / medium / tuneなし / CRF24"
            )

        if apply_profile:
            self.apply_selected_profile()

    def apply_selected_profile(self):
        codec = self.codec_var.get()
        profile = self.profile_var.get()
        p = CODEC_PRESETS.get(codec, {}).get(profile)
        if p:
            self.crf_var.set(p["crf"])
            self.preset_var.set(p["preset"])
            self.tune_var.set(p["tune"])
            self.tenbit_var.set(p["tenbit"])

    def on_codec_changed(self, _=None):
        self.configure_codec_widgets(apply_profile=True)
        self.save_state()

    def on_profile_changed(self, _=None):
        self.apply_selected_profile()
        self.save_state()

    def current_encoding_assignment(self):
        return {
            "codec": self.codec_var.get(),
            "profile": self.profile_var.get(),
            "enc_crf": str(self.crf_var.get()),
            "enc_preset": str(self.preset_var.get()),
            "enc_tune": str(self.tune_var.get()),
            "enc_tenbit": bool(self.tenbit_var.get()),
        }

    def codec_short_name(self, codec):
        return "AV1" if codec == "AV1 (SVT-AV1)" else "x265"

    def queue_profile_label(self, profile, preset, crf):
        return f"{profile} ({preset}/CRF{crf})"

    def item_encoding_settings(self, item, base_st):
        codec = item.get("codec") or base_st.get("codec") or "x265 (HEVC)"
        profile = item.get("profile") or "アニメ"
        crf = str(item.get("enc_crf", base_st.get("crf", "22")))
        preset = str(item.get("enc_preset", base_st.get("preset", "slow")))
        tune = str(item.get("enc_tune", base_st.get("tune", "")))
        tenbit = bool(item.get("enc_tenbit", base_st.get("tenbit", True)))
        return {
            "codec": codec,
            "profile": profile,
            "video_encoder": "libsvtav1" if codec == "AV1 (SVT-AV1)" else "libx265",
            "crf": crf,
            "preset": preset,
            "tune": tune,
            "tenbit": tenbit,
        }

    def apply_current_settings_to_selected(self):
        # 実行中でも「一時停止中」に限り、まだ待機中のキューは変更可能。
        if self.running and not self.pause_requested:
            self.status_var.set("処理中の設定変更はできません。一時停止してから変更してください")
            return
        if self.resume_waiting:
            self.status_var.set("再開確認中は設定を変更できません")
            return

        selected = self.tree.selection()
        if not selected:
            return

        assign = self.current_encoding_assignment()

        # 一時停止中に新しいコーデックへ切り替える場合も、
        # 再開後に失敗しないよう、その場でFFmpeg対応状況を確認する。
        ff = (self.current_settings or {}).get("ffmpeg") or self.ffmpeg_var.get().strip()
        required_encoder = "libsvtav1" if assign["codec"] == "AV1 (SVT-AV1)" else "libx265"
        if ff and not self.ffmpeg_has_encoder(ff, required_encoder):
            messagebox.showerror(
                "FFmpeg エンコーダー不足",
                f"現在のFFmpeg:\n{ff}\n\n"
                f"{required_encoder} が見つからないため、選択キューへこの設定を適用できません。\n"
                "画面上部の「参照」で対応FFmpegを指定し、「動作確認」で確認してください。"
            )
            return

        changed = 0
        skipped_done = 0
        skipped_active = 0

        for iid in selected:
            vals = list(self.tree.item(iid, "values"))
            if len(vals) < 8:
                continue
            p = Path(vals[7])
            item = self.items.get(self.path_key(p))
            if not item:
                continue

            if item.get("done"):
                skipped_done += 1
                continue

            # 実行中は現在処理中/失敗等には触れず、「待機」だけ変更する。
            if self.running and item.get("status") != "待機":
                skipped_active += 1
                continue

            item.update(assign)
            vals[1] = self.codec_short_name(assign["codec"])
            vals[2] = self.queue_profile_label(assign["profile"], assign["enc_preset"], assign["enc_crf"])
            self.tree.item(iid, values=vals)
            changed += 1

        self.save_state()
        msg = f"{changed}件に現在の設定を適用しました"
        extras = []
        if skipped_done:
            extras.append(f"処理済み {skipped_done}件")
        if skipped_active:
            extras.append(f"待機以外 {skipped_active}件")
        if extras:
            msg += "（" + " / ".join(extras) + "は変更なし）"
        self.status_var.set(msg)

    def validate_pending_queue_encoders(self, ffmpeg):
        needed = set()
        for item in self.items.values():
            if item.get("done"):
                continue
            codec = item.get("codec", "x265 (HEVC)")
            needed.add("libsvtav1" if codec == "AV1 (SVT-AV1)" else "libx265")

        missing = [enc for enc in sorted(needed) if not self.ffmpeg_has_encoder(ffmpeg, enc)]
        if missing:
            missing_text = "\n".join(f"・{enc}" for enc in missing)
            messagebox.showerror(
                "FFmpeg エンコーダー不足",
                "現在このツールが参照しているFFmpeg:\\n"
                f"{ffmpeg}\\n\\n"
                "このFFmpegに次のエンコーダーが見つかりません:\\n"
                f"{missing_text}\\n\\n"
                "AV1を使う場合は libsvtav1 を含むFFmpegビルドを用意し、"
                "画面上部の「参照」からその ffmpeg.exe を指定してください。\\n\\n"
                "確認コマンド:\\n"
                'ffmpeg -hide_banner -encoders | findstr /i "libx265 libsvtav1"'
            )
            return False
        return True

    def item_from_iid(self, iid):
        vals = self.tree.item(iid, "values")
        if len(vals) < 8:
            return None
        return self.items.get(self.path_key(Path(vals[7])))

    def sort_value(self, iid, column):
        item = self.item_from_iid(iid)
        vals = self.tree.item(iid, "values")
        if not item:
            return ""

        if column == "before":
            return int(item.get("orig_size", 0) or 0)
        if column == "after":
            v = item.get("after_size")
            return -1 if v is None else int(v)
        if column == "saved":
            v = item.get("saved_size")
            return -1 if v is None else int(v)
        if column == "elapsed":
            v = item.get("elapsed_seconds")
            return -1.0 if v is None else float(v)
        if column == "status":
            return str(item.get("status", vals[0] if vals else "")).lower()
        if column == "codec":
            return self.codec_short_name(item.get("codec", "x265 (HEVC)")).lower()
        if column == "profile":
            return self.queue_profile_label(
                item.get("profile", "アニメ"),
                item.get("enc_preset", "slow"),
                item.get("enc_crf", "22")
            ).lower()
        if column == "name":
            return item["path"].name.lower()
        if column == "path":
            return str(item["path"]).lower()
        return str(vals[0]).lower() if vals else ""

    def update_sort_headings(self):
        for col, base in self.tree_headings.items():
            suffix = ""
            if col == self.sort_column:
                suffix = " ▼" if self.sort_reverse else " ▲"
            self.tree.heading(col, text=base + suffix, command=lambda c=col: self.sort_tree(c))

    def sort_tree(self, column):
        # 実行中はworkerが開始時の表示順を使うため、順序変更は停止中のみ。
        if self.running:
            self.status_var.set("一覧の並び替えは処理停止中に行ってください")
            return

        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False

        rows = list(self.tree.get_children())
        rows.sort(key=lambda iid: self.sort_value(iid, column), reverse=self.sort_reverse)
        for idx, iid in enumerate(rows):
            self.tree.move(iid, "", idx)

        self.update_sort_headings()
        self.save_state()
        order = "降順" if self.sort_reverse else "昇順"
        self.status_var.set(f"一覧を「{self.tree_headings.get(column, column)}」で{order}に並び替えました")

    def move_selected(self, direction):
        if self.running:
            self.status_var.set("一覧の並び替えは処理停止中に行ってください")
            return

        selected = list(self.tree.selection())
        if not selected:
            return

        children = list(self.tree.get_children())
        selected_set = set(selected)

        if direction < 0:
            for iid in children:
                if iid not in selected_set:
                    continue
                idx = self.tree.index(iid)
                if idx <= 0:
                    continue
                prev = children[idx - 1]
                if prev not in selected_set:
                    self.tree.move(iid, "", idx - 1)
                    children[idx - 1], children[idx] = children[idx], children[idx - 1]
        else:
            for iid in reversed(children):
                if iid not in selected_set:
                    continue
                idx = self.tree.index(iid)
                children_now = list(self.tree.get_children())
                if idx >= len(children_now) - 1:
                    continue
                nxt = children_now[idx + 1]
                if nxt not in selected_set:
                    self.tree.move(iid, "", idx + 1)

        self.sort_column = None
        self.sort_reverse = False
        self.update_sort_headings()
        self.save_state()
        self.status_var.set("選択行の順序を変更しました")

    def queue_keys_in_display_order(self):
        keys = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if len(vals) < 8:
                continue
            key = self.path_key(Path(vals[7]))
            if key in self.items:
                keys.append(key)
        return keys

    def setup_dnd(self):
        if TkinterDnD is None:
            return
        for w in (self.root, self.tree):
            try:
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", self.on_drop)
            except Exception:
                pass

    def on_drop(self, event):
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            paths = [event.data]
        self.add_paths(paths)

    def select_ffmpeg(self):
        p = filedialog.askopenfilename(title="ffmpeg.exe を選択",
                                       filetypes=[("ffmpeg.exe","ffmpeg.exe"),("実行ファイル","*.exe"),("すべて","*.*")])
        if p:
            self.ffmpeg_var.set(p)

    def check_ffmpeg(self):
        ff = self.ffmpeg_var.get().strip()
        if not ff:
            messagebox.showerror("FFmpeg","ffmpeg.exeを指定してください。")
            return
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            cp = subprocess.run(
                [ff, "-hide_banner", "-version"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=10, creationflags=creationflags
            )
            if cp.returncode != 0:
                messagebox.showerror("FFmpeg", cp.stderr or "起動に失敗しました。")
                return

            first = ((cp.stdout or "").splitlines() or ["FFmpeg"])[0]
            x265_ok = self.ffmpeg_has_encoder(ff, "libx265")
            av1_ok = self.ffmpeg_has_encoder(ff, "libsvtav1")

            messagebox.showinfo(
                "FFmpeg 動作確認",
                f"参照先:\\n{ff}\\n\\n"
                f"{first}\\n\\n"
                f"x265 (libx265): {'対応' if x265_ok else '未対応'}\\n"
                f"AV1 (libsvtav1): {'対応' if av1_ok else '未対応'}"
            )
        except Exception as e:
            messagebox.showerror("FFmpeg", f"参照先:\\n{ff}\\n\\n{e}")

    def add_files_dialog(self):
        self.add_paths(filedialog.askopenfilenames(title="MP4/M4V/MKVを選択",
                                                   filetypes=[("動画ファイル","*.mp4 *.m4v *.mkv"),("MP4 / M4V","*.mp4 *.m4v"),("MKV","*.mkv"),("すべて","*.*")]))

    def add_folder_dialog(self):
        p = filedialog.askdirectory(title="フォルダを選択")
        if p:
            self.add_paths([p])

    def add_paths(self, paths):
        added = 0
        for raw in paths:
            p = Path(raw)
            if p.is_dir():
                it = p.rglob("*") if self.recursive_var.get() else p.glob("*")
                for x in it:
                    if x.is_file() and x.suffix.lower() in VIDEO_EXTS:
                        added += self.add_file(x)
            elif p.is_file() and p.suffix.lower() in VIDEO_EXTS:
                added += self.add_file(p)
        self.status_var.set(f"{added}件追加 / 合計 {len(self.items)}件")
        self.save_state()

    def add_file(self, p):
        p = p.resolve()
        key = self.path_key(p)
        if key in self.items:
            return 0
        try:
            size = p.stat().st_size
        except OSError:
            return 0

        hist = self.history.get(key)
        path_registered = self.is_path_processed(p)
        done = bool(path_registered or (hist and self.history_is_current(hist)))
        if done:
            if hist and self.history_is_current(hist):
                status = "完了済み" if hist.get("status") == "完了" else hist.get("status", "完了済み")
                before = int(hist.get("before_size", size) or size)
                after_size = int(hist.get("after_size", size) or size)
                saved_size = int(hist.get("saved_size", 0) or 0)
                elapsed_seconds = float(hist.get("elapsed_seconds")) if hist.get("elapsed_seconds") is not None else None
            else:
                status = "完了済み(登録)"
                before = size
                after_size = None
                saved_size = None
                elapsed_seconds = None
        else:
            if hist and not path_registered:
                self.history.pop(key, None)
            status = "待機"
            before = size
            after_size = None
            saved_size = None
            elapsed_seconds = None

        assign = self.current_encoding_assignment()
        iid = self.tree.insert(
            "", "end",
            values=(
                status,
                self.codec_short_name(assign["codec"]),
                self.queue_profile_label(assign["profile"], assign["enc_preset"], assign["enc_crf"]),
                p.name,
                human_size(before),
                human_size(after_size) if after_size is not None else "-",
                human_size(saved_size) if saved_size is not None else "-",
                str(p),
                human_elapsed(elapsed_seconds)
            )
        )
        self.items[key] = {
            "path": p, "iid": iid, "orig_size": before,
            "status": status, "after_size": after_size,
            "saved_size": saved_size, "done": done,
            "elapsed_seconds": elapsed_seconds,
            **assign,
        }
        return 1

    def remove_selected(self):
        if self.running: return
        for iid in self.tree.selection():
            vals = self.tree.item(iid,"values")
            p = Path(vals[7])
            self.tree.delete(iid)
            self.items.pop(self.path_key(p.resolve()),None)
        self.save_state()

    def clear_items(self):
        if self.running: return
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.items.clear()
        self.status_var.set("一覧をクリアしました（処理済み履歴/TXTは保持）")
        self.save_state()

    def set_row(self,item,status=None,after=None,saved=None):
        vals = list(self.tree.item(item["iid"],"values"))
        if status is not None:
            vals[0] = status
            item["status"] = status
        if after is not None:
            vals[5] = after
        if saved is not None:
            vals[6] = saved
        self.tree.item(item["iid"],values=vals)
        self.save_state()

    def current_active_encode_elapsed(self):
        if self.current_encode_started is None:
            return 0.0
        elapsed = time.monotonic() - self.current_encode_started - self.current_encode_pause_accum
        if self.current_encode_pause_started is not None:
            elapsed -= time.monotonic() - self.current_encode_pause_started
        return max(0.0, elapsed)

    def set_elapsed(self, item, seconds):
        item["elapsed_seconds"] = float(seconds) if seconds is not None else None
        vals = list(self.tree.item(item["iid"], "values"))
        if len(vals) >= 9:
            vals[8] = human_elapsed(seconds)
            self.tree.item(item["iid"], values=vals)

    def get_ffprobe(self, ffmpeg):
        ff = Path(ffmpeg)
        cand = ff.with_name("ffprobe.exe" if os.name=="nt" else "ffprobe")
        if cand.exists(): return str(cand)
        return shutil.which("ffprobe") or ""

    def probe_duration(self, ffmpeg, video):
        fp = self.get_ffprobe(ffmpeg)
        if not fp: return None
        try:
            cp = subprocess.run([fp,"-v","error","-show_entries","format=duration",
                                 "-of","default=nw=1:nk=1",str(video)],
                                capture_output=True,text=True,timeout=15,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0)
            return float((cp.stdout or "").strip()) if cp.returncode==0 else None
        except Exception:
            return None

    def active_processes(self, names):
        """
        通常のエンコーダーは存在していれば処理中。
        AmatsukazeCLI.exe だけは常駐する場合があるため、
        子プロセス / CPU時間 / I/O転送量の変化がある時だけ処理中とみなす。
        """
        if not names:
            return []

        wanted = {n.lower() for n in names}
        cli_name = "amatsukazecli.exe"
        active = []
        process_rows = []

        if psutil is not None:
            try:
                for p in psutil.process_iter(["pid", "ppid", "name"]):
                    try:
                        name = (p.info.get("name") or "").lower()
                        if name not in wanted and name != cli_name:
                            continue
                        cpu_total = None
                        io_total = None
                        try:
                            ct = p.cpu_times()
                            cpu_total = float(ct.user + ct.system)
                        except Exception:
                            pass
                        try:
                            io = p.io_counters()
                            io_total = int(io.read_bytes + io.write_bytes + getattr(io, "other_bytes", 0))
                        except Exception:
                            pass
                        process_rows.append({
                            "pid": int(p.pid),
                            "ppid": int(p.ppid()),
                            "name": name,
                            "cpu": cpu_total,
                            "io": io_total,
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                process_rows = []

        if not process_rows and os.name == "nt":
            snap = win_process_snapshot()
            for row in snap:
                name = row["name"]
                if name not in wanted and name != cli_name:
                    continue
                counters = win_process_activity_counters(row["pid"])
                cpu_total = counters[0] if counters else None
                io_total = counters[1] if counters else None
                process_rows.append({
                    "pid": row["pid"],
                    "ppid": row["ppid"],
                    "name": name,
                    "cpu": cpu_total,
                    "io": io_total,
                })

        # 通常エンコーダー等は存在だけで「処理中」
        for row in process_rows:
            name = row["name"]
            if name in wanted and name != cli_name:
                active.append(name)

        cli_rows = [r for r in process_rows if r["name"] == cli_name and cli_name in wanted]
        if cli_rows:
            # CLI配下に別プロセスがいる場合は処理中と判断。
            ppid_set = {r["ppid"] for r in process_rows}
            child_busy = any(r["pid"] in ppid_set for r in cli_rows)

            cli_busy = child_busy
            now_seen = set()

            for row in cli_rows:
                pid = row["pid"]
                now_seen.add(pid)
                current_cpu = row["cpu"]
                current_io = row["io"]
                prev = self.process_activity_cache.get(pid)

                # 初回観測は安全側で1回だけ「処理中」とする。
                if prev is None:
                    cli_busy = True
                else:
                    prev_cpu, prev_io = prev
                    if current_cpu is not None and prev_cpu is not None:
                        # psutilは秒、WinAPIは100ns。どちらでも微小な変化を拾う。
                        cpu_delta = current_cpu - prev_cpu
                        cpu_threshold = 0.02 if isinstance(current_cpu, float) else 200000  # 0.02秒
                        if cpu_delta >= cpu_threshold:
                            cli_busy = True
                    if current_io is not None and prev_io is not None:
                        # 64KB以上のI/O変化で活動中と判定。
                        if current_io - prev_io >= 64 * 1024:
                            cli_busy = True

                self.process_activity_cache[pid] = (current_cpu, current_io)

            # 終了したPIDのキャッシュを掃除
            for pid in list(self.process_activity_cache):
                if pid not in now_seen:
                    self.process_activity_cache.pop(pid, None)

            if cli_busy:
                active.append(cli_name)

        return sorted(set(active))

    def wait_for_amatsukaze(self, st):
        if not st["wait_amatsukaze"]:
            return True

        idle_since = None
        while not self.stop_requested:
            active = self.active_processes(st["wait_processes"])
            if active:
                idle_since = None
                self.q.put(("status","Amatsukaze待機中: " + ", ".join(active)))
                self.q.put(("detail","Amatsukaze側のエンコード完了を待っています"))
            else:
                if idle_since is None:
                    idle_since = time.time()
                idle = time.time() - idle_since
                remain = max(0, st["stable_seconds"] - int(idle))
                if idle >= st["stable_seconds"]:
                    self.q.put(("status","Amatsukazeの停止を確認"))
                    self.q.put(("detail",""))
                    return True
                self.q.put(("status",f"Amatsukaze終了確認中: あと約 {remain} 秒"))

            slept = 0.0
            while slept < st["poll_seconds"]:
                if self.stop_requested:
                    return False
                time.sleep(0.5)
                slept += 0.5
        return False

    def ffmpeg_has_encoder(self, ffmpeg, encoder_name):
        try:
            creationflags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            cp = subprocess.run(
                [ffmpeg, "-hide_banner", "-encoders"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                creationflags=creationflags
            )
            hay = (cp.stdout or "") + "\n" + (cp.stderr or "")
            return encoder_name.lower() in hay.lower()
        except Exception:
            return False

    def validate_settings(self):
        ff = self.ffmpeg_var.get().strip()
        if not ff:
            messagebox.showerror("設定","ffmpeg.exeを指定してください。")
            return None

        codec = self.codec_var.get()
        if codec not in CODEC_PRESETS:
            messagebox.showerror("設定","映像コーデックを選択してください。")
            return None

        try:
            crf = int(self.crf_var.get())
            stable = int(self.wait_stable_seconds_var.get())
            poll = int(self.wait_poll_seconds_var.get())
            mult = float(self.free_space_multiplier_var.get())

            max_crf = 63 if codec == "AV1 (SVT-AV1)" else 51
            if not 0 <= crf <= max_crf or stable < 1 or poll < 1 or mult < 1.0:
                raise ValueError

            if codec == "AV1 (SVT-AV1)":
                enc_preset = int(self.preset_var.get())
                if not 0 <= enc_preset <= 13:
                    raise ValueError
        except ValueError:
            crf_range = "0～63" if codec == "AV1 (SVT-AV1)" else "0～51"
            messagebox.showerror(
                "設定",
                f"CRF（{crf_range}）/ Encoder Preset / 待機秒数 / 空き容量倍率の値を確認してください。"
            )
            return None

        encoder = "libsvtav1" if codec == "AV1 (SVT-AV1)" else "libx265"

        return {
            "ffmpeg":ff,
            "codec":codec,
            "video_encoder":encoder,
            "crf":crf,
            "preset":self.preset_var.get(),
            "tune":self.tune_var.get(),
            "tenbit":self.tenbit_var.get(),
            "replace":self.replace_var.get(),
            "backup":self.backup_var.get(),
            "wait_amatsukaze":self.wait_amatsukaze_var.get(),
            "auto_pause_amatsukaze":self.auto_pause_amatsukaze_var.get(),
            "wait_processes":[x.strip().lower() for x in self.wait_processes_var.get().split(";") if x.strip()],
            "stable_seconds":stable,
            "poll_seconds":poll,
            "free_mult":mult,
        }

    def start(self):
        if self.running: return
        if not self.items:
            messagebox.showinfo("対象なし","MP4/M4V/MKVファイルを追加してください。")
            return
        st = self.validate_settings()
        if not st: return
        if not self.validate_pending_queue_encoders(st["ffmpeg"]):
            return

        # 一覧の現在の表示順を、そのまま今回の処理順として固定する。
        st["queue_keys"] = self.queue_keys_in_display_order()

        if st["replace"]:
            pending = [x for x in self.items.values() if not x.get("done")]
            nx265 = sum(1 for x in pending if x.get("codec", "x265 (HEVC)") == "x265 (HEVC)")
            nav1 = sum(1 for x in pending if x.get("codec") == "AV1 (SVT-AV1)")
            text = f"未処理キュー: x265 {nx265}件 / AV1 {nav1}件\n"
            text += "成功したファイルは1本ごとに元ファイルへ置換します。\n"
            text += "バックアップ: " + ("残す (.bak)" if st["backup"] else "残さない") + "\n"
            text += "各ファイル開始前にAmatsukazeと空き容量を再確認します。\n"
            if st.get("auto_pause_amatsukaze"):
                text += "処理中にAmatsukazeが始まった場合は自動一時停止し、終了後に自動再開します。\n"
            text += "処理済みとして記録されているファイルは自動スキップします。\n\n開始しますか？"
            if not messagebox.askyesno("確認",text):
                return

        self.running = True
        self.stop_requested = False
        self.pause_requested = False
        self.suspended_pids = []
        self.resume_waiting = False
        self.auto_pause_active = False
        self.current_settings = st
        self.start_btn.configure(state="disabled")
        self.pause_btn.configure(state="normal", text="一時停止")
        self.stop_btn.configure(state="normal")
        self.current_progress_var.set(0)
        self.overall_progress_var.set(0)
        threading.Thread(target=self.worker,args=(st,),daemon=True).start()
        if st.get("wait_amatsukaze") and st.get("auto_pause_amatsukaze"):
            self.auto_pause_thread = threading.Thread(
                target=self.auto_pause_monitor, args=(st,), daemon=True
            )
            self.auto_pause_thread.start()

    def auto_pause_monitor(self, st):
        idle_since = None

        while self.running and not self.stop_requested:
            proc_running = self.proc is not None and self.proc.poll() is None

            if (
                proc_running
                and not self.auto_pause_active
                and not self.pause_requested
                and not self.resume_waiting
            ):
                active = self.active_processes(st["wait_processes"])
                if active:
                    if self.suspend_current_process_tree():
                        self.auto_pause_active = True
                        self.pause_requested = True
                        idle_since = None
                        self.q.put(("auto_pause_started", ", ".join(active)))

            if self.auto_pause_active:
                active = self.active_processes(st["wait_processes"])

                if active:
                    idle_since = None
                    self.q.put(("auto_pause_waiting", ", ".join(active)))
                else:
                    if idle_since is None:
                        idle_since = time.time()

                    elapsed = time.time() - idle_since
                    remain = max(0, st["stable_seconds"] - int(elapsed))
                    self.q.put(("auto_pause_clear_check", remain))

                    if elapsed >= st["stable_seconds"]:
                        if not self.stop_requested and self.auto_pause_active:
                            if self.suspended_pids:
                                self.resume_current_process_tree()
                            self.auto_pause_active = False
                            self.pause_requested = False
                            idle_since = None
                            self.q.put(("auto_pause_resumed",))
                        else:
                            break

            slept = 0.0
            poll = max(1, int(st.get("poll_seconds", 5)))
            while slept < poll and self.running and not self.stop_requested:
                time.sleep(0.5)
                slept += 0.5

    def suspend_current_process_tree(self):
        if not self.proc or self.proc.poll() is not None:
            return False

        root_pid = self.proc.pid
        suspended = []

        # このPython環境からpsutilを使える場合は優先する。
        if psutil is not None:
            try:
                parent = psutil.Process(root_pid)
                procs = parent.children(recursive=True)
                for p in procs:
                    try:
                        p.suspend()
                        suspended.append(p.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                try:
                    parent.suspend()
                    suspended.append(parent.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            except Exception:
                suspended = []

        # psutilが別Python環境に入っている場合でも動くようWindows APIへフォールバック。
        if not suspended and os.name == "nt":
            for pid in win_process_tree(root_pid):  # 子→親
                try:
                    if win_suspend_pid(pid):
                        suspended.append(pid)
                except Exception:
                    pass

        self.suspended_pids = suspended
        if suspended and self.current_encode_started is not None and self.current_encode_pause_started is None:
            self.current_encode_pause_started = time.monotonic()
        return bool(suspended)

    def resume_current_process_tree(self):
        # 親→子の順で再開。
        for pid in reversed(self.suspended_pids):
            resumed = False
            if psutil is not None:
                try:
                    psutil.Process(pid).resume()
                    resumed = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass
            if not resumed and os.name == "nt":
                try:
                    win_resume_pid(pid)
                except Exception:
                    pass
        self.suspended_pids = []
        if self.current_encode_pause_started is not None:
            self.current_encode_pause_accum += time.monotonic() - self.current_encode_pause_started
            self.current_encode_pause_started = None

    def toggle_pause(self):
        if not self.running or self.resume_waiting or self.auto_pause_active:
            return

        # 一時停止
        if not self.pause_requested:
            if self.proc and self.proc.poll() is None:
                if not self.suspend_current_process_tree():
                    extra = ""
                    if psutil is None:
                        extra = "\n\npsutilは現在このツールを起動しているPythonからは読み込めませんでしたが、Windows APIでも停止を試しました。"
                    messagebox.showerror("一時停止", "FFmpeg/エンコーダーのサスペンドに失敗しました。" + extra)
                    return

            self.pause_requested = True
            self.pause_btn.configure(text="再開")
            if self.suspended_pids:
                self.status_var.set("一時停止中：現在のFFmpeg/エンコーダーをその場で停止しています")
                self.detail_var.set("「再開」でAmatsukazeを確認後、同じ位置から続行します")
            else:
                self.status_var.set("一時停止中：次の処理開始前で待機しています")
                self.detail_var.set("「再開」でAmatsukazeを確認後、続行します")
            return

        # 再開：すぐresumeせず、Amatsukazeが止まっていることを確認してから再開する。
        self.resume_waiting = True
        self.pause_btn.configure(text="再開待ち…", state="disabled")
        self.status_var.set("再開前にAmatsukazeの状態を確認しています")
        threading.Thread(target=self.resume_after_amatsukaze_check, daemon=True).start()

    def resume_after_amatsukaze_check(self):
        st = self.current_settings
        ok = True
        if st is not None and st.get("wait_amatsukaze"):
            self.q.put(("status", "再開待ち：Amatsukazeの動作を確認中"))
            self.q.put(("detail", "Amatsukazeが処理中なら終了まで待ってから自動再開します"))
            ok = self.wait_for_amatsukaze(st)

        if ok and not self.stop_requested:
            if self.suspended_pids:
                self.resume_current_process_tree()
            self.pause_requested = False
            self.q.put(("pause_resume_done",))
        else:
            self.q.put(("pause_resume_aborted",))

    def wait_if_paused(self):
        while self.pause_requested and not self.stop_requested:
            if not self.suspended_pids:
                self.q.put(("status","一時停止中：次の処理開始前で待機しています"))
                self.q.put(("detail","「再開」を押すと続行します"))
            time.sleep(0.5)
        return not self.stop_requested

    def terminate_current_process_tree(self, timeout=8.0):
        """このツールが起動した現在のFFmpegと、その子プロセスを確実に終了する。"""
        proc = self.proc
        if proc is None:
            self.suspended_pids = []
            return True

        try:
            root_pid = int(proc.pid)
        except Exception:
            root_pid = None

        # Suspend中なら、まず再開してから終了させる。
        try:
            if self.suspended_pids:
                self.resume_current_process_tree()
        except Exception:
            self.suspended_pids = []

        # すでに終了している場合。
        try:
            if proc.poll() is not None:
                try:
                    proc.wait(timeout=1)
                except Exception:
                    pass
                return True
        except Exception:
            pass

        # psutilが使える場合は、子→親の順で終了要求し、残存だけkillする。
        if psutil is not None and root_pid is not None:
            try:
                parent = psutil.Process(root_pid)
                children = parent.children(recursive=True)
                targets = list(reversed(children)) + [parent]

                for p in targets:
                    try:
                        if p.is_running():
                            p.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception:
                        pass

                try:
                    _, alive = psutil.wait_procs(targets, timeout=max(1.0, timeout / 2.0))
                except Exception:
                    alive = []

                for p in alive:
                    try:
                        p.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    except Exception:
                        pass

                if alive:
                    try:
                        psutil.wait_procs(alive, timeout=max(1.0, timeout / 2.0))
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except Exception:
                pass

        # Windowsではtaskkill /T /Fをフォールバックとして使う。
        # /TによりFFmpeg配下のプロセスも対象になる。
        if os.name == "nt" and root_pid is not None:
            try:
                if proc.poll() is None:
                    subprocess.run(
                        ["taskkill", "/PID", str(root_pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=5,
                        check=False,
                    )
            except Exception:
                pass

        # 最後にPopen自身にも終了を要求。
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        except Exception:
            pass

        self.suspended_pids = []

        try:
            return proc.poll() is not None
        except Exception:
            return True

    def request_stop(self):
        self.stop_requested = True
        self.pause_requested = False
        self.resume_waiting = False
        self.auto_pause_active = False
        self.status_var.set("停止要求を受け付けました")
        try:
            self.terminate_current_process_tree()
        except Exception:
            pass

    def worker(self, st):
        ordered_keys = st.get("queue_keys") or list(self.items.keys())
        all_items = [self.items[k] for k in ordered_keys if k in self.items]
        items = [x for x in all_items if not x.get("done", False)]
        total = len(items)
        success = failed = larger = 0
        bytes_before = bytes_after = 0

        if total == 0:
            self.q.put(("status", "未処理ファイルはありません"))
            self.q.put(("done", 0, 0, 0, 0, 0, False))
            return

        for index,item in enumerate(items,1):
            if self.stop_requested:
                break

            if not self.wait_if_paused():
                break

            # 各ファイル開始前にAmatsukazeを再確認
            self.q.put(("current",f"{index}/{total}  [{self.codec_short_name(item.get('codec', 'x265 (HEVC)'))} / {item.get('profile', 'アニメ')}]  {item['path'].name}"))
            self.q.put(("detail","Amatsukaze状態を確認中…"))
            if not self.wait_for_amatsukaze(st):
                break

            if not self.wait_if_paused():
                break

            p = item["path"]
            enc = self.item_encoding_settings(item, st)
            if not p.exists():
                self.q.put(("row",item,"元ファイルなし",None,None))
                failed += 1
                continue

            try:
                orig_size = p.stat().st_size
                free = shutil.disk_usage(p.parent).free
            except OSError as e:
                self.q.put(("row",item,"容量確認失敗",None,None))
                self.q.put(("err",p.name,str(e)))
                failed += 1
                continue

            required = int(orig_size * st["free_mult"])
            if free < required:
                self.q.put(("row",item,"空き容量不足",None,None))
                self.q.put(("status",
                    f"停止: 空き容量不足 / 必要 {human_size(required)} / 空き {human_size(free)}"))
                self.q.put(("done",success,failed+1,larger,bytes_before,bytes_after,True))
                return

            bytes_before += orig_size
            duration = self.probe_duration(st["ffmpeg"],p)
            tmp = p.with_name(p.stem + ".__reencode_tmp" + p.suffix)
            bak = p.with_name(p.name + ".bak")
            safe_unlink(tmp)

            args = [
                st["ffmpeg"],"-hide_banner","-y","-i",str(p),
                "-map","0:v:0","-map","0:a?","-map","0:s?",
                "-map_metadata","0","-map_chapters","0",
                "-c:v",enc["video_encoder"],"-preset",str(enc["preset"]),"-crf",str(enc["crf"]),
            ]

            if enc["codec"] == "x265 (HEVC)" and enc["tune"]:
                args += ["-tune",enc["tune"]]

            if enc["tenbit"]:
                args += ["-pix_fmt","yuv420p10le"]

            args += [
                "-c:a","copy","-c:s","copy",
            ]

            # +faststart is a MOV/MP4 muxer option. Do not pass it to Matroska.
            if p.suffix.lower() in {".mp4", ".m4v"}:
                args += ["-movflags","+faststart"]

            args += [
                "-progress","pipe:1","-nostats",str(tmp)
            ]

            self.q.put(("row",item,"処理中",None,None))
            self.q.put(("curprog",0))
            self.q.put(("detail",f"{self.codec_short_name(enc['codec'])} / {enc['profile']} / CRF{enc['crf']} / preset {enc['preset']} / 0.0% / fps: - / speed: -"))

            creationflags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            stderr_tail = []
            encode_elapsed = 0.0
            self.current_encode_started = time.monotonic()
            self.current_encode_pause_started = None
            self.current_encode_pause_accum = 0.0
            self.current_encode_item = item
            try:
                self.proc = subprocess.Popen(
                    args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    encoding="utf-8",errors="replace",creationflags=creationflags,bufsize=1
                )

                def read_stderr():
                    if self.proc and self.proc.stderr:
                        for line in self.proc.stderr:
                            stderr_tail.append(line.rstrip())
                            if len(stderr_tail) > 200:
                                del stderr_tail[:-200]

                th = threading.Thread(target=read_stderr,daemon=True)
                th.start()

                fps = "-"
                speed = "-"
                percent = 0.0

                if self.proc.stdout:
                    for raw in self.proc.stdout:
                        if self.stop_requested:
                            self.terminate_current_process_tree()
                            break
                        line = raw.strip()

                        if line.startswith("fps="):
                            fps = line.split("=",1)[1] or "-"
                        elif line.startswith("speed="):
                            speed = line.split("=",1)[1] or "-"
                        elif line.startswith("out_time_ms=") and duration:
                            try:
                                usec = int(line.split("=",1)[1])
                                sec = usec / 1_000_000
                                percent = max(0.0,min(100.0,sec/duration*100.0))
                                self.q.put(("curprog",percent))
                            except Exception:
                                pass
                        elif line == "progress=continue":
                            encode_elapsed = self.current_active_encode_elapsed()
                            self.q.put(("elapsed", item, encode_elapsed))
                            self.q.put(("detail",f"{self.codec_short_name(enc['codec'])} / {enc['profile']} / CRF{enc['crf']} / preset {enc['preset']} / {percent:.1f}% / fps: {fps} / speed: {speed}"))

                if self.stop_requested:
                    self.terminate_current_process_tree()

                try:
                    rc = self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.terminate_current_process_tree()
                    try:
                        rc = self.proc.wait(timeout=3)
                    except Exception:
                        rc = -998

                encode_elapsed = self.current_active_encode_elapsed()
                self.q.put(("elapsed", item, encode_elapsed))
                th.join(timeout=1)

            except Exception as e:
                rc = -999
                stderr_tail.append(str(e))
                encode_elapsed = self.current_active_encode_elapsed()
                self.q.put(("elapsed", item, encode_elapsed))
            finally:
                self.proc = None
                self.current_encode_started = None
                self.current_encode_pause_started = None
                self.current_encode_pause_accum = 0.0
                self.current_encode_item = None

            if self.stop_requested:
                # 停止直後はWindowsがファイルハンドルを解放するまで僅かに遅れることがある。
                # FFmpegツリー終了後、数秒だけ一時ファイル削除を再試行する。
                for _ in range(20):
                    try:
                        if not tmp.exists():
                            break
                        tmp.unlink()
                        break
                    except PermissionError:
                        time.sleep(0.25)
                    except Exception:
                        break

                item["elapsed_seconds"] = encode_elapsed
                self.q.put(("elapsed", item, encode_elapsed))
                self.q.put(("row",item,"停止",None,None))
                break

            if rc != 0 or not tmp.exists() or tmp.stat().st_size <= 0:
                safe_unlink(tmp)
                detail = stderr_tail[-1] if stderr_tail else f"ffmpeg return code={rc}"
                item["elapsed_seconds"] = encode_elapsed
                self.q.put(("elapsed", item, encode_elapsed))
                self.q.put(("row",item,"失敗",None,None))
                self.q.put(("err",p.name,detail))
                failed += 1
                continue

            new_size = tmp.stat().st_size
            saved = orig_size - new_size

            if new_size >= orig_size:
                safe_unlink(tmp)
                self.register_history(item, "縮小せず", orig_size, p, orig_size, 0, encode_elapsed)
                self.q.put(("row",item,"縮小せず",human_size(new_size),"0 B"))
                bytes_after += orig_size
                larger += 1
                self.q.put(("overall",index/total*100))
                continue

            if st["replace"]:
                last_replace_error = None
                replaced = False

                # 通常は即時成功する。プレーヤー・エクスプローラーのプレビュー・ウイルス対策ソフトが
                # ファイルを掴んでいる場合に備え、間隔を延ばしながら最大約60秒再試行する。
                replace_deadline = time.monotonic() + 60
                for attempt in range(400):
                    try:
                        if st["backup"]:
                            safe_unlink(bak)
                            os.replace(p,bak)
                            try:
                                os.replace(tmp,p)
                            except Exception:
                                # 元ファイルを必ず戻す。
                                if bak.exists() and not p.exists():
                                    os.replace(bak,p)
                                raise
                        else:
                            os.replace(tmp,p)

                        replaced = True
                        break

                    except PermissionError as e:
                        last_replace_error = e
                        # backupモードで元を退避済みなら、次回試行前に元へ戻す。
                        try:
                            if st["backup"] and bak.exists() and not p.exists():
                                os.replace(bak,p)
                        except Exception:
                            pass
                        if self.stop_requested or time.monotonic() >= replace_deadline:
                            break
                        if attempt == 4:
                            self.q.put(("detail", "ファイルが他のアプリで使用中のため置換を待っています（最大60秒）…"))
                        time.sleep(min(2.0, 0.25 * (attempt + 1)))

                    except Exception as e:
                        last_replace_error = e
                        break

                if not replaced:
                    e = last_replace_error or RuntimeError("unknown replace error")
                    self.q.put(("row",item,"置換失敗",human_size(new_size),human_size(saved)))
                    hint = ""
                    if isinstance(e, PermissionError) and tmp.exists():
                        hint = ("\n再エンコード済みファイルは削除せず残しています: " + str(tmp) +
                                "\n元ファイルを開いているプレーヤーやエクスプローラーのプレビューを閉じ、"
                                "元ファイルと手動で置き換えるか、もう一度実行してください。")
                    self.q.put(("err",p.name,f"置換失敗: {e}{hint}"))
                    failed += 1
                    continue
            else:
                suffix = "_av1" if enc["codec"] == "AV1 (SVT-AV1)" else "_x265"
                dst = p.with_name(p.stem + suffix + p.suffix)
                try:
                    safe_unlink(dst)
                    os.replace(tmp,dst)
                except Exception as e:
                    self.q.put(("row",item,"保存失敗",human_size(new_size),human_size(saved)))
                    self.q.put(("err",p.name,f"保存失敗: {e}"))
                    failed += 1
                    continue

            output_path = p if st["replace"] else dst
            self.register_history(item, "完了", orig_size, output_path, new_size, saved, encode_elapsed)
            bytes_after += new_size
            success += 1
            self.q.put(("row",item,"完了",human_size(new_size),human_size(saved)))
            self.q.put(("curprog",100))
            self.q.put(("detail",f"100.0% / 完了 / {human_elapsed(encode_elapsed)} / {human_size(saved)} 削減"))
            self.q.put(("overall",index/total*100))

        self.q.put(("done",success,failed,larger,bytes_before,bytes_after,self.stop_requested))

    def poll_queue(self):
        try:
            while True:
                msg = self.q.get_nowait()
                k = msg[0]
                if k=="current":
                    self.current_var.set(msg[1])
                elif k=="detail":
                    self.detail_var.set(msg[1])
                elif k=="status":
                    self.status_var.set(msg[1])
                elif k=="curprog":
                    self.current_progress_var.set(msg[1])
                elif k=="overall":
                    self.overall_progress_var.set(msg[1])
                elif k=="elapsed":
                    _,item,seconds = msg
                    self.set_elapsed(item, seconds)
                elif k=="row":
                    _,item,status,after,saved = msg
                    self.set_row(item,status,after,saved)
                elif k=="err":
                    _,name,detail = msg
                    try:
                        if "Invalid data found when processing input" in detail:
                            detail += "\n（入力ファイルの破損、録画・コピー途中、または非対応の形式の可能性があります）"
                        log_path = Path(__file__).resolve().with_name("AV1_reencoder_error.log")
                        with open(log_path,"a",encoding="utf-8") as f:
                            f.write("="*60+"\n"+time.strftime("%Y-%m-%d %H:%M:%S")+"  "+name+"\n"+detail+"\n")
                    except Exception:
                        pass
                elif k=="auto_pause_started":
                    active = msg[1]
                    self.pause_btn.configure(text="Amatsukaze待機…", state="disabled")
                    self.status_var.set("Amatsukaze開始を検知したため自動一時停止しました")
                    self.detail_var.set(f"検知: {active} / Amatsukaze終了後に自動再開します")
                elif k=="auto_pause_waiting":
                    active = msg[1]
                    self.status_var.set("自動一時停止中：Amatsukazeの終了を待っています")
                    self.detail_var.set(f"動作中: {active}")
                elif k=="auto_pause_clear_check":
                    remain = msg[1]
                    self.status_var.set(f"Amatsukaze終了確認中：あと約 {remain} 秒")
                    self.detail_var.set("連続不在を確認後、自動的に再エンコードを再開します")
                elif k=="auto_pause_resumed":
                    self.pause_btn.configure(text="一時停止", state="normal")
                    self.status_var.set("Amatsukazeの終了を確認して自動再開しました")
                    self.detail_var.set("")
                elif k=="pause_resume_done":
                    self.resume_waiting = False
                    self.pause_btn.configure(text="一時停止", state="normal")
                    self.status_var.set("Amatsukazeの停止を確認して再開しました")
                    self.detail_var.set("")
                elif k=="pause_resume_aborted":
                    self.resume_waiting = False
                    if self.running and not self.stop_requested:
                        self.pause_btn.configure(text="再開", state="normal")
                elif k=="done":
                    _,success,failed,larger,before,after,stopped = msg
                    self.running = False
                    self.pause_requested = False
                    self.suspended_pids = []
                    self.resume_waiting = False
                    self.auto_pause_active = False
                    self.current_settings = None
                    self.current_encode_started = None
                    self.current_encode_pause_started = None
                    self.current_encode_pause_accum = 0.0
                    self.current_encode_item = None
                    self.start_btn.configure(state="normal")
                    self.pause_btn.configure(state="disabled", text="一時停止")
                    self.stop_btn.configure(state="disabled")
                    if stopped:
                        if not self.status_var.get().startswith("停止: 空き容量不足"):
                            self.status_var.set("停止しました")
                    else:
                        saved = max(0,before-after)
                        self.status_var.set(f"完了: 成功 {success} / 失敗 {failed} / 縮小せず {larger} / 削減 {human_size(saved)}")
                    self.save_state()
        except queue.Empty:
            pass
        self.root.after(150,self.poll_queue)

def main():
    root = TkinterDnD.Tk() if TkinterDnD is not None else tk.Tk()
    App(root)
    root.mainloop()

if __name__=="__main__":
    main()
