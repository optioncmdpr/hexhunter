import os
import sys
import time
import secrets
import hashlib
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox

from multiprocessing import Process, Value, Event
from ctypes import c_ulonglong, c_bool

# Optional: psutil for telemetry
try:
    import psutil
except ImportError:
    psutil = None

try:
    import coincurve
except ImportError:
    print("Error: coincurve is required. Install with: pip install coincurve")
    sys.exit(1)

# ---------------------------
# Base58 / hash utilities
# ---------------------------

_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_ALPHABET_INDEX = {c: i for i, c in enumerate(_ALPHABET)}


def b58decode_check(addr_b: bytes) -> bytes:
    num = 0
    for ch in addr_b:
        if ch not in _ALPHABET_INDEX:
            raise ValueError("Invalid Base58 character")
        num = num * 58 + _ALPHABET_INDEX[ch]
    full = num.to_bytes(25, 'big')
    pad = 0
    for ch in addr_b:
        if ch == _ALPHABET[0]:
            pad += 1
        else:
            break
    full = (b'\x00' * pad) + full.lstrip(b'\x00')
    if len(full) != 25:
        full = (b'\x00' * (25 - len(full))) + full
    body, cks = full[:-4], full[-4:]
    chk = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    if chk != cks:
        raise ValueError("Checksum mismatch")
    return body


def address_or_hash160(input_str: str):
    """Accepts either a Base58 BTC address or a raw 40-char hash160 hex string."""
    s = input_str.strip()
    if len(s) == 40 and all(c in "0123456789abcdefABCDEF" for c in s):
        return None, bytes.fromhex(s)
    addr_b = s.encode('ascii')
    body = b58decode_check(addr_b)
    return body[0], body[1:]


def priv_int_to_pubkey_compressed(priv_int: int) -> bytes:
    priv_bytes = priv_int.to_bytes(32, 'big')
    return coincurve.PrivateKey(priv_bytes).public_key.format(compressed=True)


def pubkey_to_hash160(pubkey_compressed: bytes) -> bytes:
    sha = hashlib.sha256(pubkey_compressed).digest()
    return hashlib.new('ripemd160', sha).digest()


def fmt_rate(keys: int, seconds: float) -> str:
    if seconds <= 0:
        return f"{keys} keys/s"
    rate = keys / seconds
    units = ['keys/s', 'K/s', 'M/s', 'G/s']
    i = 0
    while rate >= 1000 and i < len(units) - 1:
        rate /= 1000.0
        i += 1
    return f"{rate:.2f} {units[i]}"


# ---------------------------
# Worker functions
# ---------------------------

def worker_linear(start_key, end_key, step, target_hash160,
                  progress_counter, found_flag, found_key_out,
                  stop_event, batch_size):
    k = start_key
    local_count = 0
    while not stop_event.is_set() and not found_flag.value and k < end_key:
        batch_end = min(k + step * batch_size, end_key)
        kk = k
        for _ in range(batch_size):
            if kk >= end_key:
                break
            pub = priv_int_to_pubkey_compressed(kk)
            if pubkey_to_hash160(pub) == target_hash160:
                with found_flag.get_lock():
                    if not found_flag.value:
                        found_flag.value = True
                        found_key_out.value = kk
                        stop_event.set()
                return
            kk += step
            local_count += 1
        if local_count >= 10000:
            with progress_counter.get_lock():
                progress_counter.value += local_count
            local_count = 0
        k = kk
    if local_count:
        with progress_counter.get_lock():
            progress_counter.value += local_count


def worker_random(start_key, end_key, target_hash160,
                  progress_counter, found_flag, found_key_out,
                  stop_event, random_batch):
    space = end_key - start_key
    local_count = 0
    while not stop_event.is_set() and not found_flag.value:
        for _ in range(random_batch):
            r = start_key + secrets.randbelow(space)
            pub = priv_int_to_pubkey_compressed(r)
            if pubkey_to_hash160(pub) == target_hash160:
                with found_flag.get_lock():
                    if not found_flag.value:
                        found_flag.value = True
                        found_key_out.value = r
                        stop_event.set()
                return
            local_count += 1
        if local_count >= 10000:
            with progress_counter.get_lock():
                progress_counter.value += local_count
            local_count = 0
    if local_count:
        with progress_counter.get_lock():
            progress_counter.value += local_count


# ---------------------------
# Process priority / affinity
# ---------------------------

if os.name == "nt":
    PRIORITY_MAP = {
        "Normal": 0x00000020,     # NORMAL_PRIORITY_CLASS
        "High": 0x00000080,       # HIGH_PRIORITY_CLASS
        "Realtime": 0x00000100,   # REALTIME_PRIORITY_CLASS
    }

    def set_process_priority(level: str):
        level = level.capitalize()
        if level not in PRIORITY_MAP:
            return
        try:
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ctypes.windll.kernel32.SetPriorityClass(handle, PRIORITY_MAP[level])
        except Exception:
            pass

    def set_cpu_affinity(mask: int):
        try:
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            ctypes.windll.kernel32.SetProcessAffinityMask(handle, mask)
        except Exception:
            pass
else:
    PRIORITY_MAP = {}

    def set_process_priority(level: str):
        pass

    def set_cpu_affinity(mask: int):
        pass


# ---------------------------
# Engine wrapper for GUI
# ---------------------------

class HexHunterEngine:
    """
    Wraps the multiprocessing engine for GUI control.
    """

    def __init__(self):
        self.mode = "Linear"  # or "Random"
        self.address = ""
        self.start_hex = "00000000"
        self.end_hex = "FFFFFFFF"
        self.workers = 4
        self.batch_size = 50000
        self.random_batch = 10000
        self.linear_step = 1

        self.progress = None
        self.found_flag = None
        self.found_key = None
        self.stop_event = None
        self.procs = []
        self.t0 = None

    def configure(self, mode, address, start_hex, end_hex,
                  workers, batch_size, random_batch, linear_step):
        self.mode = mode
        self.address = address
        self.start_hex = start_hex
        self.end_hex = end_hex
        self.workers = max(1, workers)
        self.batch_size = max(1, batch_size)
        self.random_batch = max(1, random_batch)
        self.linear_step = max(1, linear_step)

    def start(self):
        if self.procs:
            return  # already running

        _, target_h160 = address_or_hash160(self.address)
        start_key = int(self.start_hex, 16)
        end_key = int(self.end_hex, 16)

        self.progress = Value(c_ulonglong, 0)
        self.found_flag = Value(c_bool, False)
        self.found_key = Value('Q', 0)
        self.stop_event = Event()
        self.procs = []
        self.t0 = time.time()

        if self.mode == "Linear":
            step = self.workers
            for i in range(self.workers):
                p = Process(
                    target=worker_linear,
                    args=(
                        start_key + i,
                        end_key,
                        step,
                        target_h160,
                        self.progress,
                        self.found_flag,
                        self.found_key,
                        self.stop_event,
                        self.batch_size,
                    ),
                )
                p.daemon = True
                p.start()
                self.procs.append(p)
        else:  # Random
            for i in range(self.workers):
                p = Process(
                    target=worker_random,
                    args=(
                        start_key,
                        end_key,
                        target_h160,
                        self.progress,
                        self.found_flag,
                        self.found_key,
                        self.stop_event,
                        self.random_batch,
                    ),
                )
                p.daemon = True
                p.start()
                self.procs.append(p)

    def stop(self):
        if self.stop_event is not None:
            self.stop_event.set()
        for p in self.procs:
            p.join(timeout=0.1)
        self.procs = []

    def is_running(self):
        return any(p.is_alive() for p in self.procs) if self.procs else False

    def get_progress(self):
        if self.progress is None:
            return 0
        with self.progress.get_lock():
            return self.progress.value

    def get_found_key(self):
        if self.found_flag is not None and self.found_flag.value:
            return int(self.found_key.value)
        return None


# ---------------------------
# GUI Application
# ---------------------------

class HexHunterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HexHunter Optimized")
        self.root.geometry("1150x700")

        # Engine
        self.engine = HexHunterEngine()

        # Performance state
        self.current_preset = tk.StringVar(value="Balanced")
        self.priority_var = tk.StringVar(value="Normal")
        self.batch_size_var = tk.IntVar(value=50000)
        self.gui_refresh_var = tk.DoubleVar(value=0.5)
        self.linear_step_var = tk.IntVar(value=1)
        self.random_batch_var = tk.IntVar(value=10000)

        # CPU affinity state
        self.core_vars = []
        self._init_core_state()

        # Safe system tweak toggles (UI only)
        self.pause_onedrive_var = tk.BooleanVar(value=False)
        self.disable_animations_var = tk.BooleanVar(value=False)
        self.reduce_transparency_var = tk.BooleanVar(value=False)
        self.show_suggestions_var = tk.BooleanVar(value=False)

        # Telemetry
        self.last_progress = 0
        self.last_time = time.time()
        self.keys_per_sec = tk.DoubleVar(value=0.0)
        self.total_keys_var = tk.IntVar(value=0)
        self.cpu_usage_var = tk.StringVar(value="N/A")

        # Build UI
        self._build_ui()

        # Start telemetry update loop
        self._schedule_telemetry_update()

    # -------------------------
    # Core / CPU detection
    # -------------------------

    def _init_core_state(self):
        try:
            if psutil:
                num_cores = psutil.cpu_count(logical=True) or 4
            else:
                num_cores = os.cpu_count() or 4
        except Exception:
            num_cores = 4

        self.num_cores = num_cores
        self.core_vars = [tk.BooleanVar(value=True) for _ in range(num_cores)]

    # -------------------------
    # UI construction
    # -------------------------

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.scan_frame = ttk.Frame(self.notebook)
        self.perf_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_frame, text="Scan")
        self.notebook.add(self.perf_frame, text="Performance")

        self._build_scan_tab()
        self._build_performance_tab()

    def _build_scan_tab(self):
        frame = self.scan_frame

        top = ttk.LabelFrame(frame, text="Scan Configuration")
        top.pack(fill="x", padx=10, pady=10)

        # Target address / hash160
        ttk.Label(top, text="Target (address or hash160):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.target_entry = ttk.Entry(top, width=45)
        self.target_entry.grid(row=0, column=1, columnspan=2, sticky="we", padx=5, pady=5)
        top.columnconfigure(2, weight=1)

        # Address range
        ttk.Label(top, text="Start Key (hex):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.start_addr_entry = ttk.Entry(top, width=20)
        self.start_addr_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.start_addr_entry.insert(0, "0000000000000000000000000000000000000000000000000000000000000001")

        ttk.Label(top, text="End Key (hex):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.end_addr_entry = ttk.Entry(top, width=20)
        self.end_addr_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        self.end_addr_entry.insert(0, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")

        # Mode
        ttk.Label(top, text="Mode:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.mode_var = tk.StringVar(value="Linear")
        mode_combo = ttk.Combobox(
            top,
            textvariable=self.mode_var,
            values=["Linear", "Random"],
            state="readonly",
            width=10,
        )
        mode_combo.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # Workers
        ttk.Label(top, text="Workers:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.workers_var = tk.IntVar(value=4)
        workers_spin = ttk.Spinbox(top, from_=1, to=64, textvariable=self.workers_var, width=5)
        workers_spin.grid(row=4, column=1, sticky="w", padx=5, pady=5)

        # Linear step
        ttk.Label(top, text="Linear Step Size:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        linear_entry = ttk.Spinbox(top, from_=1, to=1000000, textvariable=self.linear_step_var, width=10)
        linear_entry.grid(row=5, column=1, sticky="w", padx=5, pady=5)

        # Random batch
        ttk.Label(top, text="Random Batch Size:").grid(row=6, column=0, sticky="w", padx=5, pady=5)
        random_entry = ttk.Spinbox(top, from_=100, to=1000000, textvariable=self.random_batch_var, width=10)
        random_entry.grid(row=6, column=1, sticky="w", padx=5, pady=5)

        # Start/Stop buttons
        btn_frame = ttk.Frame(top)
        btn_frame.grid(row=7, column=0, columnspan=3, pady=10)

        start_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan)
        start_btn.grid(row=0, column=0, padx=5)

        stop_btn = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan)
        stop_btn.grid(row=0, column=1, padx=5)

        # Status
        bottom = ttk.LabelFrame(frame, text="Status")
        bottom.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(bottom, text="Total Keys Scanned:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.total_keys_label = ttk.Label(bottom, textvariable=self.total_keys_var)
        self.total_keys_label.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(bottom, text="Keys/sec:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.kps_label = ttk.Label(bottom, textvariable=self.keys_per_sec)
        self.kps_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(bottom, text="CPU Usage:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.cpu_label = ttk.Label(bottom, textvariable=self.cpu_usage_var)
        self.cpu_label.grid(row=2, column=1, sticky="w", padx=5, pady=5)

    def _build_performance_tab(self):
        frame = self.perf_frame

        # Presets
        preset_frame = ttk.LabelFrame(frame, text="Performance Preset")
        preset_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(preset_frame, text="Preset:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        preset_combo = ttk.Combobox(
            preset_frame,
            textvariable=self.current_preset,
            values=["Balanced", "High Performance", "Maximum Overdrive"],
            state="readonly",
            width=20,
        )
        preset_combo.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        preset_combo.bind("<<ComboboxSelected>>", self.on_preset_changed)

        # Advanced controls
        adv_frame = ttk.LabelFrame(frame, text="Advanced Controls")
        adv_frame.pack(fill="x", padx=10, pady=10)

        # Priority
        ttk.Label(adv_frame, text="Process Priority:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        priority_combo = ttk.Combobox(
            adv_frame,
            textvariable=self.priority_var,
            values=["Normal", "High", "Realtime"],
            state="readonly",
            width=10,
        )
        priority_combo.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        priority_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_priority())

        # Batch size
        ttk.Label(adv_frame, text="Batch Size:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        batch_scale = ttk.Scale(
            adv_frame,
            from_=5000,
            to=200000,
            orient="horizontal",
            variable=self.batch_size_var,
            command=lambda v: self.apply_batch_size(),
        )
        batch_scale.grid(row=1, column=1, sticky="we", padx=5, pady=5)
        adv_frame.columnconfigure(1, weight=1)

        # GUI refresh
        ttk.Label(adv_frame, text="GUI Refresh (s):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        refresh_scale = ttk.Scale(
            adv_frame,
            from_=0.1,
            to=2.0,
            orient="horizontal",
            variable=self.gui_refresh_var,
        )
        refresh_scale.grid(row=2, column=1, sticky="we", padx=5, pady=5)

        # CPU affinity
        affinity_frame = ttk.LabelFrame(frame, text="CPU Affinity")
        affinity_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(affinity_frame, text="Use CPU Cores:").grid(row=0, column=0, sticky="w", padx=5, pady=5)

        cores_frame = ttk.Frame(affinity_frame)
        cores_frame.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        for i in range(self.num_cores):
            cb = ttk.Checkbutton(
                cores_frame,
                text=f"Core {i}",
                variable=self.core_vars[i],
                command=self.apply_affinity,
            )
            cb.grid(row=i // 4, column=i % 4, sticky="w", padx=5, pady=2)

        # Safe system tweaks (suggestions only)
        tweaks_frame = ttk.LabelFrame(frame, text="Safe System Tweaks (Suggestions)")
        tweaks_frame.pack(fill="x", padx=10, pady=10)

        ttk.Checkbutton(
            tweaks_frame,
            text="Pause OneDrive Sync (suggested)",
            variable=self.pause_onedrive_var,
            command=self.on_tweak_changed,
        ).grid(row=0, column=0, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            tweaks_frame,
            text="Disable Windows Animations (suggested)",
            variable=self.disable_animations_var,
            command=self.on_tweak_changed,
        ).grid(row=1, column=0, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            tweaks_frame,
            text="Reduce Transparency Effects (suggested)",
            variable=self.reduce_transparency_var,
            command=self.on_tweak_changed,
        ).grid(row=2, column=0, sticky="w", padx=5, pady=2)

        ttk.Checkbutton(
            tweaks_frame,
            text="Show Suggested Background Apps to Close",
            variable=self.show_suggestions_var,
            command=self.on_tweak_changed,
        ).grid(row=3, column=0, sticky="w", padx=5, pady=2)

        # Telemetry
        telemetry_frame = ttk.LabelFrame(frame, text="Telemetry")
        telemetry_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(telemetry_frame, text="Current Preset:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.preset_label = ttk.Label(telemetry_frame, textvariable=self.current_preset)
        self.preset_label.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(telemetry_frame, text="Process Priority:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.priority_label = ttk.Label(telemetry_frame, textvariable=self.priority_var)
        self.priority_label.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(telemetry_frame, text="Keys/sec:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.telemetry_kps_label = ttk.Label(telemetry_frame, textvariable=self.keys_per_sec)
        self.telemetry_kps_label.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(telemetry_frame, text="Total Keys:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.telemetry_total_label = ttk.Label(telemetry_frame, textvariable=self.total_keys_var)
        self.telemetry_total_label.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(telemetry_frame, text="CPU Usage:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.telemetry_cpu_label = ttk.Label(telemetry_frame, textvariable=self.cpu_usage_var)
        self.telemetry_cpu_label.grid(row=4, column=1, sticky="w", padx=5, pady=5)

    # -------------------------
    # Scan control
    # -------------------------

    def start_scan(self):
        address = self.target_entry.get().strip()
        if not address:
            messagebox.showerror("Error", "Please enter a target address or hash160.")
            return

        start_hex = self.start_addr_entry.get().strip()
        end_hex = self.end_addr_entry.get().strip()

        try:
            int(start_hex, 16)
            int(end_hex, 16)
        except ValueError:
            messagebox.showerror("Error", "Start/End keys must be valid hex.")
            return

        try:
            workers = int(self.workers_var.get())
        except Exception:
            workers = 4

        try:
            batch_size = int(self.batch_size_var.get())
        except Exception:
            batch_size = 50000

        try:
            linear_step = int(self.linear_step_var.get())
        except Exception:
            linear_step = 1

        try:
            random_batch = int(self.random_batch_var.get())
        except Exception:
            random_batch = 10000

        mode = self.mode_var.get()

        self.engine.configure(
            mode=mode,
            address=address,
            start_hex=start_hex,
            end_hex=end_hex,
            workers=workers,
            batch_size=batch_size,
            random_batch=random_batch,
            linear_step=linear_step,
        )
        self.engine.start()

    def stop_scan(self):
        self.engine.stop()

    # -------------------------
    # Performance controls
    # -------------------------

    def on_preset_changed(self, event=None):
        preset = self.current_preset.get()
        if preset == "Balanced":
            self.priority_var.set("Normal")
            self.batch_size_var.set(50000)
            self.gui_refresh_var.set(0.5)
        elif preset == "High Performance":
            self.priority_var.set("High")
            self.batch_size_var.set(100000)
            self.gui_refresh_var.set(0.75)
        elif preset == "Maximum Overdrive":
            self.priority_var.set("Realtime")
            self.batch_size_var.set(150000)
            self.gui_refresh_var.set(1.5)

        self.apply_priority()
        self.apply_batch_size()
        self.apply_affinity()

    def apply_priority(self):
        level = self.priority_var.get()
        set_process_priority(level)

    def apply_batch_size(self):
        try:
            batch = int(self.batch_size_var.get())
        except Exception:
            batch = 50000
        self.engine.batch_size = max(1, batch)

    def apply_affinity(self):
        mask = 0
        for i, var in enumerate(self.core_vars):
            if var.get():
                mask |= (1 << i)

        if mask == 0:
            self.core_vars[0].set(True)
            mask = 1

        set_cpu_affinity(mask)

    def on_tweak_changed(self):
        msgs = []
        if self.pause_onedrive_var.get():
            msgs.append("Consider pausing OneDrive sync from its tray icon for best performance.")
        if self.disable_animations_var.get():
            msgs.append("Consider disabling Windows animations in System → Accessibility → Visual effects.")
        if self.reduce_transparency_var.get():
            msgs.append("Consider disabling transparency effects in Personalization → Colors.")
        if self.show_suggestions_var.get():
            msgs.append("Close heavy apps like browsers, game launchers, and editors to free CPU/RAM.")

        if msgs:
            messagebox.showinfo("Performance Suggestions", "\n\n".join(msgs))

    # -------------------------
    # Telemetry
    # -------------------------

    def _schedule_telemetry_update(self):
        self._update_telemetry()
        interval_ms = int(self.gui_refresh_var.get() * 1000)
        interval_ms = max(100, min(interval_ms, 2000))
        self.root.after(interval_ms, self._schedule_telemetry_update)

    def _update_telemetry(self):
        now = time.time()
        current_progress = self.engine.get_progress()
        delta_keys = current_progress - self.last_progress
        delta_time = now - self.last_time

        if delta_time > 0:
            kps = delta_keys / delta_time
        else:
            kps = 0.0

        self.keys_per_sec.set(round(kps, 2))
        self.total_keys_var.set(current_progress)

        self.last_progress = current_progress
        self.last_time = now

        if psutil:
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
                self.cpu_usage_var.set(f"{cpu_percent:.1f}%")
            except Exception:
                self.cpu_usage_var.set("N/A")
        else:
            self.cpu_usage_var.set("N/A")


def main():
    root = tk.Tk()
    app = HexHunterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()