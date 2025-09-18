# live_ids_gui_flow_mc.py
# - Flow-based IDS GUI (multiclass RF) with "Load Model + Meta" button + Replay

import tkinter as tk
from tkinter import ttk, filedialog
import threading, time, os, sys, json, csv
from collections import defaultdict, deque

# Scapy
from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
from scapy.layers.inet import IP as ScapyIP

# ML / math
import joblib
import numpy as np
import pandas as pd
from datetime import datetime

# ---------------- Config (defaults, can be overridden by the button) ----------------
MODEL_PATH = "rf_flow_mc.pkl"
META_PATH  = "rf_flow_mc.meta.json"

# Heuristics
PORTSCAN_WINDOW_SEC = 1.0
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 20
SYN_RATE_WINDOW_SEC = 1.0
SYN_RATE_THRESHOLD  = 50

# Synthesis controls (Replay mode only)
USE_SYNTH_REPLIES = True
SYNTH_DATA_RATIO  = 0.15
SYNTH_RESP_SIZE   = 120


WARMUP_MIN_PKTS   = 15
WARMUP_MIN_DUR_US = 80_000  # 0.08s

# Logging / UI
LOG_FILE = "packet_log.txt"
SUMMARY_MAX = 300  # cap printed flow summaries on Stop

# ---------------- State ----------------
scan_windows = defaultdict(lambda: deque(maxlen=400))
last_scan_alert_ts = {}
syn_times = []            # recent SYN timestamps
flows = {}                # (src,dst,proto,sport,dport) -> FlowStats
is_sniffing = False

# model/meta (loaded at runtime)
model_lock = threading.Lock()
rf = None
meta = {}
NEEDED = []
CLASS_NAMES_LIST = []
_id2name = {}
_classes_arr = []

# Recent heuristic overlay (label override for a short time window)
recent_heuristic = {"kind": None, "until": 0.0}  # kind in {"DDoS","PortScan"}

# ------------- Utilities -------------
def seconds():
    return time.time()

def log_to_file(message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    try:
        output_text.insert(tk.END, line + "\n")
        output_text.see(tk.END)
    except Exception:
        pass

def set_heuristic(kind: str, ttl_sec: float = 2.0):
    recent_heuristic["kind"] = kind
    recent_heuristic["until"] = seconds() + ttl_sec

def current_overlay_label():
    now = seconds()
    if recent_heuristic["kind"] and now < recent_heuristic["until"]:
        return recent_heuristic["kind"] + " (heuristic)"
    return None

def announce_model():
    with model_lock:
        classes = list(_classes_arr)
        needed = list(NEEDED)
        cnames = [_id2name.get(c, str(c)) for c in classes]
    log_to_file(f"[i] Model ready. classes_={classes}")
    log_to_file(f"[i] Class names: {cnames}")
    log_to_file(f"[i] Expecting features ({len(needed)}): {needed}")


ALIASES = {
    "Flow Duration": ["Flow Duration", "flow duration"],
    "Flow Packets/s": ["Flow Packets/s", "flow packets/s", "flow packets per s", "flow packets per second"],
    "Average Packet Size": ["Average Packet Size", "avg packet size", "average packet size"],
    "Packet Length Std": ["Packet Length Std", "packet length std"],
    "FIN Flag Count": ["FIN Flag Count", "fin flag count"],
    "SYN Flag Count": ["SYN Flag Count", "syn flag count"],
    "RST Flag Count": ["RST Flag Count", "rst flag count"],
    "PSH Flag Count": ["PSH Flag Count", "psh flag count"],
    "ACK Flag Count": ["ACK Flag Count", "ack flag count"],
    "Total Fwd Packets": ["Total Fwd Packets", "total fwd packets"],
    "Total Backward Packets": ["Total Backward Packets", "total bwd packets", "total backward packets"],
    "Total Length of Fwd Packets": ["Total Length of Fwd Packets"],
    "Total Length of Bwd Packets": ["Total Length of Bwd Packets"],
    "Min Packet Length": ["Min Packet Length"],
    "Max Packet Length": ["Max Packet Length"],
    "Packet Length Mean": ["Packet Length Mean"],

    # present in meta too:
    "Fwd Packet Length Max": ["Fwd Packet Length Max"],
    "Fwd Packet Length Min": ["Fwd Packet Length Min"],
    "Fwd Packet Length Mean": ["Fwd Packet Length Mean"],
    "Fwd Packet Length Std":  ["Fwd Packet Length Std"],
    "Bwd Packet Length Max": ["Bwd Packet Length Max"],
    "Bwd Packet Length Min": ["Bwd Packet Length Min"],
    "Bwd Packet Length Mean": ["Bwd Packet Length Mean"],
    "Bwd Packet Length Std":  ["Bwd Packet Length Std"],
    "Flow Bytes/s": ["Flow Bytes/s"],
    "Flow IAT Mean": ["Flow IAT Mean"],
    "Flow IAT Std": ["Flow IAT Std"],
    "Flow IAT Max": ["Flow IAT Max"],
    "Flow IAT Min": ["Flow IAT Min"],
    "Fwd IAT Mean": ["Fwd IAT Mean"],
    "Fwd IAT Std": ["Fwd IAT Std"],
    "Fwd IAT Max": ["Fwd IAT Max"],
    "Fwd IAT Min": ["Fwd IAT Min"],
    "Bwd IAT Mean": ["Bwd IAT Mean"],
    "Bwd IAT Std": ["Bwd IAT Std"],
    "Bwd IAT Max": ["Bwd IAT Max"],
    "Bwd IAT Min": ["Bwd IAT Min"],
}
ALIAS_TO_CANON = {n.lower(): canon for canon, names in ALIASES.items() for n in names}

def canon(feature_name: str) -> str:
    key = " ".join(feature_name.strip().split()).lower()
    return ALIAS_TO_CANON.get(key, feature_name)

warned_missing = set()

# --------- Flow aggregator ----------
class FlowStats:
    __slots__ = (
        "first_ts","last_ts",
        "fwd_pkts","bwd_pkts",
        "fwd_bytes","bwd_bytes",
        "fwd_lengths","bwd_lengths",
        "last_ts_any","last_ts_fwd","last_ts_bwd",
        "iat_all","iat_fwd","iat_bwd",
        "fin","syn","rst","psh","ack",
        "initiator_src"
    )
    def __init__(self, initiator_src=None):
        now = seconds()
        self.first_ts = now
        self.last_ts  = now
        self.last_ts_any = None
        self.last_ts_fwd = None
        self.last_ts_bwd = None

        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.fwd_lengths = []
        self.bwd_lengths = []
        self.iat_all = []
        self.iat_fwd = []
        self.iat_bwd = []

        self.fin = self.syn = self.rst = self.psh = self.ack = 0
        self.initiator_src = initiator_src

    def _push_len(self, arr, val, cap=400):
        if len(arr) < cap:
            arr.append(val)

    def _push_iat(self, arr, delta, cap=800):
        if delta is not None and delta >= 0.0 and len(arr) < cap:
            arr.append(delta)

    def update(self, length: int, is_fwd: bool, flags: int|None):
        now = seconds()
        if self.last_ts_any is not None:
            self._push_iat(self.iat_all, now - self.last_ts_any)
        self.last_ts_any = now

        self.last_ts = now
        if is_fwd:
            self.fwd_pkts  += 1
            self.fwd_bytes += max(0, length)
            self._push_len(self.fwd_lengths, float(length))
            if self.last_ts_fwd is not None:
                self._push_iat(self.iat_fwd, now - self.last_ts_fwd)
            self.last_ts_fwd = now
        else:
            self.bwd_pkts  += 1
            self.bwd_bytes += max(0, length)
            self._push_len(self.bwd_lengths, float(length))
            if self.last_ts_bwd is not None:
                self._push_iat(self.iat_bwd, now - self.last_ts_bwd)
            self.last_ts_bwd = now

        if flags is not None:
            if flags & 0x01: self.fin += 1
            if flags & 0x02: self.syn += 1
            if flags & 0x04: self.rst += 1
            if flags & 0x08: self.psh += 1
            if flags & 0x10: self.ack += 1

    def _stats(self, arr):
        if not arr:
            return (0.0, 0.0, 0.0, 0.0)
        v = np.array(arr, dtype=np.float32)
        return (float(np.mean(v)),
                float(np.std(v, ddof=0)),
                float(np.max(v)),
                float(np.min(v)))

    def _mean_only(self, arr):
        if not arr: return 0.0
        return float(np.mean(np.array(arr, dtype=np.float32)))

    def as_features(self) -> dict:
        dur_s  = max(1e-6, self.last_ts - self.first_ts)
        dur_us = dur_s * 1e6

        total_pkts  = self.fwd_pkts + self.bwd_pkts
        total_bytes = self.fwd_bytes + self.bwd_bytes

        flow_pkts_per_s = total_pkts / dur_s
        avg_pkt_size    = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        flow_bytes_per_s= total_bytes / dur_s

        all_lengths = (self.fwd_lengths + self.bwd_lengths)
        if all_lengths:
            v_all = np.array(all_lengths, dtype=np.float32)
            pkt_len_mean = float(np.mean(v_all))
            pkt_len_std  = float(np.std(v_all, ddof=0))
            pkt_len_min  = float(np.min(v_all))
            pkt_len_max  = float(np.max(v_all))
        else:
            pkt_len_mean = pkt_len_std = pkt_len_min = pkt_len_max = 0.0

        fwd_mean, fwd_std, fwd_max, fwd_min = self._stats(self.fwd_lengths)
        bwd_mean, bwd_std, bwd_max, bwd_min = self._stats(self.bwd_lengths)

        flow_iat_mean = self._mean_only(self.iat_all)
        flow_iat_std  = float(np.std(np.array(self.iat_all, dtype=np.float32), ddof=0)) if self.iat_all else 0.0
        flow_iat_max  = float(np.max(self.iat_all)) if self.iat_all else 0.0
        flow_iat_min  = float(np.min(self.iat_all)) if self.iat_all else 0.0

        fwd_iat_mean  = self._mean_only(self.iat_fwd)
        fwd_iat_std   = float(np.std(np.array(self.iat_fwd, dtype=np.float32), ddof=0)) if self.iat_fwd else 0.0
        fwd_iat_max   = float(np.max(self.iat_fwd)) if self.iat_fwd else 0.0
        fwd_iat_min   = float(np.min(self.iat_fwd)) if self.iat_fwd else 0.0

        bwd_iat_mean  = self._mean_only(self.iat_bwd)
        bwd_iat_std   = float(np.std(np.array(self.iat_bwd, dtype=np.float32), ddof=0)) if self.iat_bwd else 0.0
        bwd_iat_max   = float(np.max(self.iat_bwd)) if self.iat_bwd else 0.0
        bwd_iat_min   = float(np.min(self.iat_bwd)) if self.iat_bwd else 0.0

        return {
            # Core
            "Flow Duration": dur_us,
            "Flow Packets/s": flow_pkts_per_s,
            "Average Packet Size": avg_pkt_size,
            "Packet Length Std": pkt_len_std,
            "FIN Flag Count": float(self.fin),
            "SYN Flag Count": float(self.syn),
            "RST Flag Count": float(self.rst),
            "PSH Flag Count": float(self.psh),
            "ACK Flag Count": float(self.ack),

            # Extra (present in meta)
            "Total Fwd Packets": float(self.fwd_pkts),
            "Total Backward Packets": float(self.bwd_pkts),
            "Total Length of Fwd Packets": float(self.fwd_bytes),
            "Total Length of Bwd Packets": float(self.bwd_bytes),

            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std":  fwd_std,

            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std":  bwd_std,

            "Flow Bytes/s": flow_bytes_per_s,

            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std":  flow_iat_std,
            "Flow IAT Max":  flow_iat_max,
            "Flow IAT Min":  flow_iat_min,

            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std":  fwd_iat_std,
            "Fwd IAT Max":  fwd_iat_max,
            "Fwd IAT Min":  fwd_iat_min,

            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std":  bwd_iat_std,
            "Bwd IAT Max":  bwd_iat_max,
            "Bwd IAT Min":  bwd_iat_min,

            "Min Packet Length": pkt_len_min,
            "Max Packet Length": pkt_len_max,
            "Packet Length Mean": pkt_len_mean,
        }

# --------- Model loading helpers ----------
def _build_class_mapping(clf, meta_path, m):
    classes_arr = list(getattr(clf, "classes_", []))
    class_names_list = None
    if isinstance(m.get("class_names"), list) and m["class_names"]:
        class_names_list = m["class_names"]
    elif isinstance(m.get("classes"), list) and m["classes"]:
        class_names_list = m["classes"]
    else:
        # try confusion-matrix CSV header next to meta
        cm_path = os.path.splitext(meta_path)[0] + ".confusion_matrix.csv"
        if os.path.isfile(cm_path):
            try:
                with open(cm_path, newline="") as cf:
                    reader = csv.reader(cf)
                    header = next(reader, None)
                    if header and len(header) > 1:
                        class_names_list = header[1:]
            except Exception:
                pass
    if class_names_list is None:
        class_names_list = [f"class_{i}" for i in range(len(classes_arr))]
    id2name = {}
    for i, cid in enumerate(classes_arr):
        name = class_names_list[i] if i < len(class_names_list) else str(cid)
        id2name[cid] = name
    return classes_arr, class_names_list, id2name

def load_model_and_meta(model_path, meta_path=None):
    global rf, meta, NEEDED, CLASS_NAMES_LIST, _id2name, _classes_arr, MODEL_PATH, META_PATH
    # infer meta if not provided
    if meta_path is None:
        base, _ = os.path.splitext(model_path)
        candidates = [
            base + ".meta.json",
            base + ".json",
            os.path.join(os.path.dirname(model_path), "meta.json"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                meta_path = c
                break
        if meta_path is None:
            raise FileNotFoundError("Meta JSON not provided and not found next to the model.")

    clf = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        m = json.load(f)

    needed = m.get("feature_columns") or m.get("feature_names") or []
    if not needed:
        raise ValueError("Meta JSON missing feature list (feature_columns/feature_names).")

    classes_arr, class_names_list, id2name = _build_class_mapping(clf, meta_path, m)

    with model_lock:
        rf = clf
        meta = m
        NEEDED = list(needed)
        _classes_arr = list(classes_arr)
        CLASS_NAMES_LIST = list(class_names_list)
        _id2name = dict(id2name)
        MODEL_PATH = model_path
        META_PATH = meta_path

    announce_model()
    try:
        model_status.config(text=f"Loaded: {os.path.basename(model_path)} / {os.path.basename(meta_path)}")
        start_button.config(state=tk.NORMAL)
    except Exception:
        pass

def choose_model_and_meta():
    model_path = filedialog.askopenfilename(
        title="Select model (.pkl)",
        filetypes=[("Pickle model", "*.pkl"), ("All files", "*.*")]
    )
    if not model_path:
        return

    # Try to guess meta next to the model
    base, _ = os.path.splitext(model_path)
    guesses = [base + ".meta.json", base + ".json", os.path.join(os.path.dirname(model_path), "meta.json")]
    meta_path = next((g for g in guesses if os.path.isfile(g)), None)
    if meta_path is None:
        meta_path = filedialog.askopenfilename(
            title="Select meta JSON",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not meta_path:
            log_to_file("Model chosen but meta JSON not provided; load cancelled.")
            return

    try:
        load_model_and_meta(model_path, meta_path)
        log_to_file(f"[i] Loaded model: {model_path}")
        log_to_file(f"[i] Loaded meta : {meta_path}")
    except Exception as e:
        log_to_file(f"[FATAL] Loading error: {e}")

# --------- Feature vector builder ----------
def _ensure_feature_vector(flow_feat: dict) -> np.ndarray:
    # snapshot needed under lock
    with model_lock:
        needed = list(NEEDED)
    row = []
    for want in needed:
        key = canon(want)
        if key in flow_feat:
            row.append(float(flow_feat[key]))
        else:
            row.append(0.0)
            if want not in warned_missing:
                warned_missing.add(want)
                log_to_file(f"[warn] Feature '{want}' not computed live; filling 0.")
    return np.array(row, dtype=np.float32).reshape(1, -1)

# --------- Flow handling ----------
def _flow_key(packet):
    src = packet[IP].src
    dst = packet[IP].dst
    proto = packet[IP].proto
    sport = 0
    dport = 0
    if TCP in packet:
        sport = int(packet[TCP].sport); dport = int(packet[TCP].dport)
    elif UDP in packet:
        sport = int(packet[UDP].sport); dport = int(packet[UDP].dport)
    return (src, dst, proto, sport, dport)

def _reverse_key(key):
    (src, dst, proto, sport, dport) = key
    return (dst, src, proto, dport, sport)

def process_packet(packet):
    # ensure model present
    with model_lock:
        clf = rf
        classes = list(_classes_arr)
        id2name_local = dict(_id2name)
    if clf is None:
        return

    try:
        if IP not in packet:
            return
        dst_port = int(packet[TCP].dport) if TCP in packet else (int(packet[UDP].dport) if UDP in packet else 0)
        flags = int(packet[TCP].flags) if TCP in packet else None

        # Heuristics
        _portscan_heuristic(packet, dst_port)
        _syn_rate_heuristic(flags, packet[IP].src if IP in packet else None)

        # Flow keys: forward/reverse
        fwd_key = _flow_key(packet)
        rev_key = _reverse_key(fwd_key)

        if fwd_key in flows:
            key = fwd_key; is_fwd = True
        elif rev_key in flows:
            key = rev_key; is_fwd = False
        else:
            key = fwd_key; is_fwd = True
            flows[key] = FlowStats(initiator_src=packet[IP].src)

        fl = flows[key]
        length = len(packet)
        fl.update(length=length, is_fwd=is_fwd, flags=flags)

        # prediction (with warm-up)
        fdict = fl.as_features()
        total_pkts = int(fdict.get("Total Fwd Packets", 0) + fdict.get("Total Backward Packets", 0))
        dur_us = float(fdict.get("Flow Duration", 0.0))
        label_txt = None
        prob_txt = ""
        if total_pkts >= WARMUP_MIN_PKTS or dur_us >= WARMUP_MIN_DUR_US:
            x = _ensure_feature_vector(fdict)
            if hasattr(clf, "predict_proba"):
                probs = clf.predict_proba(x)[0]
                top_idx = int(np.argmax(probs))
                top_cid = classes[top_idx] if classes else top_idx
                label_txt = id2name_local.get(top_cid, str(top_cid))
                prob_txt = f" (p={float(probs[top_idx]):.2f})"
            else:
                pred_cid = clf.predict(x)[0]
                label_txt = id2name_local.get(pred_cid, str(pred_cid))

        # overlay if a heuristic is currently hot
        overlay = current_overlay_label()
        if overlay:
            label_txt = overlay

        # Print log
        summary = packet.summary()
        if label_txt:
            log_to_file(f"{summary} - {label_txt}{prob_txt}")
        else:
            log_to_file(summary)

    except Exception as e:
        log_to_file(f"Error processing packet: {e}")

# --------- Heuristics ----------
def _portscan_heuristic(packet, dst_port):
    if IP not in packet:
        return
    now = seconds()
    src = packet[IP].src
    dq = scan_windows[src]
    dq.append((now, int(dst_port)))
    while dq and dq[0][0] < now - PORTSCAN_WINDOW_SEC:
        dq.popleft()
    uniq = {p for (_, p) in dq if p > 0}
    if len(uniq) >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
        last = last_scan_alert_ts.get(src, 0)
        if now - last >= PORTSCAN_WINDOW_SEC:
            last_scan_alert_ts[src] = now
            log_to_file(f"Manual Alert: Likely PortScan from {src} (unique dst ports in {PORTSCAN_WINDOW_SEC:.1f}s: {len(uniq)})")
            set_heuristic("PortScan")

def _syn_rate_heuristic(flags, src_ip=None):
    if flags is not None and (flags & 0x02):
        now = seconds()
        syn_times.append(now)
        while syn_times and syn_times[0] < now - SYN_RATE_WINDOW_SEC:
            syn_times.pop(0)
        if len(syn_times) >= SYN_RATE_THRESHOLD:
            log_to_file(f"Manual Alert: High SYN rate ({len(syn_times)}/s) - Possible DDoS!")
            set_heuristic("DDoS")

# --------- Synthetic server replies (Replay mode only) ----------
def synth_server_replies(pkt):
    if not USE_SYNTH_REPLIES:
        return
    if IP not in pkt:
        return
    ip = pkt[IP]
    proto = ip.proto
    if proto != 6 or TCP not in pkt:
        return

    src = ip.src; dst = ip.dst
    sport = int(pkt[TCP].sport); dport = int(pkt[TCP].dport)
    flags = int(pkt[TCP].flags)

    # Baseline reverse IP header
    rip = ScapyIP(src=dst, dst=src, proto=6, ttl=64)

    # Case 1: Client SYN -> server SYN/ACK
    if flags & 0x02 and not (flags & 0x10):
        synack = rip / TCP(sport=dport, dport=sport, flags="SA", seq=1000, ack=1, window=64240)
        process_packet(synack)
        ack = ScapyIP(src=src, dst=dst, proto=6, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=1, ack=1001, window=64240)
        process_packet(ack)
        return

    # Case 2: Client PSH/ACK or ACK -> server ACK
    if flags & 0x10:
        ack_back = rip / TCP(sport=dport, dport=sport, flags="A", seq=2000, ack=2, window=64240)
        process_packet(ack_back)
        if np.random.rand() < SYNTH_DATA_RATIO:
            payload = Raw(b'X' * SYNTH_RESP_SIZE)
            pshack = rip / TCP(sport=dport, dport=sport, flags="PA", seq=2000, ack=2, window=64240) / payload
            process_packet(pshack)
            ack2 = ScapyIP(src=src, dst=dst, proto=6, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=2, ack=2000+SYNTH_RESP_SIZE, window=64240)
            process_packet(ack2)
        return

# --------- Start/Stop and Replay ----------
def start_monitoring():
    global is_sniffing, scan_windows, last_scan_alert_ts, syn_times, flows
    with model_lock:
        if rf is None:
            log_to_file("No model loaded. Click 'Load Model + Meta' first.")
            return
    scan_windows = defaultdict(lambda: deque(maxlen=400))
    last_scan_alert_ts = {}
    syn_times = []
    flows = {}
    iface = iface_combobox.get().strip()
    if not iface or iface == "No interface found":
        log_to_file("No interface selected.")
        return
    is_sniffing = True
    announce_model()
    log_to_file(f"Starting Live IDS (flow, multi-class) on {iface}...")

    def sniff_loop():
        try:
            sniff(iface=iface, prn=process_packet, stop_filter=lambda p: not is_sniffing, store=0)
        except PermissionError:
            log_to_file("Sniffing Error: Permission denied. Run with sudo.")
        except Exception as e:
            log_to_file(f"Sniffing Error: {e}")

    threading.Thread(target=sniff_loop, daemon=True).start()

def stop_monitoring():
    global is_sniffing
    is_sniffing = False
    log_to_file("Stopped monitoring.")
    # Final per-flow summary
    try:
        shown = 0
        for key, fl in list(flows.items()):
            if shown >= SUMMARY_MAX:
                log_to_file(f"[flow-summary] ... truncated; {len(flows)-SUMMARY_MAX} more flows omitted")
                break
            fdict = fl.as_features()
            x = _ensure_feature_vector(fdict)
            with model_lock:
                clf = rf
                classes = list(_classes_arr)
                id2name_local = dict(_id2name)
            if clf is None:
                break
            if hasattr(clf, "predict_proba"):
                probs = clf.predict_proba(x)[0]
                top_idx = int(np.argmax(probs))
                top_cid = classes[top_idx] if classes else top_idx
                name = id2name_local.get(top_cid, str(top_cid))
                p = float(probs[top_idx])
            else:
                pred_cid = clf.predict(x)[0]
                name = id2name_local.get(pred_cid, str(pred_cid)); p = 1.0
            total_pkts = int(fdict.get("Total Fwd Packets", 0) + fdict.get("Total Backward Packets", 0))
            dur_ms = fdict.get("Flow Duration", 0.0) / 1000.0
            overlay = current_overlay_label()
            disp_name = overlay if overlay else name
            log_to_file(f"[flow-summary] {key} pkts={total_pkts} dur_ms={dur_ms:.1f} -> {disp_name} (p={p:.2f})")
            shown += 1
    except Exception as e:
        log_to_file(f"[summary error] {e}")

def replay_traffic():
    """
    Replay from a PACKET-LEVEL CSV:
      required columns:
        src_ip,dst_ip,protocol,time_to_live,src_port,dst_port,
        tcp_flags,seq_num,ack_num,window_size,packet_size
    """
    global is_sniffing, scan_windows, last_scan_alert_ts, syn_times, flows
    with model_lock:
        if rf is None:
            log_to_file("No model loaded. Click 'Load Model + Meta' first.")
            return
    path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if not path:
        log_to_file("Replay: no file selected.")
        return

    scan_windows = defaultdict(lambda: deque(maxlen=400))
    last_scan_alert_ts = {}
    syn_times = []
    flows = {}
    is_sniffing = True
    announce_model()
    log_to_file(f"Replaying traffic from {path} ...")

    def do_replay():
        try:
            df = pd.read_csv(path)
            required = [
                "src_ip","dst_ip","protocol","time_to_live","src_port","dst_port",
                "tcp_flags","seq_num","ack_num","window_size","packet_size"
            ]
            missing = [c for c in required if c not in df.columns]
            if missing:
                log_to_file(f"Replay Error: CSV missing columns: {missing}")
                return

            for _, row in df.iterrows():
                if not is_sniffing:
                    break

                pkt = ScapyIP(
                    src=row.get('src_ip', '0.0.0.0'),
                    dst=row.get('dst_ip', '0.0.0.0'),
                    proto=int(row.get('protocol', 6)),
                    ttl=int(row.get('time_to_live', 64))
                )
                proto = int(row.get('protocol', 6))
                if proto == 6:
                    pkt = pkt / TCP(
                        sport=int(row.get('src_port', 0)),
                        dport=int(row.get('dst_port', 0)),
                        flags=int(row.get('tcp_flags', 0)),
                        seq=int(row.get('seq_num', 0)),
                        ack=int(row.get('ack_num', 0)),
                        window=int(row.get('window_size', 0))
                    )
                elif proto == 17:
                    pkt = pkt / UDP(
                        sport=int(row.get('src_port', 0)),
                        dport=int(row.get('dst_port', 0))
                    )

                desired = int(row.get('packet_size', 0))
                delta = max(0, desired - len(pkt))
                if delta > 0:
                    pkt = pkt / Raw(b'\x00' * delta)

                # Feed forward packet
                process_packet(pkt)
                # Inject synthetic reverse responses
                synth_server_replies(pkt)

                
                time.sleep(0.0002)
        except Exception as e:
            log_to_file(f"Replay Error: {e}")
        finally:
            stop_monitoring()

    threading.Thread(target=do_replay, daemon=True).start()

# ---------------- GUI ----------------
root = tk.Tk()
root.title("AI-Driven IDS (Flow, Multi-class)")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

label = tk.Label(frame, text="AI-Driven IDS (Flow, Multi-class)", font=("Helvetica", 15))
label.pack(pady=8)

# Model status + load button
model_status = tk.Label(frame, text="No model loaded")
model_status.pack(pady=(0,6))

load_btn = tk.Button(frame, text="Load Model + Meta", command=choose_model_and_meta)
load_btn.pack(pady=4)

iface_label = tk.Label(frame, text="Select Network Interface:")
iface_label.pack()

try:
    interfaces = get_if_list() or []
except Exception as e:
    interfaces = []
    print(f"[WARN] Could not list interfaces: {e}")

default_iface = "lo"
for cand in interfaces:
    if cand not in ("lo",):
        default_iface = cand
        break

iface_combobox = ttk.Combobox(frame, values=interfaces if interfaces else ["No interface found"], width=50, state="readonly")
iface_combobox.pack(pady=5)
iface_combobox.set(default_iface if interfaces else "No interface found")

start_button = tk.Button(frame, text="Start Live Monitoring", command=start_monitoring, bg="green", fg="white", state=tk.DISABLED)
start_button.pack(pady=5)

stop_button = tk.Button(frame, text="Stop Monitoring", command=stop_monitoring, bg="red", fg="white")
stop_button.pack(pady=5)

replay_button = tk.Button(frame, text="Replay Traffic (CSV)", command=replay_traffic, bg="blue", fg="white")
replay_button.pack(pady=5)

def toggle_theme():
    bg_now = frame.cget('bg')
    dark = (bg_now != 'black')
    new_bg = 'black' if dark else 'white'
    new_fg = 'white' if dark else 'black'
    for w in (frame, label, iface_label, output_text, model_status):
        try:
            w.config(bg=new_bg, fg=new_fg)
        except:
            pass

theme_button = tk.Button(frame, text="Toggle Dark/Light Mode", command=toggle_theme)
theme_button.pack(pady=5)

output_text = tk.Text(frame, height=22, width=110, bg='white', fg='black')
output_text.pack()

# Initial theme
frame.config(bg='white'); label.config(bg='white', fg='black'); iface_label.config(bg='white', fg='black'); model_status.config(bg='white', fg='black')

# Try to load defaults; if not present, keep app open and wait for button
try:
    load_model_and_meta(MODEL_PATH, META_PATH)
except Exception as e:
    log_to_file(f"[WARN] Default model/meta not loaded: {e}")
    model_status.config(text="No model loaded (use 'Load Model + Meta')")

root.mainloop()
