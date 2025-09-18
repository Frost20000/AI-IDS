# scripts/validate_data.py
import argparse, os, hashlib, sys
import pandas as pd

EXPECTED = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infiltration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

def sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def norm_col(s: str) -> str:
    # trim BOM + whitespace and lowercase
    return (s or "").replace("\ufeff", "").strip().lower()

def has_label_column(csv_path: str) -> tuple[bool, list[str]]:
    try:
        cols = list(pd.read_csv(csv_path, nrows=0, engine="python").columns)
        normed = [norm_col(c) for c in cols]
        return ("label" in normed), cols
    except Exception as e:
        return False, [f"<error reading header: {e}>"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-dir", required=True, help="Folder with the 8 daily CSVs")
    ap.add_argument("--flows", default=None, help="Optional data/processed/flows.csv to inspect")
    ap.add_argument("--out", default="reports/checksums.txt", help="Checksums output path")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    print(f"[i] Checking raw dir: {args.raw_dir}")
    missing = [f for f in EXPECTED if not os.path.exists(os.path.join(args.raw_dir, f))]
    if missing:
        print("[!] Missing files:")
        for m in missing:
            print("   -", m)
        print("\nDownload the 8 daily CSVs and place them under data/raw/CICIDS2017/")
        sys.exit(2)
    print("[ok] All 8 daily CSVs found.")

    # checksums
    print("[i] Computing checksums...")
    with open(args.out, "w", encoding="utf-8") as out:
        for fname in EXPECTED:
            p = os.path.join(args.raw_dir, fname)
            out.write(f"{fname},{sha256_file(p)}\n")
    print(f"[ok] Wrote checksums to {args.out}")

    # schema checks: ensure each CSV has a Label column (tolerant to spaces/BOM)
    bad = []
    for fname in EXPECTED:
        p = os.path.join(args.raw_dir, fname)
        ok, raw_cols = has_label_column(p)
        if not ok:
            bad.append((fname, raw_cols))
    if bad:
        print("[!] Some CSVs do not expose a 'Label' header after normalization:")
        for fname, cols in bad:
            print(f"   - {fname}: header = {cols[:12]}{' ...' if len(cols) > 12 else ''}")
        print("    (Common cause: header named ' Label' with a leading space or BOM.)")
        sys.exit(3)
    else:
        print("[ok] 'Label' header detected (after normalization) in all CSVs.")

    # optional flows.csv checks
    if args.flows and os.path.exists(args.flows):
        print(f"[i] Inspecting flows: {args.flows}")
        try:
            df = pd.read_csv(args.flows)
            if "Label" not in df.columns:
                # also accept normalized name in case upstream code changed
                if "label" not in [c.lower() for c in df.columns]:
                    print("[!] flows.csv missing 'Label' column.")
                    sys.exit(4)
            print("[ok] flows.csv has Label.")
            print("[i] Class distribution (top):")
            print(df["Label"].value_counts().head(20))
            print("[ok] flows.csv rows:", len(df))
        except Exception as e:
            print(f"[!] Could not read flows.csv: {e}")
            sys.exit(5)
    else:
        print("[i] flows.csv not provided; run data_prep to generate it.")

if __name__ == "__main__":
    main()
