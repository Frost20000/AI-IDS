import sys, importlib, platform
print(f"Python: {sys.version.split()[0]}  on  {platform.system()} {platform.machine()}")
mods = ["numpy","pandas","sklearn","matplotlib","joblib"]
missing=[]
for m in mods:
    try:
        importlib.import_module(m)
        print(f"[OK] {m} import")
    except ImportError:
        print(f"[MISSING] {m}")
        missing.append(m)
if missing:
    print("\nInstall missing packages:\n  pip install -r requirements.txt")
    sys.exit(1)
print("\nEnvironment looks good.")
