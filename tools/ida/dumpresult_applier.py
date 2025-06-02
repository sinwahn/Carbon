import idc
import idaapi
import os

SCRIPT_DIR = os.path.dirname(__file__)
INPUT_FILE = os.path.join(SCRIPT_DIR, "data/dumpresult.txt")

def apply_names_from_file(path):
    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path}")
        return

    base = idaapi.get_imagebase()
    count = 0

    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or '=' not in line or '|' not in line:
                continue  # skip malformed lines

            try:
                name_part, rest = line.split('=', 1)
                addr_str, _ = rest.split('|', 1)
                name = name_part.strip()
                addr = int(addr_str, 16) + base

                if idc.set_name(addr, name, idc.SN_CHECK):
                    print(f"[OK] {name} @ 0x{addr:X}")
                    count += 1
                else:
                    print(f"[FAIL] Could not name 0x{addr:X} as {name}")
            except Exception as e:
                print(f"[ERROR] Failed to parse line: {line}\n  {e}")

    print(f"Done. Renamed {count} functions.")

# ==== Run it ====
apply_names_from_file(INPUT_FILE)