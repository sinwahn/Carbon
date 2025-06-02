import os
import idaapi
import re

SCRIPT_DIR = os.path.dirname(__file__)
HEADER_FILE = os.path.join(SCRIPT_DIR, "structures.h")

def extract_struct_blocks(text):
    lines = text.splitlines()
    blocks = []
    collecting = False
    brace_level = 0
    current_block = []
    forward_decls = []

    for line in lines:
        stripped = line.strip()

        # Skip empty lines or comments
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            if collecting:
                current_block.append(line)
            continue

        # Collect forward declarations (e.g., "struct X;")
        if not collecting and stripped.startswith("struct ") and stripped.endswith(";") and "{" not in stripped:
            forward_decls.append(line)
            continue

        # Skip simple typedefs without structs
        if not collecting and stripped.startswith("typedef") and ";" in stripped and "{" not in stripped:
            continue

        # Start of struct block
        if not collecting and (
            stripped.startswith("struct ") or
            stripped.startswith("typedef struct")
        ):
            collecting = True
            current_block = forward_decls + [line]  # Include forward declarations
            brace_level = line.count("{") - line.count("}")
            forward_decls = []  # Clear used forward declarations
            continue

        if collecting:
            current_block.append(line)
            brace_level += line.count("{")
            brace_level -= line.count("}")
            if brace_level == 0 and ";" in stripped:
                blocks.append("\n".join(current_block))
                collecting = False
                current_block = []

    # Append any remaining forward declarations as a separate block
    if forward_decls:
        blocks.insert(0, "\n".join(forward_decls))

    return blocks

def parse_struct_block(block, index):
    try:
        result = idaapi.idc_parse_types(block, 0)
        if result == 0:
            print(f"[FAIL] Block #{index} failed:\n{block}\n")
        else:
            print(f"[OK] Block #{index} parsed successfully.")
        return result
    except Exception as e:
        print(f"[ERROR] Block #{index} raised exception: {str(e)}\n{block}\n")
        return 0

def load_structs_safely(header_path):
    if not os.path.isfile(header_path):
        print(f"[ERROR] File not found: {header_path}")
        return

    with open(header_path, "r", encoding="utf-8") as f:
        text = f.read()

    # Try parsing the entire file first
    print("[INFO] Attempting to parse entire header file...")
    if parse_struct_block(text, 0):
        print("[DONE] Entire header file parsed successfully.")
        return

    # If whole-file parsing fails, fall back to splitting
    print("[INFO] Whole-file parsing failed, falling back to block parsing...")
    blocks = extract_struct_blocks(text)
    print(f"[INFO] Found {len(blocks)} struct blocks.")

    ok = 0
    for i, block in enumerate(blocks, 1):
        if parse_struct_block(block, i):
            ok += 1

    print(f"[DONE] Parsed {ok}/{len(blocks)} struct blocks.")

    # If splitting fails for some blocks, try combining problematic blocks
    if ok < len(blocks):
        print("[INFO] Attempting to combine blocks to resolve dependencies...")
        combined_block = "\n".join(blocks)
        if parse_struct_block(combined_block, "combined"):
            print("[DONE] Combined block parsed successfully.")
        else:
            print("[ERROR] Combined block parsing failed.")

load_structs_safely(HEADER_FILE)