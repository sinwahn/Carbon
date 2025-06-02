import ida_typeinf
import ida_name
import ida_idaapi
import idautils
import idc

import idc
import idautils
import os

SCRIPT_DIR = os.path.dirname(__file__)
DUMP_FILE = os.path.join(SCRIPT_DIR, "dumpresult.txt")
LUA_HEADER = os.path.join(SCRIPT_DIR, "lua.h")
LUALIB_HEADER = os.path.join(SCRIPT_DIR, "lualib.h")

def parse_lua_header(file_path):
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' not found.")
        return []

    with open(file_path, 'r') as f:
        content = f.read()

    # Simplify Lua macros
    content = content.replace('LUALIB_API', '').replace('LUA_API', '').replace('l_noret', 'void')
    lines = content.splitlines()
    declarations = {}
    inside_struct = False

    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('/*'):
            continue
        
        # Skip structs
        if line.startswith('struct'):
            inside_struct = True
            continue
        if inside_struct and line.endswith('};'):
            inside_struct = False
            continue
        if inside_struct:
            continue
        
        # Skip typedefs
        if line.startswith('typedef'):
            continue
        
        # Detect function declarations
        if line.endswith(');') and '(' in line and ')' in line and '(*' not in line:
            func_name = line.split('(')[0].strip().split()[-1].replace('*', '')
            declarations[func_name] = line

    return declarations

def find_lua_functions():
    """Find Lua-like functions in IDA's function list."""
    lua_functions = {}
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if name.startswith(("lua_", "luaL_", "lauxlib_")) or name == "lua_Alloc":
            lua_functions[name] = ea
            print(f"[INFO] Detected Lua function: {name} @ 0x{ea:X}")
    return lua_functions


def apply_type_info(callee_name, callee_prototype_decl):
    til = ida_typeinf.get_idati()
    parse_result = ida_typeinf.idc_parse_decl(til, callee_prototype_decl, ida_typeinf.PT_REPLACE)
    if parse_result is None:
        print("Failed to parse declaration.")
        return

    name, types, fields, *rest = parse_result
    tif = ida_typeinf.tinfo_t()
    if not tif.deserialize(til, types, fields):
        print("Failed to deserialize type info.")
        return

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, callee_name)
    if ea == ida_idaapi.BADADDR:
        print(f"{callee_name} function not found.")
        return
    
    if idc.apply_type(ea, parse_result, idc.TINFO_DEFINITE):
        print(f"Applied type info @ {ea} '{tif}'")
    else:
        print(f"Could not apply type info @ {ea} '{tif}'")

    for xref in idautils.CodeRefsTo(ea, 0):
        if not ida_typeinf.apply_callee_tinfo(xref, tif):
            print(f"Could not apply type info @ {xref:x}")

declarations = {}
declarations.update(parse_lua_header(LUA_HEADER))
declarations.update(parse_lua_header(LUALIB_HEADER))

for name, declaration in declarations.items():
    print(f"Function Name: {name}")
    print(f"Declaration: {declaration}")

functionToEa = find_lua_functions()

# Apply types to all identified functions
for name, addr in functionToEa.items():
    type_name = declarations.get(name)
    if type_name:
        if apply_type_info(name, type_name):
            typed_count += 1
    else:
        print(f"[INFO] No type mapping for {name} @ 0x{addr:X}")