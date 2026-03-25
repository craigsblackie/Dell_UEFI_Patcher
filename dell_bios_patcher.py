import os
import argparse
import sys

# --- DEFAULT CONFIGURATION ---
# Default Setup VarStore GUID: EC87D643-EBA4-4BB5-A1E5-3F3E36B20DA9
DEFAULT_GUID_HEX = "43D687ECA4EBB54BA1E53F3E36B20DA9"
# Default Name: "Setup" in UTF-16LE + Null terminator
DEFAULT_NAME_HEX = "530065007400750070000000"
# Pre-boot DMA setting on Dell Optiplex 3000, 0x975 on the XPS 15 9560
DEFAULT_OFFSET = 0x812

def find_ibb_range(data):
    """Programmatically find the IBB safety range using the FIT (Firmware Interface Table)."""
    flash_size = len(data)
    
    # Strategy 1: Look at the architectural pointer relative to ACTUAL file size
    # This assumes the file is a full flash dump meant to end at 4GB (0xFFFFFFFF)
    fit_ptr_offset = flash_size - 0x40
    if fit_ptr_offset > 0:
        fit_addr = int.from_bytes(data[fit_ptr_offset:fit_ptr_offset+4], 'little')
        # Map assuming this file ends at 0xFFFFFFFF
        fit_offset = fit_addr - (0x100000000 - flash_size)
        if 0 <= fit_offset < flash_size and data[fit_offset:fit_offset+8] == b'_FIT_   ':
            print(f"[*] FIT found via architectural pointer at offset 0x{fit_offset:08X}.")
            return parse_fit(data, fit_offset, flash_size)

    # Strategy 2: Direct signature search (robust for non-standard dumps)
    fit_offset = data.rfind(b'_FIT_   ')
    if fit_offset != -1:
        print(f"[*] FIT found via signature search at offset 0x{fit_offset:08X}.")
        return parse_fit(data, fit_offset, flash_size)
            
    print("[!] No FIT signature found.")
    return None

def parse_fit(data, fit_offset, mapping_size):
    """Helper to parse FIT entries once the table is located."""
    flash_size = len(data)
    num_entries = int.from_bytes(data[fit_offset+8:fit_offset+11], 'little')
    print(f"[*] Parsing FIT with {num_entries} entries.")

    for i in range(1, num_entries):
        entry_off = fit_offset + (i * 16)
        if entry_off + 16 > flash_size:
            break
            
        ent_type = data[entry_off + 14] & 0x7F
        
        if ent_type == 0x07: # IBB Entry
            ibb_addr = int.from_bytes(data[entry_off:entry_off+8], 'little')
            ibb_size_raw = int.from_bytes(data[entry_off+8:entry_off+11], 'little')
            ibb_size = ibb_size_raw * 16
            
            # Map address back to file offset
            ibb_start = ibb_addr - (0x100000000 - mapping_size)
            ibb_end = ibb_start + ibb_size
            
            print(f"[*] Detected IBB Range: 0x{ibb_start:08X} - 0x{ibb_end:08X} (Size: 0x{ibb_size:X})")
            return (ibb_start, ibb_end)
    return None

def patch_bios(input_file, output_file, apply_patch, force_unsafe, target_guid_hex, target_name_hex, target_offset):
    print(f"[*] Starting BIOS Analysis for {input_file}...")
    
    if not os.path.exists(input_file):
        print(f"[!] Error: File '{input_file}' not found.")
        return

    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    # --- Step 1: Discover IBB Range ---
    ibb_range = find_ibb_range(data)
    if ibb_range:
        ibb_start, ibb_end = ibb_range
    else:
        # Fallback to hardcoded defaults if FIT discovery fails
        print("[!] Falling back to default IBB safety boundaries.")
        ibb_start, ibb_end = 0x01F60000, 0x02000000

    def is_safe(addr):
        """Check if an address is outside the IBB protected range."""
        return not (ibb_start <= addr < ibb_end)

    # --- Step 2: Search for Target Header ---
    try:
        header_pattern = bytes.fromhex(target_guid_hex) + bytes.fromhex(target_name_hex)
    except ValueError as e:
        print(f"[!] Error parsing GUID or Name hex: {e}")
        return

    print(f"[*] Searching for VarStore Header: {target_guid_hex[:8]}... (Offset 0x{target_offset:X})")
    
    idx = data.find(header_pattern)
    counts = {"safe": 0, "unsafe": 0}

    if idx == -1:
        print("[!] Target VarStore header not found.")
        return

    # Header size is GUID (16) + Name (variable)
    header_size = len(header_pattern)

    while idx != -1:
        body_base = idx + header_size
        addr = body_base + target_offset
        
        if addr >= len(data):
            print(f"  [!] Calculated address 0x{addr:08X} is out of bounds.")
            idx = data.find(header_pattern, idx + 1)
            continue

        val = data[addr]
        print(f"  [*] Found VarStore at 0x{idx:08X}. Target byte at 0x{addr:08X} is 0x{val:02X}")

        if val != 0x00:
            if is_safe(addr) or force_unsafe:
                status = "[SAFE]" if is_safe(addr) else "[!!! UNSAFE !!!]"
                print(f"    {status} Patching at 0x{addr:08X}: 0x{val:02X} -> 00")
                if apply_patch:
                    data[addr] = 0x00
                    counts["safe"] += 1
                else:
                    counts["safe"] += 1 # In analysis mode, we count potential patches
            else:
                print(f"    [SKIPPED] Address 0x{addr:08X} is IBB PROTECTED.")
                counts["unsafe"] += 1
        else:
            print(f"    [INFO] Byte at 0x{addr:08X} is already 0x00.")

        idx = data.find(header_pattern, idx + 1)

    # --- FINAL SUMMARY ---
    print("\n" + "="*60)
    print("PATCH SUMMARY")
    print("-" * 60)
    print(f"Target GUID: {target_guid_hex}")
    print(f"Target Offset: 0x{target_offset:X}")
    print(f"Safe Points Found:           {counts['safe']}")
    print(f"IBB Protected Points:        {counts['unsafe']}")
    print("=" * 60)

    if apply_patch:
        if counts["unsafe"] > 0 and not force_unsafe:
            print("\n[!] WARNING: IBB Protected areas were found. Only safe areas were patched.")
        
        if counts["safe"] > 0:
            print(f"\n[*] Writing patched file to {output_file}...")
            with open(output_file, 'wb') as f:
                f.write(data)
            print("[*] DONE.")
        else:
            print("\n[!] No safe patches were applied. File not written.")
    else:
        print("\n[*] Analysis complete. Run with '--apply' to generate the binary.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Programmatic Dell BIOS Patcher with IBB Safety")
    parser.add_argument("input", help="Input BIOS binary")
    parser.add_argument("output", nargs="?", default="PATCHED_SAFE.BIN", help="Output filename")
    parser.add_argument("--apply", action="store_true", help="Apply patches to safe areas")
    parser.add_argument("--force-unsafe", action="store_true", help="Patch even IBB protected areas (WILL BRICK)")
    
    # Custom search parameters
    parser.add_argument("--guid", default=DEFAULT_GUID_HEX, help=f"Hex string of the VarStore GUID (Default: {DEFAULT_GUID_HEX})")
    parser.add_argument("--name", default=DEFAULT_NAME_HEX, help=f"Hex string of the VarStore Name (Default: {DEFAULT_NAME_HEX})")
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=DEFAULT_OFFSET, help=f"Offset from VarStore body start (Default: 0x{DEFAULT_OFFSET:X})")

    args = parser.parse_args()

    patch_bios(args.input, args.output, args.apply, args.force_unsafe, args.guid, args.name, args.offset)
