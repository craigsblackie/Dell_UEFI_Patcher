# Dell BIOS Surgical Patcher (IBB-Safe)

A specialized Python utility designed for surgical modification of Dell UEFI BIOS binaries. This tool automates the discovery of **Intel Boot Guard (BtG)** protected ranges and identifies specific VarStore (Setup) offsets for modification, ensuring that patches are only applied to "Safe" (unverified) regions of the flash.

Thie was primarily created for the purpose of disabling pre-boot DMA without requiring the UEFI BIOS password or triggering the requirement for the recovery key. It was tested successfully on a Dell Optiplex 3000 with UEFI version 1.23.2. This was vibe-coded and works for me, YMMV. 

## 🛡️ The "Safety" Problem
Modern Dell systems employ Intel Boot Guard. The CPU verifies the hash of the **Initial Boot Block (IBB)** before execution. Modifying even a single bit within this range will cause a verification failure, resulting in the device not powering on or POST).

This tool solves this by:
1. **Programmatically parsing the FIT** (Firmware Interface Table) to find the exact IBB boundaries for *your specific* dump.
2. **Validating every patch address** against these boundaries before writing.
3. **Providing a "Force" override** only if the user explicitly acknowledges the risk of a brick.

## ✨ Key Features
*   **Size-Agnostic:** Works with 8MB, 16MB, 32MB, and 64MB full-flash dumps.
*   **FIT Discovery:** Automatically locates the `_FIT_` signature and parses Type 0x07 (IBB) entries.
*   **Surgical Search:** Scans for VarStore headers using GUID + Name signatures (Default: `Setup`).
*   **Dependency Mapping:** Specifically configured to target the "IOMMU Pre-boot Behavior" bit (Offset `0x812`), critical for disabling DMA protection.

## 🚀 Usage

### 1. Analysis Mode (Safe)
Scan a BIOS dump to see where the setting is located and whether it is safe to patch:
```bash
python3 dell_bios_patcher.py bios_dump.bin
```

### 2. Apply Patch
Generate a new binary with the setting disabled (set to `0x00`) in safe areas:
```bash
python3 dell_bios_patcher.py bios_dump.bin patched.bin --apply
```

### 3. Advanced Customization
Target a different setting or GUID by providing custom hex strings:
```bash
python3 dell_bios_patcher.py dump.bin --guid <HEX_GUID> --offset 0x45F --name <HEX_NAME>
```

## 🛠️ Technical Details
The tool uses a multi-strategy approach to locate the FIT:
1. **Architectural Pointer:** Checks `4GB - 0x40` relative to the file size (standard for full flash dumps).
2. **Signature Search:** Scans the binary for the `_FIT_   ` magic string if the pointer is missing or obscured.

Once the IBB range is identified (FIT Type 0x07), the script maps the UEFI memory addresses (e.g., `0xFFF60000`) back to the physical file offsets in your dump to create a "No-Fly Zone" for patches.

## ⚠️ Disclaimer
**WARNING:** BIOS modification is inherently risky. While this tool includes safety checks to prevent Intel Boot Guard triggers, it cannot guarantee that the modified BIOS logic will function as intended. Always have a hardware programmer (like a CH341A) and a verified backup of your original dump before proceeding.

