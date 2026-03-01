#!/usr/bin/env python3
"""
Write a standard MBR bootstrap that:
1. Finds the active partition in the partition table
2. Loads its first sector (VBR) to 0x7C00
3. Jumps to it

This replaces only the first 440 bytes (boot code area),
preserving the disk signature and partition table.
"""
import struct, sys, os

# Standard MBR bootstrap code (x86 real mode)
# This is a minimal but functional MBR that scans the partition table
# for an active (0x80) entry, loads that partition's first sector to 0x7C00,
# and jumps to it.
asm = bytearray([
    # 0x0000: cli; xor ax,ax; mov ds,ax; mov es,ax; mov ss,ax; mov sp,0x7C00; sti
    0xFA,                               # cli
    0x33, 0xC0,                         # xor ax, ax
    0x8E, 0xD8,                         # mov ds, ax
    0x8E, 0xC0,                         # mov es, ax
    0x8E, 0xD0,                         # mov ss, ax
    0xBC, 0x00, 0x7C,                   # mov sp, 0x7C00
    0xFB,                               # sti
    # Relocate from 0x7C00 to 0x0600
    0xBE, 0x00, 0x7C,                   # mov si, 0x7C00
    0xBF, 0x00, 0x06,                   # mov di, 0x0600
    0xB9, 0x00, 0x02,                   # mov cx, 0x200 (512 bytes)
    0xFC,                               # cld
    0xF3, 0xA4,                         # rep movsb
    # Jump to relocated code
    0xEA, 0x1C, 0x00, 0x00, 0x06,      # jmp 0x0600:0x001C (continue after relocation)
    # 0x001C: Scan partition table for active entry
    0xBE, 0xBE, 0x07,                   # mov si, 0x07BE (partition table in relocated MBR at 0x0600+0x1BE)
    0xB3, 0x04,                         # mov bl, 4 (4 partition entries)
    # loop_start (0x0021):
    0x80, 0x3C, 0x80,                   # cmp byte [si], 0x80
    0x74, 0x0E,                         # je found (jump to 0x0033)
    0x83, 0xC6, 0x10,                   # add si, 16
    0xFE, 0xCB,                         # dec bl
    0x75, 0xF5,                         # jnz loop_start (back to 0x0021)
    # No active partition found - print error and halt
    0xBE, 0x6E, 0x00,                   # mov si, offset msg (will be at 0x0600+0x6E)
    0xEB, 0x1A,                         # jmp print_halt
    # found (0x0033): Load VBR using INT 13h
    # Use LBA from partition entry at [si+8]
    0x66, 0x8B, 0x44, 0x08,            # mov eax, [si+8]  (LBA start)
    0x66, 0x0F, 0xB6, 0x0C,            # movzx ecx, byte [si] (drive number from boot flag, should be 0x80)
    # Set up DAP (Disk Address Packet) on stack for INT 13h ext read
    0x66, 0x50,                         # push eax (LBA)
    0x66, 0x6A, 0x00,                   # push dword 0 (upper 32 bits of LBA)
    # Actually, let's use CHS from the partition table for max compatibility
])

# Let me use a simpler, proven approach - just use INT 13h with the CHS values
# from the partition table entry directly, plus LBA fallback via extensions.

# Actually, let me just write a well-known working standard MBR.
# The Windows XP standard MBR code is well-documented. Let me write
# a minimal one that works with INT 13h extensions (LBA mode).

asm2 = bytearray(440)  # 440 bytes of boot code area

code = bytearray([
    # 0x7C00: Set up segments and stack
    0xFA,                               # cli
    0x33, 0xC0,                         # xor ax, ax
    0x8E, 0xD0,                         # mov ss, ax
    0xBC, 0x00, 0x7C,                   # mov sp, 0x7C00
    0x8E, 0xD8,                         # mov ds, ax
    0x8E, 0xC0,                         # mov es, ax
    0xFB,                               # sti
    0xFC,                               # cld
    # Relocate MBR to 0x0600
    0xBE, 0x00, 0x7C,                   # mov si, 0x7C00
    0xBF, 0x00, 0x06,                   # mov di, 0x0600
    0xB9, 0x00, 0x02,                   # mov cx, 512
    0xF3, 0xA4,                         # rep movsb
    # Far jump to continue at relocated address
    # Next instruction will be at offset 0x1B in the code
    0xEA,                               # far jmp
])

jmp_target = len(code) + 4  # +4 for the far jump operand (offset + segment)
code += struct.pack('<HH', jmp_target, 0x0060)  # jmp 0x0060:jmp_target

# After relocation, scan partition table
# Partition table is at 0x0600 + 0x1BE = 0x07BE
scan_start = len(code)
code += bytearray([
    0xBE, 0xBE, 0x07,                  # mov si, 0x07BE
    0xB3, 0x04,                         # mov bl, 4
])

loop_start = len(code)
code += bytearray([
    0x80, 0x3C, 0x80,                  # cmp byte [si], 0x80
    0x74, 0x00,                         # je found (patch later)
    0x83, 0xC6, 0x10,                  # add si, 16
    0xFE, 0xCB,                         # dec bl
    0x75, 0xF5,                         # jnz loop (back to cmp)
])

# Error - no active partition
err_offset = len(code)
code += bytearray([
    0xBE, 0x00, 0x00,                  # mov si, msg_offset (patch later)
])
print_loop = len(code)
code += bytearray([
    0xAC,                               # lodsb
    0x3C, 0x00,                         # cmp al, 0
    0x74, 0xFE,                         # je halt (patch later)
    0xB4, 0x0E,                         # mov ah, 0x0E
    0xBB, 0x07, 0x00,                   # mov bx, 0x0007
    0xCD, 0x10,                         # int 0x10
    0xEB, 0xF2,                         # jmp print_loop
])
halt_offset = len(code)
code += bytearray([
    0xF4,                               # hlt
    0xEB, 0xFD,                         # jmp halt
])

# found: use INT 13h extensions to load VBR
found_offset = len(code)
code += bytearray([
    # Save DL (drive number from BIOS)
    0x88, 0x16, 0x00, 0x00,            # mov [drive_byte], dl (patch later)
    # Build DAP on stack
    0x66, 0x6A, 0x00,                  # push dword 0 (LBA high)
    0x66, 0xFF, 0x74, 0x08,            # push dword [si+8] (LBA low from partition entry)
    0x6A, 0x00,                         # push word 0 (buffer segment=0)  → SI+6,7
    0x68, 0x00, 0x7C,                  # push word 0x7C00 (buffer offset) → SI+4,5
    0x6A, 0x01,                         # push word 1 (sector count)
    0x6A, 0x10,                         # push word 16 (DAP size)
    # Call INT 13h extension
    0x89, 0xE6,                         # mov si, sp (point SI to DAP)
    0xB4, 0x42,                         # mov ah, 0x42
    0x8A, 0x16, 0x00, 0x00,            # mov dl, [drive_byte] (patch later)
    0xCD, 0x13,                         # int 0x13
    0x83, 0xC4, 0x10,                  # add sp, 16 (clean up DAP)
    0x72, 0x00,                         # jc read_error (patch later)
    # Check for valid boot signature
    0x81, 0x3E, 0xFE, 0x7D, 0x55, 0xAA, # cmp word [0x7DFE], 0xAA55
    0x75, 0x00,                         # jne sig_error (patch later)
    # Jump to loaded VBR
    0x8A, 0x16, 0x00, 0x00,            # mov dl, [drive_byte] (patch later)
    0xEA, 0x00, 0x7C, 0x00, 0x00,      # jmp 0x0000:0x7C00
])

# read error handler
read_err = len(code)
code += bytearray([
    0xBE, 0x00, 0x00,                  # mov si, read_err_msg (patch later)
    0xEB, 0x00,                         # jmp print_loop (patch later)
])

# sig error handler  
sig_err = len(code)
code += bytearray([
    0xBE, 0x00, 0x00,                  # mov si, sig_err_msg (patch later)
    0xEB, 0x00,                         # jmp print_loop (patch later)
])

# Messages
msg_no_active = len(code)
code += b'No active partition\x00'
msg_read_err = len(code)
code += b'Disk read error\x00'
msg_sig_err = len(code)
code += b'Missing OS\x00'

# Drive byte storage
drive_byte = len(code)
code += bytearray([0x80])

# Now patch all the forward references
# At loop_start+3: je found -> found_offset
code[loop_start + 4] = (found_offset - (loop_start + 5)) & 0xFF

# At err_offset+1,2: msg address = 0x0600 + msg_no_active
struct.pack_into('<H', code, err_offset + 1, 0x0600 + msg_no_active)

# halt je target (at print_loop+3): je halt
code[print_loop + 4] = (halt_offset - (print_loop + 5)) & 0xFF

# drive_byte references (4 places in found)
for search_start in range(found_offset, found_offset + 80):
    pass

# Patch drive_byte address in "found" section
# mov [drive_byte], dl is at found_offset, bytes +2,+3
struct.pack_into('<H', code, found_offset + 2, 0x0600 + drive_byte)
# mov dl, [drive_byte] for INT 13h call
# Find the pattern 0x8A 0x16 after the INT 13h setup
pos = found_offset + 4
while pos < len(code):
    if code[pos] == 0x8A and code[pos+1] == 0x16:
        struct.pack_into('<H', code, pos + 2, 0x0600 + drive_byte)
        pos += 4
    else:
        pos += 1

# jc read_error: find 0x72 after int 0x13
pos = found_offset
while pos < read_err:
    if code[pos] == 0x72 and code[pos+1] == 0x00:
        code[pos + 1] = (read_err - (pos + 2)) & 0xFF
        break
    pos += 1

# jne sig_error: find 0x75 after cmp
pos = found_offset
while pos < sig_err:
    if code[pos] == 0x75 and code[pos+1] == 0x00 and code[pos-1] == 0xAA:
        code[pos + 1] = (sig_err - (pos + 2)) & 0xFF
        break
    pos += 1

# Patch read_err: mov si, msg; jmp print_loop
struct.pack_into('<H', code, read_err + 1, 0x0600 + msg_read_err)
code[read_err + 4] = (print_loop - (read_err + 5)) & 0xFF

# Patch sig_err: mov si, msg; jmp print_loop
struct.pack_into('<H', code, sig_err + 1, 0x0600 + msg_sig_err)
code[sig_err + 4] = (print_loop - (sig_err + 5)) & 0xFF

print(f"MBR code size: {len(code)} bytes (max 440)")
assert len(code) <= 440, f"Code too large: {len(code)} bytes"

# Pad to 440 bytes
code += bytearray(440 - len(code))

# Now patch the disk image
if len(sys.argv) < 2:
    print("Usage: fix_mbr.py <disk_image>")
    sys.exit(1)
img = os.path.abspath(sys.argv[1])
with open(img, 'r+b') as f:
    # Read existing MBR
    old_mbr = f.read(512)
    # Keep disk signature (440-443) and null (444-445) and partition table (446-511)
    new_mbr = bytes(code) + old_mbr[440:]
    assert len(new_mbr) == 512
    assert new_mbr[510:512] == b'\x55\xAA', "Boot signature missing!"
    # Write new MBR
    f.seek(0)
    f.write(new_mbr)

print("MBR patched successfully!")
print(f"Partition table preserved: {old_mbr[446:462].hex()}")
print(f"Boot signature: {new_mbr[510:512].hex()}")
