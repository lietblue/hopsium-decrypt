# hopsium-decrypt

A simple Python/Rust tool for decrypting Hopsium Mod Boot Loader encrypted disk images.

(No type hints. The bootloader didn't leave any documentation either.)

## Background

The disk is encrypted with **Hopsium Mod Boot Loader** — a modified TrueCrypt bootloader found on arcade/kiosk machines. It uses **AES-256-XTS** with no password; the bootloader decrypts the disk automatically at boot. Only the NTFS partition data is encrypted. The first 63 sectors (MBR + bootloader code) are stored in plaintext.

Standard TrueCrypt and VeraCrypt cannot decrypt it. Hopsium changed the volume header magic from `TRUE` to `Cx?O`, rewrote the key derivation, and hardcoded the master key inside an additionally-encrypted stage 2 bootloader. The only practical way to get the keys is to let the bootloader do its job and take them from memory.

## Requirements

- A disk image you definitely own
- `qemu-system-i386`, `qemu-img`
- Python 3.8+ with `pycryptodome`:
  ```bash
  pip install pycryptodome
  # or via nix:
  nix-shell -p "python3.withPackages(ps: with ps; [pycryptodome])" qemu
  ```
- Rust (for building `xts_decrypt`):
  ```bash
  cd xts_decrypt && cargo build --release
  # binary: xts_decrypt/target/release/xts_decrypt
  ```

## Usage

```bash
# Step 1: extract keys
python3 extract_keys.py wlf.vdi          # supports .vdi / .raw / .img

# Step 2: decrypt
qemu-img convert -f vdi -O raw wlf.vdi wlf.raw
cd xts_decrypt && cargo build --release && cd ..
./xts_decrypt/target/release/xts_decrypt \
    wlf.raw wlf.decrypted.raw \
    <data_key_hex> <tweak_key_hex> \
    <lba_start> <num_sectors>            # values from .keys file

# Step 3: fix MBR
python3 fix_mbr.py wlf.decrypted.raw

# Boot
qemu-system-i386 -m 512 -hda wlf.decrypted.raw -rtc base=localtime
```

## How it works

### Step 1 — `extract_keys.py`: boots a VM to steal keys from memory

QEMU boots the encrypted image in snapshot mode (no writes to disk). The Hopsium bootloader auto-decrypts and loads the cipher context into memory. After 15 seconds we send a `pmemsave` command over QMP and dump `0x90000–0xA0000`.

Inside the dump we search for the decrypted TrueCrypt volume header signature `Cx?O` at offset +0x10. The cipher context lives at `base + 0x5200`:

| Offset | Content |
|--------|---------|
| `+0x0004` | Data key (32 bytes) |
| `+0x01EC` | Tweak key (32 bytes) |

Keys are verified by decrypting the first NTFS sector and checking for the `NTFS` OEM ID. Output is written to `<image>.keys`:

```json
{
  "data_key": "5ebe8c36...",
  "tweak_key": "34e1bb44...",
  "algorithm": "AES-256-XTS",
  "partition_lba_start": 63,
  "partition_sectors": 58621122,
  "verified": true
}
```

### Step 2 — `xts_decrypt`: AES-256-XTS, the boring part

Build the binary first:

```bash
cd xts_decrypt && cargo build --release
```

The Rust binary decrypts sector by sector. For each sector, the tweak is `AES-ECB(tweak_key, sector_number_le128)`. Each 16-byte block: XOR → decrypt → XOR. The first 63 sectors (MBR region) are copied as-is without decryption.

Performance: ~400 MB/s. 28 GB takes about 72 seconds.

### Step 3 — `fix_mbr.py`: replaces bootloader with something that actually works

The decrypted image still has Hopsium bootloader code in the first 63 sectors. It will try to decrypt an already-decrypted disk and hang. `fix_mbr.py` overwrites only the first 440 bytes (boot code area) with a standard MBR bootstrap, preserving bytes 440–511 (disk signature + partition table + `0x55AA`).

The replacement bootstrap:
1. Relocates itself from `0x7C00` to `0x0600`
2. Scans the partition table for the active (`0x80`) entry
3. Loads its VBR to `0x7C00` via INT 13h extensions (LBA mode)
4. Verifies `0x55AA` and jumps

## Mounting without booting

```bash
# offset = lba_start(63) × sector_size(512) = 32256
udisksctl loop-setup -f wlf.decrypted.raw
udisksctl mount -b /dev/loop0p1
```

## Files

| File | Description |
|------|-------------|
| `extract_keys.py` | Boot QEMU, dump memory, extract AES-256-XTS keys |
| `xts_decrypt/` | Rust AES-256-XTS decryptor (`cargo build --release`) |
| `fix_mbr.py` | Replace Hopsium bootloader with standard MBR bootstrap |
| `*.keys` | Extracted key file (JSON) |
