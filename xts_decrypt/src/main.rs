use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::time::Instant;

fn gf128_mul2(tweak: &mut [u8; 16]) {
    let mut carry = 0u8;
    for b in tweak.iter_mut() {
        let new_carry = *b >> 7;
        *b = (*b << 1) | carry;
        carry = new_carry;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

fn xor16(dst: &mut [u8; 16], src: &[u8; 16]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

fn decrypt_sector(
    dec_cipher: &Aes256,
    tweak_cipher: &Aes256,
    sector_num: u64,
    data: &mut [u8],
) {
    // Encrypt sector number to get initial tweak
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_num.to_le_bytes());
    let tweak_block: &mut aes::Block = (&mut tweak).into();
    tweak_cipher.encrypt_block(tweak_block);

    for chunk in data.chunks_exact_mut(16) {
        let block: &mut [u8; 16] = chunk.try_into().unwrap();
        xor16(block, &tweak);
        let aes_block: &mut aes::Block = block.into();
        dec_cipher.decrypt_block(aes_block);
        xor16(block, &tweak);
        gf128_mul2(&mut tweak);
    }
}

fn parse_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 7 {
        eprintln!(
            "Usage: {} <input> <output> <data_key_hex> <tweak_key_hex> <lba_start> <num_sectors>",
            args[0]
        );
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];
    let data_key: [u8; 32] = parse_hex(&args[3]).try_into().unwrap();
    let tweak_key: [u8; 32] = parse_hex(&args[4]).try_into().unwrap();
    let lba_start: u64 = args[5].parse().unwrap();
    let num_sectors: u64 = args[6].parse().unwrap();

    let dec_cipher = Aes256::new((&data_key).into());
    let tweak_cipher = Aes256::new((&tweak_key).into());

    // Verify first sector
    {
        let mut f = File::open(input_path)?;
        f.seek(SeekFrom::Start(lba_start * 512))?;
        let mut buf = [0u8; 512];
        f.read_exact(&mut buf)?;
        decrypt_sector(&dec_cipher, &tweak_cipher, lba_start, &mut buf);
        if &buf[3..7] != b"NTFS" {
            eprintln!("ERROR: verification failed, first 16 bytes: {:02x?}", &buf[..16]);
            std::process::exit(1);
        }
        eprintln!("[+] Verification OK (NTFS signature found)");
    }

    let mut fin = BufReader::with_capacity(4 * 1024 * 1024, File::open(input_path)?);
    let mut fout = BufWriter::with_capacity(4 * 1024 * 1024, File::create(output_path)?);

    // Copy pre-partition data as-is
    let pre_size = (lba_start * 512) as usize;
    let mut pre_buf = vec![0u8; pre_size];
    fin.read_exact(&mut pre_buf)?;
    fout.write_all(&pre_buf)?;
    drop(pre_buf);

    // Decrypt in 4MB batches
    let batch_sectors: u64 = 8192;
    let mut buf = vec![0u8; (batch_sectors * 512) as usize];
    let mut done: u64 = 0;
    let start = Instant::now();

    while done < num_sectors {
        let count = std::cmp::min(batch_sectors, num_sectors - done);
        let bytes = (count * 512) as usize;
        fin.read_exact(&mut buf[..bytes])?;

        for i in 0..count {
            let sector_num = lba_start + done + i;
            let off = (i * 512) as usize;
            decrypt_sector(&dec_cipher, &tweak_cipher, sector_num, &mut buf[off..off + 512]);
        }

        fout.write_all(&buf[..bytes])?;
        done += count;

        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let speed = (done * 512) as f64 / elapsed / 1_048_576.0;
            let pct = done as f64 / num_sectors as f64 * 100.0;
            let eta = (num_sectors - done) as f64 * 512.0 / (speed * 1_048_576.0);
            eprint!(
                "\r  [{:5.1}%] {}/{} sectors, {:.1} MB/s, ETA {:.0}s   ",
                pct, done, num_sectors, speed, eta
            );
        }
    }

    fout.flush()?;
    let elapsed = start.elapsed().as_secs_f64();
    let total_gb = (num_sectors * 512) as f64 / 1_073_741_824.0;
    let speed = total_gb / elapsed * 1024.0;
    eprintln!(
        "\n[+] Done! {:.2} GB in {:.1}s ({:.1} MB/s)",
        total_gb, elapsed, speed
    );
    Ok(())
}
