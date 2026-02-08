#![cfg(windows)]
use sequoia_openpgp::crypto::symmetric::{BlockCipherMode, Decryptor, Encryptor, PaddingMode};
use sequoia_openpgp::crypto::{SessionKey, SymmetricAlgorithm};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::sync::Mutex;

struct LoggingAlloc(Mutex<Vec<Vec<u8>>>);

unsafe impl GlobalAlloc for LoggingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 { System.alloc(layout) }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().unwrap().push(std::slice::from_raw_parts(ptr, layout.size()).to_vec());
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static LEAKS: LoggingAlloc = LoggingAlloc(Mutex::new(Vec::new()));

fn take_leaks() -> Vec<Vec<u8>> {
    std::mem::take(&mut *LEAKS.0.lock().unwrap())
}

fn main() -> sequoia_openpgp::Result<()> {
    let key = SessionKey::from(vec![0x23; 32]);

    // Produce a ciphertext block using the same backend.
    let mut cipher = Encryptor::new(
        SymmetricAlgorithm::AES256,
        BlockCipherMode::CFB,
        PaddingMode::None,
        &key,
        None,
        Vec::new(),
    )?;
    cipher.write_all(b"cipher leak demo")?;
    let ciphertext = cipher.finalize()?;
    take_leaks(); // discard encryptor artefacts

    // Decrypt the message – the temporary `buffer` now holds the plaintext.
    let mut reader = &ciphertext[..];
    let mut dec = Decryptor::new(
        SymmetricAlgorithm::AES256,
        BlockCipherMode::CFB,
        PaddingMode::None,
        &key,
        None,
        &mut reader,
    )?;
    let mut out = vec![0u8; 16];
    dec.read_exact(&mut out)?;
    drop(dec); // drops the uncleared `Vec` returned by `decrypt`

    for leak in take_leaks() {
        if leak.windows(out.len()).any(|w| w == out.as_slice()) {
            println!("Recovered decrypted plaintext from freed heap: {:?}", leak);
        }
    }

    Ok(())
}
