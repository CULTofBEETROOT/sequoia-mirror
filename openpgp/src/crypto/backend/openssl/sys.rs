//! Low-level OpenSSL FFI shims.

use crate::crypto::mem::Protected;
use crate::{Error, Result};

use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl_sys as ffi;
use std::os::raw::c_int;
use std::ptr;

// Based on openssl::cvt in openssl/src/lib.rs.
fn cvt(ret: c_int) -> Result<c_int> {
    if ret <= 0 {
        Err(ErrorStack::get().into())
    } else {
        Ok(ret)
    }
}

pub(super) fn encapsulate(key: &PKey<Public>, ciphertext: &mut [u8]) -> Result<Protected> {
    let ctx = PkeyCtx::new(key)?;
    unsafe {
        cvt(ffi::EVP_PKEY_encapsulate_init(ctx.as_ptr(), ptr::null()))?;
    }

    let mut ciphertext_len = 0;
    let mut keyshare_len = 0;
    unsafe {
        cvt(ffi::EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ptr::null_mut(),
            &mut ciphertext_len,
            ptr::null_mut(),
            &mut keyshare_len,
        ))?;
    }
    if ciphertext.len() != ciphertext_len {
        return Err(Error::InvalidArgument(format!(
            "OpenSSL requires {} bytes for encapsulated key; expected {}",
            ciphertext_len,
            ciphertext.len()
        ))
        .into());
    }

    let mut keyshare = Protected::new(keyshare_len);
    unsafe {
        cvt(ffi::EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            keyshare.as_mut_ptr(),
            &mut keyshare_len,
        ))?;
    }
    if ciphertext_len != ciphertext.len() {
        return Err(Error::InvalidOperation(format!(
            "OpenSSL returned {} bytes for encapsulated key; expected {}",
            ciphertext_len,
            ciphertext.len()
        ))
        .into());
    }

    if keyshare_len == keyshare.len() {
        Ok(keyshare)
    } else {
        Ok(Protected::from(&keyshare[..keyshare_len]))
    }
}

pub(super) fn decapsulate(key: &PKey<Private>, ciphertext: &[u8]) -> Result<Protected> {
    let ctx = PkeyCtx::new(key)?;
    unsafe {
        cvt(ffi::EVP_PKEY_decapsulate_init(ctx.as_ptr(), ptr::null()))?;
    }

    let mut keyshare_len = 0;
    unsafe {
        cvt(ffi::EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            ptr::null_mut(),
            &mut keyshare_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }

    let mut keyshare = Protected::new(keyshare_len);
    unsafe {
        cvt(ffi::EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            keyshare.as_mut_ptr(),
            &mut keyshare_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }

    if keyshare_len == keyshare.len() {
        Ok(keyshare)
    } else {
        Ok(Protected::from(&keyshare[..keyshare_len]))
    }
}
