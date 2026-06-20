//! Low-level OpenSSL FFI shims.

use crate::crypto::mem::Protected;
use crate::{Error, Result};

use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl_sys as ffi;
use std::ffi::CStr;
use std::os::raw::c_int;
use std::ptr;

pub(super) const ML_DSA_65_NAME: &CStr = c"ML-DSA-65";
pub(super) const ML_DSA_87_NAME: &CStr = c"ML-DSA-87";

// Based on openssl::cvt in openssl/src/lib.rs.
fn cvt(ret: c_int) -> Result<c_int> {
    if ret <= 0 {
        Err(ErrorStack::get().into())
    } else {
        Ok(ret)
    }
}

// Based on openssl::cvt_p in openssl/src/lib.rs.
fn cvt_p<T>(ptr: *mut T) -> Result<*mut T> {
    if ptr.is_null() {
        Err(ErrorStack::get().into())
    } else {
        Ok(ptr)
    }
}

struct EvpSignature(*mut ffi::EVP_SIGNATURE);

impl EvpSignature {
    fn fetch(algorithm: &CStr) -> Result<Self> {
        ffi::init();
        let signature = unsafe {
            cvt_p(ffi::EVP_SIGNATURE_fetch(
                ptr::null_mut(),
                algorithm.as_ptr(),
                ptr::null(),
            ))?
        };
        Ok(Self(signature))
    }

    fn as_ptr(&self) -> *mut ffi::EVP_SIGNATURE {
        self.0
    }
}

impl Drop for EvpSignature {
    fn drop(&mut self) {
        unsafe {
            ffi::EVP_SIGNATURE_free(self.0);
        }
    }
}

pub(super) fn sign_message(
    key: &PKey<Private>,
    algorithm: &CStr,
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut ctx = PkeyCtx::new(key)?;
    let signature_algorithm = EvpSignature::fetch(algorithm)?;
    unsafe {
        cvt(ffi::EVP_PKEY_sign_message_init(
            ctx.as_ptr(),
            signature_algorithm.as_ptr(),
            ptr::null(),
        ))?;
    }

    let mut signature = Vec::new();
    ctx.sign_to_vec(message, &mut signature)?;
    Ok(signature)
}

pub(super) fn verify_message(
    key: &PKey<Public>,
    algorithm: &CStr,
    message: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let mut ctx = PkeyCtx::new(key)?;
    let signature_algorithm = EvpSignature::fetch(algorithm)?;
    unsafe {
        cvt(ffi::EVP_PKEY_verify_message_init(
            ctx.as_ptr(),
            signature_algorithm.as_ptr(),
            ptr::null(),
        ))?;
    }

    Ok(ctx.verify(message, signature)?)
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
