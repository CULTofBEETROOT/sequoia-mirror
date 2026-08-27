//! Implementation of Sequoia crypto API using the OpenSSL cryptographic library.

use crate::crypto::mem::Protected;
use crate::crypto::mpi::ProtectedMPI;

pub mod aead;
pub mod asymmetric;
pub mod der;
pub mod ecdh;
pub mod hash;
pub mod kdf;
pub mod symmetric;

pub struct Backend(());

#[cfg(any(opensslmajorversion = "1", opensslmajorversion = "3"))]
#[ctor::ctor(unsafe)]
fn openssl_init() {
    // Older versions of OpenSSL (<= 3) register an atexit handler
    // that calls OPENSSL_cleanup to free some resources.  This can
    // lead to a crash if another thread is still using OpenSSL when
    // the atexit handler is invoked.
    //
    // Happily, this is no longer automatically called:
    //
    //   https://openssl-library.org/post/2026-03-10-remove-atexit
    //
    // But the version of OpenSSL shipped in Debian Trixie (3.5.5)
    // still calls it.
    //
    // We use this mechanism to call OPENSSL_init_ssl (hopefully)
    // first so that the atexit handlers are not registered.
    use ossl::bindings::OPENSSL_init_ssl;
    use ossl::bindings::OPENSSL_INIT_NO_ATEXIT;

    unsafe {
        OPENSSL_init_ssl(OPENSSL_INIT_NO_ATEXIT,
                         std::ptr::null());
    }
}

impl super::interface::Backend for Backend {
    fn backend() -> String {
        format!("OpenSSL {}",
                std::ffi::CStr::from_bytes_with_nul(
                    ossl::bindings::OPENSSL_FULL_VERSION_STR)
                .expect("version to be 0-terminated")
                .to_str()
                .expect("version to be valid UTF-8"))
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        // Previously, this mapped to RAND_bytes:
        //
        //openssl::rand::rand_bytes(buf)?;

        let ctx = context();
        let mut rand_ctx = ossl::rand::EvpRandCtx::new_hmac_drbg(
            &ctx, ossl::digest::DigestAlg::Sha2_512, b"")?;
        rand_ctx.generate(b"", buf)?;
        Ok(())
    }
}

/// Returns a library context for use with `ossl`.
pub fn context() -> &'static ossl::OsslContext {
    use std::sync::OnceLock;
    static OSSL_CONTEXT: OnceLock<ossl::OsslContext> =
        OnceLock::new();

    OSSL_CONTEXT.get_or_init(|| {
        let mut context = ossl::OsslContext::new_lib_ctx();
        // First, load default configuration. It should change the context
        // to sensible defaults defined in the configuration file, loading
        // providers, FIPS module, cryptographic policy ...
        // Failure is not fatal.
        let _ = context.load_default_configuration();
        // Try to load legacy provider. Ignore the failures as the worst
        // what could happen is that we won't support some of the legacy
        // algorithms.
        let _ = context.load_legacy_provider();
        // If we have FIPS provider, set it to permissive mode.
        let _ = context.set_permissive_fips();
        context
    })
}

impl From<ossl::OsslSecret> for Protected {
    fn from(v: ossl::OsslSecret) -> Self {
        Protected::from(v.as_ref())
    }
}

impl From<&ossl::OsslSecret> for Protected {
    fn from(v: &ossl::OsslSecret) -> Self {
        Protected::from(v.as_ref())
    }
}

impl From<ossl::OsslSecret> for ProtectedMPI {
    fn from(v: ossl::OsslSecret) -> Self {
        ProtectedMPI::from(v.as_ref())
    }
}

impl From<&ossl::OsslSecret> for ProtectedMPI {
    fn from(v: &ossl::OsslSecret) -> Self {
        ProtectedMPI::from(v.as_ref())
    }
}

impl From<&Protected> for ossl::OsslSecret {
    fn from(v: &Protected) -> Self {
        ossl::OsslSecret::from_slice(v.as_ref())
    }
}

impl From<&ProtectedMPI> for ossl::OsslSecret {
    fn from(v: &ProtectedMPI) -> Self {
        ossl::OsslSecret::from_slice(v.value())
    }
}
