//! Public key algorithm specification.

use crate::Error;
use crate::Profile;
use crate::PublicKeyAlgorithm;
use crate::Result;
use crate::packet::Key;
use crate::packet::key::Key4;
use crate::packet::key::Key6;
use crate::packet::key;
use crate::types::Curve;
use crate::types::KeyFlags;

/// A full specification of a public key algorithm.
///
/// OpenPGP's [`PublicKeyAlgorithm`] type does not completely specify
/// the public key algorithm.  For some ECC keys, a curve parameter is
/// also required, and for some algorithms like RSA and DSA, a size
/// parameter is required.  This data structure captures all of the
/// required parameters.
#[derive(Clone, Debug)]
pub struct PublicKeyAlgorithmSpecification {
    inner: PublicKeyAlgorithmSpecificationInner,
}

#[derive(Clone, Debug)]
#[allow(non_camel_case_types)]
enum PublicKeyAlgorithmSpecificationInner {
    /// RSA
    RSA(usize),
    /// ElGamal (Encrypt-Only).
    ElGamal(usize),
    /// DSA (Digital Signature Algorithm)
    DSA(usize),
    /// Elliptic curve DH
    ECDH(Curve),
    /// Elliptic curve DSA
    ECDSA(Curve),
    /// "Twisted" Edwards curve DSA
    EdDSA(Curve),
    /// X25519 (RFC 7748).
    X25519,
    /// X448 (RFC 7748).
    X448,
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// Ed448 (RFC 8032).
    Ed448,
}

impl PublicKeyAlgorithmSpecification {
    /// Returns the OpenPGP public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        use PublicKeyAlgorithmSpecificationInner::*;

        #[allow(deprecated)]
        match self.inner {
            RSA(_) => PublicKeyAlgorithm::RSAEncryptSign,
            ElGamal(_) => PublicKeyAlgorithm::ElGamalEncrypt,
            DSA(_) => PublicKeyAlgorithm::DSA,
            ECDH(_) => PublicKeyAlgorithm::ECDH,
            ECDSA(_) => PublicKeyAlgorithm::ECDSA,
            EdDSA(_) => PublicKeyAlgorithm::EdDSA,
            X25519 => PublicKeyAlgorithm::X25519,
            X448 => PublicKeyAlgorithm::X448,
            Ed25519 => PublicKeyAlgorithm::Ed25519,
            Ed448 => PublicKeyAlgorithm::Ed448,
        }
    }

    /// Returns the elliptical curve parameter, if any.
    ///
    /// Note: Not all elliptical curve algorithms have an elliptical
    /// curve parameter.
    pub fn curve(&self) -> Option<Curve> {
        use PublicKeyAlgorithmSpecificationInner::*;

        match &self.inner {
            RSA(_) => None,
            ElGamal(_) => None,
            DSA(_) => None,
            ECDH(curve) => Some(curve.clone()),
            ECDSA(curve) => Some(curve.clone()),
            EdDSA(curve) => Some(curve.clone()),
            X25519 => None,
            X448 => None,
            Ed25519 => None,
            Ed448 => None,
        }
    }

    /// Returns the bits parameter.
    ///
    /// Note: Not all algorithms have a bits parameter.
    pub fn bits(&self) -> Option<usize> {
        use PublicKeyAlgorithmSpecificationInner::*;

        match self.inner {
            RSA(bits) => Some(bits),
            ElGamal(bits) => Some(bits),
            DSA(bits) => Some(bits),
            ECDH(_) => None,
            ECDSA(_) => None,
            EdDSA(_) => None,
            X25519 => None,
            X448 => None,
            Ed25519 => None,
            Ed448 => None,
        }
    }
}

impl PublicKeyAlgorithmSpecification {
    /// Returns whether this algorithm is supported.
    pub fn is_supported(&self) -> bool {
        let algo = self.pk_algo();
        let curve = self.curve();

        algo.is_supported()
            && curve.map(|c| c.is_supported()).unwrap_or(true)
    }

    /// Returns whether this algorithm is for signing.
    pub fn for_signing(&self) -> bool {
        self.pk_algo().for_signing()
    }

    /// Returns whether this algorithm is for signing.
    pub fn for_encryption(&self) -> bool {
        self.pk_algo().for_encryption()
    }

    /// RSA
    ///
    /// According to [RFC 9580, Section
    /// 9.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1),
    /// RSA keys are deprecated and should not be generated, but may
    /// be interpreted.
    pub fn rsa(bits: usize) -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::RSA(bits),
        }
    }

    /// DSA
    ///
    /// According to [RFC 9580, Section
    /// 9.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1),
    /// DSA keys are deprecated and must not be generated.
    ///
    /// This library still allows the generation of v4 DSA keys, but
    /// forbids the generation of v6 keys.
    pub fn dsa(bits: usize) -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::DSA(bits),
        }
    }

    /// Elgamal
    ///
    /// According to [RFC 9580, Section
    /// 9.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1),
    /// ElGamal keys are deprecated and must not be generated.
    ///
    /// This library still allows the generation of v4 Elgamal keys,
    /// but forbids the generation of v6 keys.
    pub fn elgamal(bits: usize) -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ElGamal(bits),
        }
    }

    /// Ed25519
    ///
    /// D.J. Bernstein's "Twisted" Edwards curve Ed25519.
    ///
    /// [RFC 9580, Section 9.1 deprecates this legacy variant of
    /// Cv25519](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1)
    /// in favor of a new [Ed25519
    /// variant](PublicKeyAlgorithmSpecification::ed25519).  However,
    /// if you are using v4 instead of v6 keys due to interopability
    /// concerns, then you should prefer the legacy algorithm as well.
    pub fn legacy_ed25519() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::EdDSA(Curve::Ed25519),
        }
    }

    /// Cv25519
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's
    /// Curve25519, legacy variant.
    ///
    /// [RFC 9580, Section 9.1 deprecates this legacy variant of
    /// Cv25519](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1)
    /// in favor of a new [X25519
    /// variant](PublicKeyAlgorithmSpecification::x25519).  However,
    /// if you are using v4 instead of v6 keys due to interopability
    /// concerns, then you should prefer the legacy algorithm as well.
    pub fn legacy_cv25519() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::Cv25519),
        }
    }

    /// Cv25519
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's
    /// Curve25519, new variant.
    ///
    /// This variant can be used with v4 keys, but if you are using v4
    /// instead of v6 keys due to interopability concerns, then you
    /// should prefer the legacy algorithm,
    /// [`PublicKeyAlgorithmSpecification::legacy_ed25519`] as well.
    pub fn ed25519() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::Ed25519,
        }
    }

    /// Cv25519
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's
    /// Curve25519, new variant.
    ///
    /// This variant can be used with v4 keys, but if you are using v4
    /// instead of v6 keys due to interopability concerns, then you
    /// should prefer the legacy algorithm,
    /// [`PublicKeyAlgorithmSpecification::legacy_cv25519`] as well.
    pub fn x25519() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::X25519,
        }
    }

    /// Ed448
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's Ed448.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn ed448() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::Ed448,
        }
    }

    /// X448
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein's X448.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn x448() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::X448,
        }
    }

    /// NIST curve P-256 for encryption.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn nistp256_for_encryption() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::NistP256),
        }
    }

    /// NIST curve P-256 for signing.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn nistp256_for_signing() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDSA(Curve::NistP256),
        }
    }

    /// NIST curve P-384 for encryption.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn nistp384_for_encryption() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::NistP384),
        }
    }

    /// NIST curve P-384 for signing.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn nistp384_for_signing() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDSA(Curve::NistP384),
        }
    }

    /// NIST curve P-521 for encryption.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn nistp521_for_encryption() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::NistP521),
        }
    }

    /// NIST curve P-521 for signing.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn nistp521_for_signing() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDSA(Curve::NistP521),
        }
    }

    /// BRAINPOOL curve P256r1 for encryption.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn brainpoolp256_for_encryption() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::BrainpoolP256),
        }
    }

    /// Brainpool curve P256r1 for signing.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn brainpoolp256_for_signing() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDSA(Curve::BrainpoolP256),
        }
    }

    /// Brainpool curve P384r1 for encryption.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn brainpoolp384_for_encryption() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::BrainpoolP384),
        }
    }

    /// Brainpool curve P384r1 for signing.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn brainpoolp384_for_signing() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDSA(Curve::BrainpoolP384),
        }
    }

    /// Brainpool curve P512r1 for encryption.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn brainpoolp512_for_encryption() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDH(Curve::BrainpoolP512),
        }
    }

    /// Brainpool curve P512r1 for signing.
    ///
    /// See [RFC 9580, Section
    /// 11.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-11.1).
    pub fn brainpoolp512_for_signing() -> Self {
        PublicKeyAlgorithmSpecification {
            inner: PublicKeyAlgorithmSpecificationInner::ECDSA(Curve::BrainpoolP512),
        }
    }

    /// Generates a key according to the specification.
    pub fn generate_key(&self, profile: Profile)
        -> Result<Key<key::SecretParts, key::UnspecifiedRole>>
    {
        use PublicKeyAlgorithmSpecificationInner::*;

        let key = match &self.inner {
            RSA(bits) => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_rsa(*bits)?.into()
                    }
                    Profile::RFC9580 => {
                        Key6::generate_rsa(*bits)?.into()
                    }
                }
            }
            ElGamal(bits) => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_elgamal(*bits)?.into()
                    }
                    Profile::RFC9580 => {
                        return Err(Error::InvalidArgument(
                            "Can't generate v6 Elgamal keys".into()).into());
                    }
                }
            }
            DSA(bits) => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_dsa(*bits)?.into()
                    }
                    Profile::RFC9580 => {
                        return Err(Error::InvalidArgument(
                            "Can't generate v6 DSA keys".into()).into());
                    }
                }
            }
            ECDH(curve) => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_ecc(false, curve.clone())?.into()
                    }
                    Profile::RFC9580 => {
                        if curve == &Curve::Cv25519 {
                            // Key6::generate_ecc silently maps a
                            // legacy Cv25519 curve to a new X25519
                            // algorithm.  We forbid that here.
                            return Err(Error::InvalidArgument(
                                "Can't generate a v6 Cv25519 key".into()).into());
                        } else {
                            Key6::generate_ecc(false, curve.clone())?.into()
                        }
                    }
                }
            }
            ECDSA(curve) => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_ecc(true, curve.clone())?.into()
                    }
                    Profile::RFC9580 => {
                        Key6::generate_ecc(true, curve.clone())?.into()
                    }
                }
            }
            EdDSA(curve) => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_ecc(true, curve.clone())?.into()
                    }
                    Profile::RFC9580 => {
                        if curve == &Curve::Ed25519 {
                            // Key6::generate_ecc silently maps a
                            // legacy Ed25519 curve to a new Ed25519
                            // algorithm.  We forbid that here.
                            return Err(Error::InvalidArgument(
                                "Can't generate a v6 Ed25519 key".into()).into());
                        } else {
                            Key6::generate_ecc(true, curve.clone())?.into()
                        }
                    }
                }
            }
            X25519 => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_x25519()?.into()
                    }
                    Profile::RFC9580 => {
                        Key6::generate_x25519()?.into()
                    }
                }
            }
            Ed25519 => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_ed25519()?.into()
                    }
                    Profile::RFC9580 => {
                        Key6::generate_ed25519()?.into()
                    }
                }
            }
            X448 => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_x448()?.into()
                    }
                    Profile::RFC9580 => {
                        Key6::generate_x448()?.into()
                    }
                }
            }
            Ed448 => {
                match profile {
                    Profile::RFC4880 => {
                        Key4::generate_ed448()?.into()
                    }
                    Profile::RFC9580 => {
                        Key6::generate_ed448()?.into()
                    }
                }
            }
        };

        Ok(key)
    }

    /// Generates a key according to the specification and checks that
    /// it is compatible with the key flags.
    pub fn generate_key_for<K>(&self, profile: Profile, key_flags: K)
        -> Result<Key<key::SecretParts, key::UnspecifiedRole>>
    where
        K: AsRef<KeyFlags>
    {
        let algo = self.pk_algo();

        let key_flags = key_flags.as_ref();

        let need_signing = key_flags.for_certification()
            || key_flags.for_signing()
            || key_flags.for_authentication();

        let need_encryption = key_flags.for_transport_encryption()
            || key_flags.for_storage_encryption();

        if need_signing && need_encryption
            && (! algo.for_signing() || ! algo.for_encryption())
        {
            return Err(Error::InvalidOperation(
                "Can't use key for signing and encryption".into())
                .into());
        } else if need_signing && ! algo.for_signing() {
            return Err(Error::InvalidOperation(
                "Can't use key for signing".into())
                .into());
        } else if need_encryption && ! algo.for_encryption() {
            return Err(Error::InvalidOperation(
                "Can't use key for encryption".into())
                .into());
        } else {
            self.generate_key(profile)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::crypto::mpi;

    #[test]
    fn check() {
        let check = |spec: PublicKeyAlgorithmSpecification,
                     algo: PublicKeyAlgorithm,
                     curve: Option<Curve>,
                     bits: Option<usize>|
        {
            assert_eq!(spec.pk_algo(), algo);
            assert_eq!(spec.curve(), curve);
            assert_eq!(spec.bits(), bits);
        };

        use PublicKeyAlgorithm::*;

        check(PublicKeyAlgorithmSpecification::rsa(2048),
              RSAEncryptSign, None, Some(2048));
        #[allow(deprecated)]
        check(PublicKeyAlgorithmSpecification::dsa(2048),
              DSA, None, Some(2048));
        #[allow(deprecated)]
        check(PublicKeyAlgorithmSpecification::elgamal(2048),
              ElGamalEncrypt, None, Some(2048));
        check(PublicKeyAlgorithmSpecification::legacy_ed25519(),
              EdDSA, Some(Curve::Ed25519), None);
        check(PublicKeyAlgorithmSpecification::legacy_cv25519(),
              ECDH, Some(Curve::Cv25519), None);
        check(PublicKeyAlgorithmSpecification::ed25519(),
              Ed25519, None, None);
        check(PublicKeyAlgorithmSpecification::x25519(),
              X25519, None, None);
        check(PublicKeyAlgorithmSpecification::ed448(),
              Ed448, None, None);
        check(PublicKeyAlgorithmSpecification::x448(),
              X448, None, None);
        check(PublicKeyAlgorithmSpecification::nistp256_for_encryption(),
              ECDH, Some(Curve::NistP256), None);
        check(PublicKeyAlgorithmSpecification::nistp256_for_signing(),
              ECDSA, Some(Curve::NistP256), None);
        check(PublicKeyAlgorithmSpecification::nistp384_for_encryption(),
              ECDH, Some(Curve::NistP384), None);
        check(PublicKeyAlgorithmSpecification::nistp384_for_signing(),
              ECDSA, Some(Curve::NistP384), None);
        check(PublicKeyAlgorithmSpecification::nistp521_for_encryption(),
              ECDH, Some(Curve::NistP521), None);
        check(PublicKeyAlgorithmSpecification::nistp521_for_signing(),
              ECDSA, Some(Curve::NistP521), None);
        check(PublicKeyAlgorithmSpecification::brainpoolp256_for_encryption(),
              ECDH, Some(Curve::BrainpoolP256), None);
        check(PublicKeyAlgorithmSpecification::brainpoolp256_for_signing(),
              ECDSA, Some(Curve::BrainpoolP256), None);
        check(PublicKeyAlgorithmSpecification::brainpoolp384_for_encryption(),
              ECDH, Some(Curve::BrainpoolP384), None);
        check(PublicKeyAlgorithmSpecification::brainpoolp384_for_signing(),
              ECDSA, Some(Curve::BrainpoolP384), None);
        check(PublicKeyAlgorithmSpecification::brainpoolp512_for_encryption(),
              ECDH, Some(Curve::BrainpoolP512), None);
        check(PublicKeyAlgorithmSpecification::brainpoolp512_for_signing(),
              ECDSA, Some(Curve::BrainpoolP512), None);
    }

    #[test]
    fn generate_key() {
        use PublicKeyAlgorithm::*;
        use Profile::*;

        let check = |profile: Profile,
                     spec: PublicKeyAlgorithmSpecification,
                     algo: PublicKeyAlgorithm,
                     curve: Option<Curve>,
                     bits: Option<usize>|
        {
            assert_eq!(
                spec.is_supported(),
                algo.is_supported()
                    && curve.as_ref()
                        .map(|c| {
                            c.is_supported()
                        }).unwrap_or(true));

            if ! spec.is_supported() {
                // The algorithms are not supported by the crypto
                // backend; skip.
                eprintln!("Skipping unsupported algorithm: {}, curve: {:?}",
                          spec.pk_algo(), spec.curve());
                return;
            }

            let key = spec.generate_key(profile)
                .expect("Can generate key");

            match profile {
                RFC4880 => {
                    assert_eq!(key.version(), 4);
                }
                RFC9580 => {
                    assert_eq!(key.version(), 6);
                }
            }

            assert_eq!(algo, key.pk_algo());

            assert_eq!(curve, spec.curve());
            let curve = match key.mpis() {
                mpi::PublicKey::EdDSA { curve, .. }
                | mpi::PublicKey::ECDSA { curve, .. }
                | mpi::PublicKey::ECDH { curve, .. } => {
                    Some(curve)
                }
                _ => None,
            };
            assert_eq!(curve, spec.curve().as_ref());

            assert_eq!(bits, spec.bits());
            if bits.is_some() {
                assert_eq!(bits, key.mpis().bits());
            }
        };

        #[allow(deprecated)]
        check(RFC4880, PublicKeyAlgorithmSpecification::elgamal(2048),
              ElGamalEncrypt, None, Some(2048));
        PublicKeyAlgorithmSpecification::elgamal(2048)
            .generate_key(RFC9580)
            .expect_err("forbidden by RFC9580");

        #[allow(deprecated)]
        check(RFC4880, PublicKeyAlgorithmSpecification::dsa(2048),
              DSA, None, Some(2048));
        PublicKeyAlgorithmSpecification::dsa(2048)
            .generate_key(RFC9580)
            .expect_err("forbidden by RFC9580");

        check(RFC4880, PublicKeyAlgorithmSpecification::legacy_cv25519(),
              ECDH, Some(Curve::Cv25519), None);
        PublicKeyAlgorithmSpecification::legacy_cv25519()
            .generate_key(RFC9580)
            .expect_err("forbidden by RFC9580");

        check(RFC4880, PublicKeyAlgorithmSpecification::legacy_ed25519(),
              EdDSA, Some(Curve::Ed25519), None);
        PublicKeyAlgorithmSpecification::legacy_ed25519()
            .generate_key(RFC9580)
            .expect_err("forbidden by RFC9580");

        for profile in [ RFC4880, RFC9580 ] {
            check(profile, PublicKeyAlgorithmSpecification::rsa(2048),
                  RSAEncryptSign, None, Some(2048));

            check(profile, PublicKeyAlgorithmSpecification::nistp256_for_encryption(),
                  ECDH, Some(Curve::NistP256), None);
            check(profile, PublicKeyAlgorithmSpecification::nistp384_for_encryption(),
                  ECDH, Some(Curve::NistP384), None);
            check(profile, PublicKeyAlgorithmSpecification::nistp521_for_encryption(),
                  ECDH, Some(Curve::NistP521), None);
            check(profile, PublicKeyAlgorithmSpecification::brainpoolp256_for_encryption(),
                  ECDH, Some(Curve::BrainpoolP256), None);
            check(profile, PublicKeyAlgorithmSpecification::brainpoolp384_for_encryption(),
                  ECDH, Some(Curve::BrainpoolP384), None);
            check(profile, PublicKeyAlgorithmSpecification::brainpoolp512_for_encryption(),
                  ECDH, Some(Curve::BrainpoolP512), None);

            check(profile, PublicKeyAlgorithmSpecification::nistp256_for_signing(),
                  ECDSA, Some(Curve::NistP256), None);
            check(profile, PublicKeyAlgorithmSpecification::nistp384_for_signing(),
                  ECDSA, Some(Curve::NistP384), None);
            check(profile, PublicKeyAlgorithmSpecification::nistp521_for_signing(),
                  ECDSA, Some(Curve::NistP521), None);
            check(profile, PublicKeyAlgorithmSpecification::brainpoolp256_for_signing(),
                  ECDSA, Some(Curve::BrainpoolP256), None);
            check(profile, PublicKeyAlgorithmSpecification::brainpoolp384_for_signing(),
                  ECDSA, Some(Curve::BrainpoolP384), None);
            check(profile, PublicKeyAlgorithmSpecification::brainpoolp512_for_signing(),
                  ECDSA, Some(Curve::BrainpoolP512), None);

            check(profile, PublicKeyAlgorithmSpecification::ed25519(),
                  Ed25519, None, None);
            check(profile, PublicKeyAlgorithmSpecification::ed448(),
                  Ed448, None, None);
            check(profile, PublicKeyAlgorithmSpecification::x25519(),
                  X25519, None, None);
            check(profile, PublicKeyAlgorithmSpecification::x448(),
                  X448, None, None);
        }
    }

    #[test]
    fn generate_key_for() {
        use Profile::*;

        let algos = [
            (true, true, RFC4880, PublicKeyAlgorithmSpecification::rsa(2048)),
            (true, true, RFC9580, PublicKeyAlgorithmSpecification::rsa(2048)),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::elgamal(2048)),
            (false, false, RFC9580, PublicKeyAlgorithmSpecification::elgamal(2048)),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::dsa(2048)),
            (false, false, RFC9580, PublicKeyAlgorithmSpecification::dsa(2048)),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::legacy_cv25519()),
            (false, false, RFC9580, PublicKeyAlgorithmSpecification::legacy_cv25519()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::nistp256_for_encryption()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::nistp384_for_encryption()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::nistp521_for_encryption()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::brainpoolp256_for_encryption()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::brainpoolp384_for_encryption()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::brainpoolp512_for_encryption()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::nistp256_for_signing()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::nistp384_for_signing()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::nistp521_for_signing()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::brainpoolp256_for_signing()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::brainpoolp384_for_signing()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::brainpoolp512_for_signing()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::ed25519()),
            (true, false, RFC4880, PublicKeyAlgorithmSpecification::ed448()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::x25519()),
            (false, true, RFC4880, PublicKeyAlgorithmSpecification::x448()),
        ];

        let signing = KeyFlags::certification();
        let encryption = KeyFlags::transport_encryption();

        for (for_signing, for_encryption, profile, spec) in algos {
            if ! spec.is_supported() {
                eprintln!("Skipping {:?}, not supported", spec);
                continue;
            }

            let result = spec.generate_key_for(profile, &signing);
            assert_eq!(result.is_ok(), for_signing,
                       "Result for {:?}: {:?}", spec, result.map(|_| ()));

            let result = spec.generate_key_for(profile, &encryption);
            assert_eq!(result.is_ok(), for_encryption,
                       "Result for {:?}: {:?}", spec, result.map(|_| ()));
        }
    }
}
