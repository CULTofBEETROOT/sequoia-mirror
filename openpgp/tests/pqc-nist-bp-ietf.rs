use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptorBuilder, DecryptionHelper, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::policy::NullPolicy;
use openpgp::types::SymmetricAlgorithm;
use openpgp::Error;

fn to_hex(bytes: &[u8]) -> String {
    // Uppercase hex, no separators.
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02X}", b);
    }
    s
}

fn debug_enabled() -> bool {
    std::env::var_os("SEQ_DEBUG_PQC").is_some()
}

fn is_pgp_file(p: &Path) -> bool {
    p.extension() == Some(OsStr::new("pgp"))
}

fn classify_vector_file(name: &str) -> Option<(&str, &'static str)> {
    const PK: &str = "-sample-pk.pgp";
    const SK: &str = "-sample-sk.pgp";
    const MSG: &str = "-sample-message.pgp";

    if let Some(base) = name.strip_suffix(PK) {
        return Some((base, "pk"));
    }
    if let Some(base) = name.strip_suffix(SK) {
        return Some((base, "sk"));
    }
    if let Some(base) = name.strip_suffix(MSG) {
        return Some((base, "message"));
    }
    None
}

#[derive(Default, Debug)]
struct Triplet {
    pk: Option<PathBuf>,
    sk: Option<PathBuf>,
    message: Option<PathBuf>,
}

struct Helper {
    verify_cert: Cert,
    decrypt_cert: Cert,
    vector_name: String,
    debug: bool,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.verify_cert.clone()])
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // Require at least one good signature, and optionally print summary.
        let mut total = 0usize;
        let mut good = 0usize;
        let mut bad = 0usize;

        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    total += 1;
                    if r.is_ok() {
                        good += 1;
                    } else {
                        bad += 1;
                    }
                }
            }
        }

        if self.debug {
            eprintln!(
                "[{}] signature verification: total={} good={} bad={}",
                self.vector_name, total, good, bad
            );
        }

        if good > 0 {
            Ok(())
        } else {
            Err(openpgp::Error::ManipulatedMessage.into())
        }
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        if self.debug {
            eprintln!("[{}] PKESKs: {}", self.vector_name, pkesks.len());
            for (i, pkesk) in pkesks.iter().enumerate() {
                eprintln!(
                    "[{}]   pkesk[{}]: pk_algo={:?} recipient={:?}",
                    self.vector_name,
                    i,
                    pkesk.pk_algo(),
                    pkesk.recipient()
                );
            }

            eprintln!("[{}] Secret cert keys:", self.vector_name);
            for ka in self.decrypt_cert.keys().secret() {
                eprintln!(
                    "[{}]   fp={} pk_algo={:?}",
                    self.vector_name,
                    ka.key().fingerprint(),
                    ka.key().pk_algo()
                );
            }
        }

        for ka in self.decrypt_cert.keys().secret() {
            let fp = ka.key().fingerprint();
            let pk_algo = ka.key().pk_algo();

            let mut kp: KeyPair = match ka.key().clone().into_keypair() {
                Ok(kp) => kp,
                Err(e) => {
                    if self.debug {
                        eprintln!(
                            "[{}]   skipping key fp={} pk_algo={:?}: into_keypair failed: {}",
                            self.vector_name, fp, pk_algo, e
                        );
                    }
                    continue;
                }
            };

            for pkesk in pkesks {
                if let Some((algo, sk)) = pkesk.decrypt(&mut kp, sym_algo) {
                    if self.debug {
                        eprintln!(
                            "[{}]   decrypted session key using fp={} pk_algo={:?} sym={:?} (len={})",
                            self.vector_name,
                            fp,
                            pk_algo,
                            algo,
                            sk.as_ref().len()
                        );
                        // Print the actual session key bytes (hex) right after the summary line.
                        eprintln!(
                            "[{}]   decrypted session key (hex)={}",
                            self.vector_name,
                            to_hex(sk.as_ref())
                        );
                    }

                    if decrypt(algo, &sk) {
                        return Ok(Some(self.decrypt_cert.clone()));
                    }
                }
            }
        }

        Ok(None)
    }
}

fn run_one_vector(base: &str, t: &Triplet, debug: bool) -> openpgp::Result<()> {
    let pk = t.pk.as_ref().unwrap();
    let sk = t.sk.as_ref().unwrap();
    let msg = t.message.as_ref().unwrap();

    if debug {
        eprintln!("=== PQC NIST/BP IETF vector: {} ===", base);
        eprintln!("  pk:  {}", pk.display());
        eprintln!("  sk:  {}", sk.display());
        eprintln!("  msg: {}", msg.display());
    }

    let verify_cert = Cert::from_reader(File::open(pk)?)?;
    let decrypt_cert = Cert::from_reader(File::open(sk)?)?;
    let msg_reader = File::open(msg)?;

    // Test harness for known-good vectors; disables policy filtering for new algos.
    let policy = unsafe { NullPolicy::new() };

    let helper = Helper {
        verify_cert,
        decrypt_cert,
        vector_name: base.to_string(),
        debug,
    };

    let mut decryptor = DecryptorBuilder::from_reader(msg_reader)?
        .with_policy(&policy, None, helper)?;

    let mut plaintext = Vec::new();
    decryptor.read_to_end(&mut plaintext)?;

    if debug {
        eprintln!(
            "[{}] message decrypted successfully (plaintext_len={})",
            base,
            plaintext.len()
        );
        // Print the actual plaintext right after the summary line.
        eprintln!(
            "[{}] message plaintext={:?}",
            base,
            String::from_utf8_lossy(&plaintext)
        );
    }

    Ok(())
}

#[test]
fn pqc_nist_bp_comp_ietf_vectors_decrypt_and_verify() -> openpgp::Result<()> {
    let debug = debug_enabled();

    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("pqc-nist-bp")
        .join("ietf");

    if debug {
        eprintln!("Scanning vectors in {}", dir.display());
    }

    let mut groups: BTreeMap<String, Triplet> = BTreeMap::new();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || !is_pgp_file(&path) {
            continue;
        }

        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };

        let Some((base, kind)) = classify_vector_file(name) else {
            continue;
        };

        let t = groups.entry(base.to_string()).or_default();
        match kind {
            "pk" => t.pk = Some(path),
            "sk" => t.sk = Some(path),
            "message" => t.message = Some(path),
            _ => {}
        }
    }

    if groups.is_empty() {
        return Err(Error::MalformedPacket(
            "No pqc-nist-bp-ietf test vectors discovered (expected *-sample-{pk,sk,message}.pgp)"
                .into(),
        )
        .into());
    }

    for (base, t) in &groups {
        let mut missing = Vec::new();
        if t.pk.is_none() {
            missing.push("pk");
        }
        if t.sk.is_none() {
            missing.push("sk");
        }
        if t.message.is_none() {
            missing.push("message");
        }

        if !missing.is_empty() {
            return Err(Error::MalformedPacket(format!(
                "Incomplete test vector '{}': missing {}",
                base,
                missing.join(", ")
            ))
            .into());
        }

        run_one_vector(base, t, debug)?;
    }

    if debug {
        eprintln!("All pqc-nist-bp-ietf vectors decrypted and verified successfully.");
    }

    Ok(())
}
