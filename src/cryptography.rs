use anyhow::{bail, Context, Result};
use der_parser::oid::Oid;
use oid_registry::*;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};
use ring::signature;
use ring::signature::VerificationAlgorithm;

pub(crate) fn verify_signed_message(
    signature_alg: &Oid,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if *signature_alg == OID_PKCS1_SHA1WITHRSA {
        signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
            .verify(
                untrusted::Input::from(public_key),
                untrusted::Input::from(message),
                untrusted::Input::from(signature),
            )
            .context("Certificate Verification failed")
    } else if *signature_alg == OID_PKCS1_SHA256WITHRSA {
        signature::RSA_PKCS1_2048_8192_SHA256
            .verify(
                untrusted::Input::from(public_key),
                untrusted::Input::from(message),
                untrusted::Input::from(signature),
            )
            .context("Certificate Verification failed")
    } else if *signature_alg == OID_PKCS1_SHA384WITHRSA {
        signature::RSA_PKCS1_2048_8192_SHA384
            .verify(
                untrusted::Input::from(public_key),
                untrusted::Input::from(message),
                untrusted::Input::from(signature),
            )
            .context("Certificate Verification failed")
    } else if *signature_alg == OID_PKCS1_SHA512WITHRSA {
        signature::RSA_PKCS1_2048_8192_SHA512
            .verify(
                untrusted::Input::from(public_key),
                untrusted::Input::from(message),
                untrusted::Input::from(signature),
            )
            .context("Certificate Verification failed")
    } else if *signature_alg == OID_SIG_ECDSA_WITH_SHA256 {
        let signature =
            Signature::from_asn1(signature).context("Certificate signature couldn't be parsed")?;

        let public_key = VerifyingKey::from_sec1_bytes(public_key)
            .context("Parent certificate public key couldn't be parsed")?;

        match public_key.verify(message, &signature) {
            Ok(_) => Ok(()),
            Err(_) => bail!("Certificate Verification failed"),
        }
    } else {
        bail!("Unsupported Signature Algorithm");
    }
}

pub(crate) fn compare_with_message_hash(hash_alg: &Oid, message: &[u8], hash: &[u8]) -> bool {
    let mut digest_algorithm = &SHA256;
    if hash_alg.to_id_string() == "1.3.14.3.2.26" {
        digest_algorithm = &SHA1_FOR_LEGACY_USE_ONLY;
    } else if *hash_alg == OID_NIST_HASH_SHA256 {
        digest_algorithm = &SHA256;
    } else if hash_alg.to_id_string() == "2.16.840.1.101.3.4.2.2" {
        digest_algorithm = &SHA384;
    } else if hash_alg.to_id_string() == "2.16.840.1.101.3.4.2.3" {
        digest_algorithm = &SHA512;
    } else if hash_alg.to_id_string() == "2.16.840.1.101.3.4.2.6" {
        digest_algorithm = &SHA512_256;
    }

    let mut context = ring::digest::Context::new(digest_algorithm);
    message.chunks(1024).for_each(|chunk| context.update(chunk));

    hash.eq(context.finish().as_ref())
}
