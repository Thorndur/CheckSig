use oid_registry::*;
use ring::signature::VerificationAlgorithm;
use ring::signature;
use anyhow::{Context, Result, bail};
use der_parser::oid::Oid;


use p256::ecdsa::VerifyingKey;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;

pub(crate) fn verify_signed_message(signature_alg: &Oid, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if *signature_alg == OID_PKCS1_SHA1WITHRSA {
        signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY.verify(
            untrusted::Input::from(public_key),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        ).context("Certificate Verification failed")
    } else if *signature_alg == OID_PKCS1_SHA256WITHRSA {
        signature::RSA_PKCS1_2048_8192_SHA256.verify(
            untrusted::Input::from(public_key),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        ).context("Certificate Verification failed")
    } else if *signature_alg == OID_PKCS1_SHA384WITHRSA {
        signature::RSA_PKCS1_2048_8192_SHA384.verify(
            untrusted::Input::from(public_key),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        ).context("Certificate Verification failed")
    } else if *signature_alg == OID_PKCS1_SHA512WITHRSA {
        signature::RSA_PKCS1_2048_8192_SHA512.verify(
            untrusted::Input::from(public_key),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        ).context("Certificate Verification failed")
    } else if *signature_alg == OID_SIG_ECDSA_WITH_SHA256 {
        let signature = Signature::from_asn1(signature)
            .expect("Certificate signature couldn't be parsed");

        let public_key = VerifyingKey::from_sec1_bytes(public_key)
            .expect("Parent certificate public key couldn't be parsed");

        match public_key.verify(message, &signature) {
            Ok(_) => Ok(()),
            Err(_) => bail!("Certificate Verification failed")
        }
    } else {
        bail!("Unsupported Signature Algorithm");
    }
}