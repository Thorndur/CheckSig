use wasm_bindgen::JsValue;
use x509_parser::parse_x509_certificate;
use anyhow::{Result, bail};


use p256::ecdsa::VerifyingKey;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;


use serde::{Serialize, Deserialize};

use ring::digest::SHA256;
use crate::certificate::check_certificate;
use chrono::{DateTime, FixedOffset};


#[derive(Serialize, Deserialize)]
pub struct SignatureParts {
    pub signed_attributes_buffer: Vec<u8>,
    pub message_hash_buffer: Vec<u8>,
    pub signature_buffer: Vec<u8>,
    pub public_keys_buffer: Vec<Vec<u8>>
}

pub(crate) fn get_signature_parts_from_js_value(js_value: JsValue) -> SignatureParts {
    serde_wasm_bindgen::from_value(js_value).expect("Signature parts couldn't be parsed")
}

pub(crate) async fn check_signature(signature_parts: SignatureParts, message: &[u8], signing_date_time: DateTime<FixedOffset>) -> Result<()> {

    let mut context = ring::digest::Context::new(&SHA256);
    message.chunks(1024).for_each( |chunk| context.update(chunk));

    if signature_parts.message_hash_buffer.eq(context.finish().as_ref()) {
        let signature = Signature::from_asn1(signature_parts.signature_buffer.as_slice()).expect("Signature couldn't be parsed");

        let (_, cert) = parse_x509_certificate(signature_parts.public_keys_buffer[0].as_slice()).expect("Certificate couldn't be parsed");

        let public_key = VerifyingKey::from_sec1_bytes(cert.tbs_certificate.subject_pki.subject_public_key.data).expect("Public Key couldn't be parsed");

        match public_key.verify(signature_parts.signed_attributes_buffer.as_slice(), &signature) {
            Ok(_) => check_certificate(cert).await,
            Err(_) => bail!("Signature Couldn't be Verified")
        }
    } else {
        bail!("Message Hash in Signature is wrong")
    }
}