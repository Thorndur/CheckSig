use wasm_bindgen::JsValue;
use x509_parser::parse_x509_certificate;
use anyhow::{Result, bail, Context};

use der_parser::oid;

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;


use serde::{Serialize, Deserialize};

use ring::digest::SHA256;
use crate::certificate::{check_certificate_chain, check_certificate};
use chrono::{DateTime, FixedOffset};
use der_parser::oid::{Oid, ParseError};
use oid_registry::OidEntry;
use crate::crypography::verify_signed_message;


#[derive(Serialize, Deserialize)]
pub struct SignatureParts {
    pub signed_attributes_buffer: Vec<u8>,
    pub hash_algorithm_id: String,
    pub message_hash_buffer: Vec<u8>,
    pub signature_algorithm_id: String,
    pub signature_buffer: Vec<u8>,
    pub certificates_buffer: Vec<Vec<u8>>
}

pub(crate) fn get_signature_parts_from_js_value(js_value: JsValue) -> SignatureParts {
    serde_wasm_bindgen::from_value(js_value).expect("Signature parts couldn't be parsed")
}

pub(crate) async fn check_signature(signature_parts: SignatureParts, message: &[u8], signing_date_time: DateTime<FixedOffset>) -> Result<()> {
    if compare_with_message_hash(message, signature_parts.message_hash_buffer.as_slice()) {
        let (_, cert) = parse_x509_certificate(signature_parts.certificates_buffer[0].as_slice()).expect("Certificate couldn't be parsed");

        let oid = get_oid_form_id_string(signature_parts.signature_algorithm_id)?;
        let public_key = cert.tbs_certificate.subject_pki.subject_public_key.data;
        let message = signature_parts.signed_attributes_buffer.as_slice();
        let signature = signature_parts.signature_buffer.as_slice();

        match verify_signed_message(&oid, public_key, message, signature) {
            Ok(_) => check_certificate(cert, signing_date_time).await,
            Err(_) => bail!("Signature Couldn't be Verified")
        }
    } else {
        bail!("Message Hash in Signature is wrong")
    }
}

fn compare_with_message_hash(message: &[u8], hash: &[u8]) -> bool {
    let mut context = ring::digest::Context::new(&SHA256);
    message.chunks(1024).for_each( |chunk| context.update(chunk));

    hash.eq(context.finish().as_ref())
}

fn get_oid_form_id_string(id: String) -> Result<Oid<'static>> {

    let id_string_array: Vec<&str> = id.split(".").collect();
    let id_i64_array: Vec<u64> = id_string_array.iter().map(|x| x.parse::<u64>().expect("oid can't be parsed")).collect();

    match Oid::from(id_i64_array.as_slice()) {
        Ok(oid) => Ok(oid),
        Err(_) => bail!("Oid couldn't be parsed")
    }
}