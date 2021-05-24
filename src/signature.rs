use anyhow::{bail, Context, Result};
use chrono::{DateTime, FixedOffset};
use der_parser::oid::Oid;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;
use x509_parser::parse_x509_certificate;

use crate::certificate::check_certificate;
use crate::cryptography::{compare_with_message_hash, verify_signed_message};

#[derive(Serialize, Deserialize)]
pub struct SignatureParts {
    pub signed_attributes_buffer: Vec<u8>,
    pub hash_algorithm_id: String,
    pub message_hash_buffer: Vec<u8>,
    pub signature_algorithm_id: String,
    pub signature_buffer: Vec<u8>,
    pub certificates_buffer: Vec<Vec<u8>>,
}

pub(crate) fn get_signature_parts_from_js_value(js_value: JsValue) -> Result<SignatureParts> {
    match serde_wasm_bindgen::from_value(js_value) {
        Ok(signature_parts) => Ok(signature_parts),
        Err(_) => bail!("Signature parts couldn't be parsed"),
    }
}

pub(crate) async fn check_signature(
    signature_parts: SignatureParts,
    message: &[u8],
    signing_date_time: DateTime<FixedOffset>,
) -> Result<()> {
    let hash_algorithm_id = get_oid_form_id_string(signature_parts.hash_algorithm_id)?;

    if compare_with_message_hash(
        &hash_algorithm_id,
        message,
        signature_parts.message_hash_buffer.as_slice(),
    ) {
        let (_, cert) = parse_x509_certificate(signature_parts.certificates_buffer[0].as_slice())
            .context("Certificate couldn't be parsed")?;

        let signature_algorithm_id =
            get_oid_form_id_string(signature_parts.signature_algorithm_id)?;

        let public_key = cert.tbs_certificate.subject_pki.subject_public_key.data;

        let message = signature_parts.signed_attributes_buffer.as_slice();

        let signature = signature_parts.signature_buffer.as_slice();

        match verify_signed_message(&signature_algorithm_id, public_key, message, signature) {
            Ok(_) => check_certificate(cert, signing_date_time).await,
            Err(e) => bail!("Signature Couldn't be Verified:  {}", e.to_string()),
        }
    } else {
        bail!("Message Hash in Signature is wrong")
    }
}

fn get_oid_form_id_string(id: String) -> Result<Oid<'static>> {
    let id_i64_array: Vec<u64> = id
        .split(".")
        .map(|x| x.parse::<u64>().expect("oid can't be parsed"))
        .collect();

    match Oid::from(id_i64_array.as_slice()) {
        Ok(oid) => Ok(oid),
        Err(_) => bail!("Oid couldn't be parsed"),
    }
}
