mod pdf_signature;

use wasm_bindgen::prelude::*;
use js_sys::ArrayBuffer;
use sha3::{Sha3_256, Digest};
use regex::Regex;
use picky_asn1_der::{from_bytes, Asn1RawDer};
use picky_asn1::wrapper::{ApplicationTag0};
use itertools::Itertools;
use x509_parser::{parse_x509_der, X509Certificate};
use ring::{
    rand,
    signature::{self, KeyPair, },
};
use std::borrow::Borrow;
use crate::pdf_signature::SignedData;
use crate::pdf_signature::PDFSignature;
use std::sync::Mutex;


// When the `wee_alloc` feature is enabled, this uses `wee_alloc` as the global
// allocator.
//
// If you don't want to use `wee_alloc`, you can safely delete this.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {

    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}


// This is like the `main` function, except for JavaScript.
#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    // This provides better error messages in debug mode.
    // It's disabled in release mode so it doesn't bloat up the file size.
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");

    let file: web_sys::Element = document.get_element_by_id( "file" ).expect("should have a file upload");
    let mut  output = document.get_element_by_id( "output" ).expect("should have a output Paragraph");

    Ok(())
}

#[wasm_bindgen]
pub fn check_file(array_buffer: ArrayBuffer) -> String {

    let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
    let mut body:Vec<u8> = vec![0; typebuf.length() as usize];
    typebuf.copy_to(&mut body[..]);

    let buffer: Vec<u8> = body;
    let versions = split_pdf_versions(buffer);

    for version in &versions {
        log(String::from_utf8_lossy(version.as_slice()).to_string().as_str());
    }

    let certificate_version = &mut versions.get(1).unwrap().to_vec().clone();

    let signature  = extract_certificate(certificate_version).unwrap();

    /*if verify_signature(&signature.0, &signature.1, versions.get(0).unwrap()) {
        "Verified".to_string()
    } else {
        "False Signature".to_string()
    }*/

    hex::encode(signature.1)
    //hex::encode(hash(&buffer).as_slice())
}

fn split_pdf_versions(buffer: Vec<u8>) -> Vec<Vec<u8>> {
    let separator = "%%EOF";

    let mut positions: Vec<usize> = buffer.windows(separator.len()).positions(|window| window == separator.as_bytes()).collect();
    positions.pop();

    positions = positions.iter().map(|position| position + separator.len()).collect();

    split_vec_at_positions(buffer, positions)
}

fn split_vec_at_positions<T>(vector: Vec<T>, positions: Vec<usize>) -> Vec<Vec<T>> {
    use std::collections::VecDeque;

    let mut vector_deque: VecDeque<T> = vector.into(); // avoids reallocating when possible

    let mut new_vector = Vec::new();

    let mut old_position: usize = 0;

    for position in positions {
        new_vector.push(vector_deque.drain(0..(position - old_position)).collect());
        vector_deque.shrink_to_fit();

        old_position = position;
    }

    new_vector.push(vector_deque.into());

    new_vector
}

fn verify_signature(x509: &X509Certificate, signature_bytes: &Vec<u8>, message: &Vec<u8>) -> bool {
    let peer_public_key =
        signature::UnparsedPublicKey::new(&signature::ED25519, x509.signature_value.data);
    peer_public_key.verify(message, signature_bytes).is_ok()

}

fn extract_certificate<'a>(version: &'a mut Vec<u8>) -> Option<(X509Certificate<'a>, Vec<u8>)>{
    if !(version.windows(10).any(|window| window == "/Type /Sig".as_bytes())) {
        None
    } else {

        let certificate_as_byte_vec: Vec<u8> = extract_certificate_bytes_from_pdf_version(version);

        log(hex::encode(&certificate_as_byte_vec.as_slice()).as_str());

        let signature: pdf_signature::PDFSignature = from_bytes(&certificate_as_byte_vec.as_slice()).unwrap();

        let signed_data_option: Option<ApplicationTag0<SignedData>> = signature.clone().signed_data;

        let x509_certificate: Option<ApplicationTag0<Asn1RawDer>> = signed_data_option.clone().unwrap().0.certificates.0;

        let x509_der: &'a mut  Vec<u8> = version;

        x509_der.clone_from(&(x509_certificate.unwrap().0).0);
        //(x509_certificate.unwrap().0).0.clone_into(x509_der);

        let x509: X509Certificate<'a> = parse_x509_der(x509_der).unwrap().1;

//        log(hex::encode(signature.signed_data.unwrap().0.signer_infos.0.get(0).unwrap().clone().signed_attrs.).as_str());

        // Some((
        //     x509,
        //     signature.signed_data.unwrap().0.signer_infos.0.get(0).unwrap().clone().signature
        // ))

        None
    }
}


fn extract_certificate_bytes_from_pdf_version(version: &mut Vec<u8>) -> Vec<u8> {
    let version_to_string = String::from_utf8_lossy(version.as_slice()).to_string();

    let regex = Regex::new("<[0-9A-Fa-f]*>").unwrap();
    let certificate_as_hex_str = regex.find(version_to_string.as_str()).unwrap().as_str();

    let certificate_as_hex_str = certificate_as_hex_str.replace("<", "");
    let certificate_as_hex_str = certificate_as_hex_str.replace(">", "");

    hex::decode(certificate_as_hex_str).unwrap()
}

fn hash(buffer: &Vec<u8>) -> Vec<u8> {
    let mut hash_function: Sha3_256 = Sha3_256::new();
    hash_function.input(buffer.as_slice());
    hash_function.result().to_vec()
}
