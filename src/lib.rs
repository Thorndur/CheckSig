use std::str;

use anyhow::Result;
use wasm_bindgen::prelude::*;

use itertools::Itertools;
use crate::byte_range::parse_byte_range;
use crate::signature_verification::{check_signature, get_signature_parts_from_js_value};

mod byte_range;
mod certificate_verification;
mod signature_verification;


// When the `wee_alloc` feature is enabled, this uses `wee_alloc` as the global
// allocator.
//
// If you don't want to use `wee_alloc`, you can safely delete this.
// #[cfg(feature = "wee_alloc")]
// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: String);
}

#[wasm_bindgen(module = "/js/signature.js")]
extern "C" {
   fn getSignatureParts(signatureArray: Vec<u8>) -> JsValue;
}

// This is like the `main` function, except for JavaScript.
#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    // This provides better error messages in debug mode.
    // It's disabled in release mode so it doesn't bloat up the file size.
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
    Ok(())
}

#[wasm_bindgen]
pub async fn check_document(array_buffer: Vec<u8>) -> bool {
    let (signature, message) = extract_signature_and_message(array_buffer);
    log(hex::encode(signature.as_slice()));
    let signature_parts = get_signature_parts_from_js_value(getSignatureParts(signature));
    check_signature(signature_parts, message.as_slice()).await.is_ok()
}

fn extract_signature_and_message(document: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    // let signature_element_start_separator = b"/Type /Sig";
    // let signature_element_start_position = document
    //     .windows(signature_element_start_separator.len())
    //     .position(|window| window == signature_element_start_separator)
    //     .unwrap() + signature_element_start_separator.len();
    //
    // let signature_date_start_separator = b"/M (D:";
    // let signature_date_start_position = document.split_at(signature_element_start_position).1
    //     .windows(signature_date_start_separator.len())
    //     .position(|window| window == signature_date_start_separator)
    //     .unwrap() + signature_date_start_separator.len();
    //
    // let signature_date_end_separator = b")";
    // let signature_date_end_position = document.split_at(signature_date_start_position).1
    //     .windows(signature_date_end_separator.len())
    //     .position(|window| window == signature_date_end_separator)
    //     .unwrap() + signature_date_end_separator.len();

    let start_separator = b"/Contents <";
    let start_position = document//.split_at(signature_date_end_position).1
        .windows(start_separator.len())
        .position(|window| window == start_separator)
        .unwrap() + start_separator.len();

    let end_separator = b">";
    let end_position = document.split_at(start_position).1
        .windows(end_separator.len())
        .position(|window| window == end_separator)
        .unwrap() + start_position;

    let byte_range_start_separator = b"/ByteRange [";
    let byte_range_start = document.split_at(end_position).1
        .windows(byte_range_start_separator.len())
        .position(|window| window == byte_range_start_separator)
        .unwrap() + end_position + byte_range_start_separator.len();

    let byte_range_end_separator = b"]";
    let byte_range_end = document.split_at(byte_range_start).1
        .windows(byte_range_end_separator.len())
        .position(|window| window == byte_range_end_separator)
        .unwrap() + byte_range_start;

    let message = parse_byte_range(&document.as_slice()[byte_range_start..byte_range_end])
        .iter()
        .map(|range| document.as_slice()[range.0..(range.0+range.1)].to_vec())
        .concat();

    // first 38 bytes are removed to ignore PAdES wrapper of CMS
    let signature_bytes = document.as_slice()[start_position+38..end_position].to_vec().clone();

    let signature = hex::decode(
        String::from_utf8_lossy(
            signature_bytes.as_slice()
        ).as_bytes()
    ).unwrap();

    // let date = &document.as_slice()[signature_date_start_position..signature_date_end_position];
    //
    // log(str::from_utf8(date).unwrap().to_string());

    (signature, message)
}








// #[wasm_bindgen]
// pub fn check_signature(signed_attributes_buffer: &[u8], message_hash_buffer: &[u8], signature_buffer: &[u8], public_key_buffer: &[u8]) -> bool {
//     if message_hash_buffer.eq(MESSAGE_HASH_MUTEX.lock().unwrap().as_slice()) {
//         let peer_public_key =
//             signature::UnparsedPublicKey::new(
//                 &signature::ECDSA_P256_SHA256_ASN1,
//                 public_key_buffer);
//
//         peer_public_key
//             .verify(signed_attributes_buffer, signature_buffer)
//             .is_ok()
//     } else {
//         false
//     }
// }