use std::str;

use anyhow::Result;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::signature::{check_signature, get_signature_parts_from_js_value};
use crate::pdf::extract_signature_and_message_from_pdf_file;

mod certificate;
mod pdf;
mod signature;


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
pub async fn check_document(array_buffer: Vec<u8>) -> Result<(), JsValue> {
    let (signature, message) = extract_signature_and_message_from_pdf_file(array_buffer);
    log(hex::encode(signature.as_slice()));
    let signature_parts = get_signature_parts_from_js_value(getSignatureParts(signature));
    check_signature(signature_parts, message.as_slice()).await.map_err(|error| JsValue::from_str(error.to_string().as_str()))
}