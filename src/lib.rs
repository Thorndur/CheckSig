use wasm_bindgen::prelude::*;
use js_sys::{ArrayBuffer};
use ring::digest::{Context, SHA256};
use ring::{signature};
use wasm_bindgen::__rt::std::io::{Error, Cursor, Read};


// When the `wee_alloc` feature is enabled, this uses `wee_alloc` as the global
// allocator.
//
// If you don't want to use `wee_alloc`, you can safely delete this.
// #[cfg(feature = "wee_alloc")]
// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


static mut GLOBAL_MESSAGE: Vec<u8> = Vec::new();

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: String);
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
pub fn get_signature_from_file(array_buffer: ArrayBuffer) -> Vec<u8> {
    let (signature, message) =
        extract_signature_and_message(get_vec_from_array_buffer(array_buffer));

    unsafe {
        GLOBAL_MESSAGE = message;
    }

    signature
}

fn get_vec_from_array_buffer(array_buffer: ArrayBuffer) -> Vec<u8> {
    let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
    let mut buffer: Vec<u8> = vec![0; typebuf.length() as usize];
    typebuf.copy_to(&mut buffer[..]);

    buffer
}

fn extract_signature_and_message(mut document: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let start_separator = b"/Contents <";
    let start_position = document
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


    SignatureAndMessage {
        signature,
        hash: document_without_signature
    }
}

#[wasm_bindgen]
pub fn check_signature(signature_buffer: ArrayBuffer, public_key_buffer: ArrayBuffer) {

    //Verify the signature
    let public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1,
                                         get_vec_from_array_buffer(public_key_buffer));

    unsafe {
        public_key.verify(GLOBAL_MESSAGE.clone().as_slice(), get_vec_from_array_buffer(signature_buffer).as_slice()).unwrap();
    }
//    unsafe {
//        let secp = Secp256k1::new();
//
//        log(hex::encode(globalHash.clone().as_slice()).as_str());
//
//        let message = secp256k1::Message::from_slice(globalHash.clone().as_slice()).unwrap();
//
//
//        log(hex::encode(get_vec_from_array_buffer(signature_buffer.clone()).as_slice()).as_str());
//        let signature = secp256k1::Signature::from_der(&get_vec_from_array_buffer(signature_buffer).as_slice()).unwrap();
//
//        log(hex::encode(get_vec_from_array_buffer(public_key_buffer.clone())).as_str());
//        log(get_vec_from_array_buffer(public_key_buffer.clone()).len().to_string().as_str());
//
//        let public_key = secp256k1::PublicKey::from_slice(&get_vec_from_array_buffer(public_key_buffer)).unwrap();
//
//        secp.verify(&message, &signature, &public_key);
//    }
}

fn sha256_digest(vector: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    let mut reader = Cursor::new(vector);

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish().as_ref().to_vec())
}

fn sha256_digest<R: Read>(mut reader: R) -> Result<Digest, Error> {
    let mut context = Context::new(&SHA256);
    let mut buffer = [0; 1024];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        context.update(&buffer[..count]);
    }

    Ok(context.finish())
}