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
    fn log(s: &str);
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
#[derive(Clone)]
pub struct SignatureAndMessage {
    signature: Vec<u8>,
    message: Vec<u8>
}

#[wasm_bindgen]
pub fn get_signature_from_file(array_buffer: ArrayBuffer) -> Vec<u8> {
    let signature_and_hash = extract_signature_and_message(get_vec_from_array_buffer(array_buffer));
    unsafe {
        GLOBAL_MESSAGE = signature_and_hash.message;
    }

    signature_and_hash.signature
}

fn get_vec_from_array_buffer(array_buffer: ArrayBuffer) -> Vec<u8> {
    let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
    let mut buffer: Vec<u8> = vec![0; typebuf.length() as usize];
    typebuf.copy_to(&mut buffer[..]);

    buffer
}

fn extract_signature_and_message(mut document: Vec<u8>) -> SignatureAndMessage {
    let start_separator = b"/ETSI.CAdES.detached\n/Contents <";
    let start_position = document.windows(start_separator.len()).position(|window| window == start_separator).unwrap() + start_separator.len();

    let end_separator = b">";
    let end_position = document.split_at(start_position).1
        .windows(end_separator.len())
        .position(|window| window == end_separator)
        .unwrap() + start_position;

    let signature_size = (start_position..end_position).count();

    // first 38 bytes are taken out to remove PAdES wrapper of CMS
    let mut signature_bytes = vec![0; signature_size-38];

    signature_bytes.clone_from_slice(&document.drain(start_position..end_position).as_slice()[38..]);

    let signature = hex::decode(
        String::from_utf8_lossy(
            signature_bytes.as_slice()
        ).as_bytes()
    ).unwrap();

    //document.as_mut_slice()[start_position..end_position].clone_from_slice(vec!['0' as u8; signature_size].as_mut_slice());

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