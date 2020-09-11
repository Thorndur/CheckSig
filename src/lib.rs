mod pdf_signature;

use wasm_bindgen::prelude::*;
use js_sys::ArrayBuffer;
//use sha3::{Sha3_256, Digest};
use ring::digest::{Context, SHA256};
use wasm_bindgen::__rt::std::io::{Error, Cursor, Read};


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

    #[wasm_bindgen(module = "/siglib.js")]
    fn getSignatureParts(signedDataString: Vec<u8>) -> ArrayBuffer;
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

// #[wasm_bindgen]
// pub fn getSigString(array_buffer: ArrayBuffer) -> String {
//     let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
//     let mut body:Vec<u8> = vec![0; typebuf.length() as usize];
//     typebuf.copy_to(&mut body[..]);
//
//     let buffer: Vec<u8> = body;
//     let versions = split_pdf_versions(buffer);
//
//     for version in &versions {
//         log(String::from_utf8_lossy(version.as_slice()).to_string().as_str());
//     }
//
//     let certificate_version = &mut versions.get(1).unwrap().to_vec().clone();
//
//     extract_signature_string(certificate_version).unwrap()
// }
//
// #[wasm_bindgen]
// pub fn getSigHash(array_buffer: ArrayBuffer) -> String {
//     let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
//     let mut body:Vec<u8> = vec![0; typebuf.length() as usize];
//     typebuf.copy_to(&mut body[..]);
//
//     let buffer: Vec<u8> = body;
//     let versions = split_pdf_versions(buffer);
//
//     for version in &versions {
//         log(String::from_utf8_lossy(version.as_slice()).to_string().as_str());
//     }
//
//
//     hex::encode(sha256_digest(&versions.get(0).unwrap().to_vec()).unwrap())
//
// }

#[wasm_bindgen]
pub struct SignatureAndHash {
    signature: Vec<u8>,
    hash: Vec<u8>
}

#[wasm_bindgen]
pub fn get_signature_and_hash_from_file(array_buffer: ArrayBuffer) -> SignatureAndHash {
    let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
    let mut body: Vec<u8> = vec![0; typebuf.length() as usize];
    typebuf.copy_to(&mut body[..]);
    //getSignatureParts(body.clone());

    extract_signature_and_hash(body)
}

// #[wasm_bindgen]
// pub fn check_file(array_buffer: ArrayBuffer) -> String {
//
//     let typebuf: js_sys::Uint8Array = js_sys::Uint8Array::new(&array_buffer);
//     let mut body:Vec<u8> = vec![0; typebuf.length() as usize];
//     typebuf.copy_to(&mut body[..]);
//
//     let buffer: Vec<u8> = body;
//     let versions = split_pdf_versions(buffer);
//
//     for version in &versions {
//         log(String::from_utf8_lossy(version.as_slice()).to_string().as_str());
//     }
//
//     let certificate_version = &mut versions.get(1).unwrap().to_vec().clone();
//
//     let signature  = extract_signature(certificate_version).unwrap();
//
//     /*if verify_signature(&signature.0, &signature.1, versions.get(0).unwrap()) {
//         "Verified".to_string()
//     } else {
//         "False Signature".to_string()
//     }*/
//
//     hex::encode(signature.1)
//     //hex::encode(hash(&buffer).as_slice())
// }

// fn split_pdf_versions(buffer: Vec<u8>) -> Vec<Vec<u8>> {
//     let separator = "%%EOF";
//
//     let mut positions: Vec<usize> = buffer.windows(separator.len()).positions(|window| window == separator.as_bytes()).collect();
//     positions.pop();
//
//     positions = positions.iter().map(|position| position + separator.len()).collect();
//
//     split_vec_at_positions(buffer, positions)
// }

fn split_vec_at_positions<T>(vector: Vec<T>, positions: Vec<usize>) -> Vec<Vec<T>> {
    use std::collections::VecDeque;

    let mut vector_deque: VecDeque<T> = vector.into(); // avoids reallocating when possible

    let mut new_vector: Vec<Vec<T>> = Vec::new();

    let mut old_position: usize = 0;

    for position in positions {
        new_vector.push(vector_deque.drain(0..(position - old_position)).collect());
        vector_deque.shrink_to_fit();

        old_position = position;
    }

    new_vector.push(vector_deque.into());

    new_vector
}
//
// fn verify_signature(x509: &X509Certificate, signature_bytes: &Vec<u8>, message: &Vec<u8>) -> bool {
//     let peer_public_key =
//         signature::UnparsedPublicKey::new(&signature::ED25519, x509.signature_value.data);
//     peer_public_key.verify(message, signature_bytes).is_ok()
//
// }
//
// fn extract_signature_string(version: &mut Vec<u8>) -> Option<String> {
//     if !(version.windows(10).any(|window| window == "/Type /Sig".as_bytes())) {
//         None
//     } else {
//
//         let certificate_as_byte_vec: Vec<u8> = extract_certificate_bytes_from_pdf_version(version);
//
//         log(hex::encode(&certificate_as_byte_vec.as_slice()).as_str());
//
//         Some(hex::encode(&certificate_as_byte_vec.as_slice()))
//     }
//
// }
//
// fn extract_certificate<'a>(version: &'a mut Vec<u8>) -> Option<(X509Certificate<'a>, Vec<u8>)>{
//     if !(version.windows(10).any(|window| window == "/Type /Sig".as_bytes())) {
//         None
//     } else {
//
//         let certificate_as_byte_vec: Vec<u8> = extract_certificate_bytes_from_pdf_version(version);
//
//
//         log(hex::encode(&certificate_as_byte_vec.as_slice()).as_str());
//
//         let signature: pdf_signature::PDFSignature = from_bytes(&certificate_as_byte_vec.as_slice()).unwrap();
//
//         let signed_data_option: Option<ApplicationTag0<SignedData>> = signature.clone().signed_data;
//
//         let x509_certificate: Option<ApplicationTag0<Asn1RawDer>> = signed_data_option.clone().unwrap().0.certificates.0;
//
//         let x509_der: &'a mut  Vec<u8> = version;
//
//         x509_der.clone_from(&(x509_certificate.unwrap().0).0);
//         //(x509_certificate.unwrap().0).0.clone_into(x509_der);
//
//         let x509: X509Certificate<'a> = parse_x509_der(x509_der).unwrap().1;
//
// //        log(hex::encode(signature.signed_data.unwrap().0.signer_infos.0.get(0).unwrap().clone().signed_attrs.).as_str());
//
//         // Some((
//         //     x509,
//         //     signature.signed_data.unwrap().0.signer_infos.0.get(0).unwrap().clone().signature
//         // ))
//
//         None
//     }
// }

fn extract_signature_and_hash(document: Vec<u8>) -> SignatureAndHash {
    let start_separator = b"/ETSI.CAdES.detached\n/Contents <";
    let start_position = document.windows(start_separator.len()).position(|window| window == start_separator).unwrap() + start_separator.len();

    let end_separator = b">";
    let end_position = document.split_at(start_position).1.windows(end_separator.len()).position(|window| window == end_separator).unwrap() + start_position;


    log(String::from_utf8_lossy(&document[end_position..]).to_string().as_str());

    let document_parts = split_vec_at_positions(document.to_vec(), vec![start_position, end_position]);


    let signature = document_parts[1].clone();

    let mut document_without_signature = document_parts[0].clone();

    document_without_signature.extend(document_parts[2].clone());

    let hash = sha256_digest(&document_without_signature).unwrap();


    SignatureAndHash {
        signature,
        hash
    }
}


// fn extract_certificate_bytes_from_pdf_version(version: &mut Vec<u8>) -> Vec<u8> {
//
//
//     let version_to_string = String::from_utf8_lossy(version.as_slice()).to_string();
//
//     let regex = Regex::new("<[0-9A-Fa-f]*>").unwrap();
//     let certificate_as_hex_str = regex.find(version_to_string.as_str()).unwrap().as_str();
//
//     let certificate_as_hex_str = certificate_as_hex_str.replace("<", "");
//     let certificate_as_hex_str = certificate_as_hex_str.replace(">", "");
//
//     hex::decode(certificate_as_hex_str).unwrap()
// }

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
