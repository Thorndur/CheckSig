use std::str;

use anyhow::{Context, Result, anyhow, bail};

use wasm_bindgen::__rt::core::pin::Pin;
use wasm_bindgen::__rt::core::future::Future;

use x509_parser::{parse_x509_certificate, parse_x509_crl};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{ParsedExtension, GeneralName};

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier;
use crate::log;
use ring::signature::VerificationAlgorithm;


use der_parser::oid;
use oid_registry::*;


pub(crate) fn check_certificate(certificate: X509Certificate) -> Pin<Box<dyn '_ + Future<Output = Result<()>>>> {
    Box::pin(async move {

        // Certificate Authority Information Access

        let authority_info_access_uri_result = get_authority_info_access_uri(&certificate);

        match authority_info_access_uri_result {
            Ok(authority_info_access_uri) => {
                let parent_certificate_vec = fetch_vec_u8_from_url(authority_info_access_uri).await?;

                let (_, parent_certificate) = parse_x509_certificate(parent_certificate_vec.as_slice()).unwrap();

                match verify_signature(&certificate, parent_certificate.tbs_certificate.subject_pki.subject_public_key.as_ref()) {
                    Ok(_) => {

                        match certificate.tbs_certificate.extensions.get(&oid!(2.5.29.31)) {
                            Some(parsed_extension) => {
                                if let ParsedExtension::UnsupportedExtension = parsed_extension.parsed_extension() {
                                    let url_string_end = usize::from(9 + parsed_extension.value[9]);
                                    let url_byte_slice = &parsed_extension.value[10..=url_string_end];
                                    let url = str::from_utf8(url_byte_slice).unwrap();

                                    // log(url.to_string());
                                    //
                                    // let certificate_revocation_list_byte_array = fetch_vec_u8_from_url(url).await?;
                                    //
                                    // log("1".to_string());
                                    // let (_, certificate_revocation_list) = parse_x509_crl(certificate_revocation_list_byte_array.as_slice())?;
                                    //
                                    // log("2".to_string());
                                    // log(certificate_revocation_list.tbs_cert_list.revoked_certificates.len().to_string());
                                    // if (certificate_revocation_list.iter_revoked_certificates().any(|revoked| revoked.user_certificate == certificate.tbs_certificate.serial)) { //&& revoked.revocation_date < signing_date)
                                    //     log("revoked".to_string());
                                    // } else {
                                    //     log("not revoked".to_string());
                                    // }
                                }
                            }
                            None => { bail!("Missing Certificate extension: CRL Distribution Points"); }
                        };
                        check_certificate(parent_certificate).await
                    }
                    Err(_) => {bail!("Certificate Signature is Invalid");}
                }
            }
            Err(_) => {
                Ok(())  //Root Certificate?
            }
        }



    })
}

fn get_authority_info_access_uri<'a>(certificate: &'a X509Certificate) -> Result<&'a str> {
    return match certificate.tbs_certificate.extensions().get(&oid!(1.3.6.1.5.5.7.1.1)) {
        Some(parsed_extension) => {
            if let ParsedExtension::AuthorityInfoAccess(authority_info_access) = parsed_extension.parsed_extension() {

                // Parent Certificate

                if let GeneralName::URI(uri) = authority_info_access.accessdescs.get(&oid!(1.3.6.1.5.5.7.48.2)).unwrap()[0] {
                    Ok(uri)
                } else { bail!("Certificate Authority Information Access Uri is invalid") }
            } else { bail!("Certificate Authority Information Access is invalid") }
        }
        None => bail!("Missing Certificate extension: Certificate Authority Information Acces")
    };
}

fn verify_signature(
    certificate: &X509Certificate,
    parent_public_key: &[u8]
) -> Result<()> {
    use ring::signature;
    let signature_alg = &certificate.signature_algorithm.algorithm;
    log(signature_alg.to_string());
    //certificate.verify_signature()

    if *signature_alg == OID_PKCS1_SHA1WITHRSA {

        return signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY.verify(
            untrusted::Input::from(parent_public_key.as_ref()),
            untrusted::Input::from(certificate.tbs_certificate.as_ref()),
            untrusted::Input::from(certificate.signature_value.as_ref()),
        ).context("Certificate Verification failed");

    } else if *signature_alg == OID_PKCS1_SHA256WITHRSA {

        return signature::RSA_PKCS1_2048_8192_SHA256.verify(
            untrusted::Input::from(parent_public_key.as_ref()),
            untrusted::Input::from(certificate.tbs_certificate.as_ref()),
            untrusted::Input::from(certificate.signature_value.as_ref()),
        ).context("Certificate Verification failed");

    } else if *signature_alg == OID_PKCS1_SHA384WITHRSA {

        return signature::RSA_PKCS1_2048_8192_SHA384.verify(
            untrusted::Input::from(parent_public_key.as_ref()),
            untrusted::Input::from(certificate.tbs_certificate.as_ref()),
            untrusted::Input::from(certificate.signature_value.as_ref()),
        ).context("Certificate Verification failed");

    } else if *signature_alg == OID_PKCS1_SHA512WITHRSA {

        return signature::RSA_PKCS1_2048_8192_SHA512.verify(
            untrusted::Input::from(parent_public_key.as_ref()),
            untrusted::Input::from(certificate.tbs_certificate.as_ref()),
            untrusted::Input::from(certificate.signature_value.as_ref()),
        ).context("Certificate Verification failed");

    } else if *signature_alg == OID_SIG_ECDSA_WITH_SHA256 {

        let signature = Signature::from_asn1(&certificate.signature_value.as_ref()).unwrap();

        let public_key = VerifyingKey::from_sec1_bytes(parent_public_key.as_ref()).unwrap();


        let result = match public_key.verify(certificate.tbs_certificate.as_ref(), &signature){
            Ok(_) => Ok(()),
            Err(_) => Err(anyhow!("Certificate Verification failed"))
        };
        return result;

    }else {
        bail!("Unsupported Signature Algorithm");
    };

}

async fn fetch_vec_u8_from_url(url: &str) -> Result<Vec<u8>> {
    log(format!("fetching {}", url).to_string());
    let response = reqwest::get(url).await.context(format!("{} couldnt be loaded", url))?;
    Ok(response.bytes().await?.to_vec())
}