use std::collections::HashSet;
use std::iter::FromIterator;
use std::str;

use anyhow::{anyhow, bail, Context, Error, Result};
use chrono::{DateTime, FixedOffset};
use der_parser::num_bigint::BigUint;
use der_parser::oid;
use wasm_bindgen::__rt::core::future::Future;
use wasm_bindgen::__rt::core::pin::Pin;
use web_sys::window;
use x509_parser::{parse_x509_certificate, parse_x509_crl};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};

use crate::cryptography::verify_signed_message;
use crate::log;

fn check_root_certificate(
    certificate: X509Certificate,
    signing_date_time: DateTime<FixedOffset>,
) -> Result<()> {
    if !is_in_certificate_valid_timerange(&certificate, &signing_date_time) {
        bail!("Signature date is too old or too new for Root Certificate Validity Timerange");
    } else {
        verify_certificate_signature(
            &certificate,
            certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .as_ref(),
        )
    }
}

pub(crate) fn check_certificate(
    certificate: X509Certificate,
    signing_date_time: DateTime<FixedOffset>,
) -> Pin<Box<dyn '_ + Future<Output=Result<()>>>> {
    Box::pin(async move {
        if !is_in_certificate_valid_timerange(&certificate, &signing_date_time) {
            bail!("Signature date is too old or too new for Certificate Validity Timerange");
        } else {
            // Certificate Authority Information Access

            let authority_info_access_uri_result = get_authority_info_access_uri(&certificate);

            match authority_info_access_uri_result {
                Ok(parent_certificate_url) => {
                    let parent_certificate_vec = fetch_vec_u8_from_url(parent_certificate_url)
                        .await
                        .context(format!(
                            "Parent certificate from {} couldn't be loaded",
                            parent_certificate_url
                        ))?;

                    let (_, parent_certificate) =
                        parse_x509_certificate(parent_certificate_vec.as_slice())
                            .context("Parent certificate couldn't be parsed")?;

                    match verify_certificate_signature(
                        &certificate,
                        parent_certificate
                            .tbs_certificate
                            .subject_pki
                            .subject_public_key
                            .as_ref(),
                    ) {
                        Ok(_) => {
                            check_certificate(parent_certificate, signing_date_time).await
                            //  match check_crl(&certificate).await {
                            //      Ok(_) => check_certificate(parent_certificate, signing_date_time).await,
                            //      Err(error) => bail!("Certificate not valid: {}", error.to_string())
                            //  }
                        },
                        Err(_) => bail!("Certificate Signature is Invalid"),
                    }
                }
                Err(_) => {
                    let root_certificate_url = get_root_cert_url(&certificate)?;


                    let root_certificate_vec = fetch_vec_u8_from_url(root_certificate_url.as_str())
                        .await
                        .context(format!(
                            "root certificate from {} couldn't be loaded",
                            root_certificate_url
                        ))?;

                    let (_, root_certificate) =
                        parse_x509_certificate(root_certificate_vec.as_slice())
                            .context("Root certificate couldn't be parsed")?;

                    match verify_certificate_signature(
                        &certificate,
                        root_certificate
                            .tbs_certificate
                            .subject_pki
                            .subject_public_key
                            .as_ref(),
                    ) {
                        Ok(_) => {
                            check_root_certificate(root_certificate, signing_date_time)
                            // match check_crl(&certificate).await {
                            //     Ok(_) => check_root_certificate(root_certificate, signing_date_time),
                            //     Err(error) => bail!("Certificate not valid: {}", error.to_string())
                            // }
                        }
                        Err(error) => bail!("Certificate not valid: {}", error.to_string())
                    }
                    //    .and_then(|_| check_root_certificate(root_certificate, signing_date_time))
                }
            }
        }
    })
}

async fn check_crl<'a>(certificate: &X509Certificate<'a>) -> Result<()> {
    let crl_uri = get_crl_uri(&certificate)?;


    log(crl_uri.to_string());
    let certificate_revocation_list_byte_array = fetch_vec_u8_from_url(crl_uri).await?;
    let (_, certificate_revocation_list) = parse_x509_crl(certificate_revocation_list_byte_array.as_slice())?;
    let revokedCerts: HashSet<BigUint> = certificate_revocation_list.iter_revoked_certificates().map(|revoked| revoked.user_certificate.clone()).collect();

    if revokedCerts.contains(&certificate.tbs_certificate.serial) { //&& revoked.revocation_date < signing_date)
        bail!("Certificate is Revoked")
    } else {
        Ok(())
    }
}

fn is_in_certificate_valid_timerange(
    certificate: &X509Certificate,
    signing_date_time: &DateTime<FixedOffset>,
) -> bool {
    let certificate_validity_start_date_time =
        DateTime::parse_from_rfc2822(certificate.validity().not_before.to_rfc2822().as_str())
            .unwrap();

    let certificate_validity_end_date_time =
        DateTime::parse_from_rfc2822(certificate.validity().not_after.to_rfc2822().as_str())
            .unwrap();

    certificate_validity_start_date_time < *signing_date_time
        && *signing_date_time < certificate_validity_end_date_time
}

fn get_root_cert_url(certificate: &X509Certificate) -> Result<String> {
    let issuer_common_name = certificate
        .tbs_certificate
        .issuer
        .iter_common_name()
        .next()
        .context("missing common name")?
        .attr_value
        .content
        .as_str()
        .context("missing common name")?;

    Ok(format!("./certs/{}.crt", issuer_common_name))
}

fn get_authority_info_access_uri<'a>(certificate: &'a X509Certificate) -> Result<&'a str> {
    match certificate.tbs_certificate.extensions().get(&oid!(1.3.6 .1 .5 .5 .7 .1 .1)) {
        Some(parsed_extension) => {
            if let ParsedExtension::AuthorityInfoAccess(authority_info_access) =
            parsed_extension.parsed_extension()
            {
                // Parent Certificate

                if let GeneralName::URI(uri) = authority_info_access
                    .accessdescs
                    .get(&oid!(1.3.6 .1 .5 .5 .7 .48 .2))
                    .unwrap()[0]
                {
                    Ok(uri)
                } else {
                    bail!("Certificate Authority Information Access Uri is invalid")
                }
            } else {
                bail!("Certificate Authority Information Access is invalid")
            }
        }
        None => bail!("Missing Certificate extension: Certificate Authority Information Access"),
    }
}

fn get_crl_uri<'a>(certificate: &'a X509Certificate) -> Result<&'a str> {
    match certificate.tbs_certificate.extensions.get(&oid!(2.5.29.31)) {
        Some(parsed_extension) => {
            let url_byte_slice = &parsed_extension.value[10..parsed_extension.value.len()];
            let url = str::from_utf8(url_byte_slice).unwrap();
            Ok(url)
        }
        None => { bail!("Missing Certificate extension: CRL Distribution Points"); }
    }
}


fn verify_certificate_signature(certificate: &X509Certificate, parent_public_key: &[u8]) -> Result<()> {
    let signature_alg = &certificate.signature_algorithm.algorithm;
    //certificate.verify_signature()

    let public_key = parent_public_key.as_ref();
    let message = certificate.tbs_certificate.as_ref();
    let signature = certificate.signature_value.as_ref();

    verify_signed_message(signature_alg, public_key, message, signature).map_err(|error| anyhow!("Signature Couldn't be Verified: {}", error.to_string()))
}

async fn fetch_vec_u8_from_url(url: &str) -> Result<Vec<u8>> {
    if url.len() > 0 {
        let absoute_url;

        if url.chars().next().unwrap() == '.' {
            let location_origin = window()
                .context("Origin Url couldn't be detected")?
                .location()
                .origin()
                .map_err(|_| anyhow!("Origin Url couldn't be detected"))?;

            absoute_url = format!("{}{}", location_origin, url[1..].to_string());
        } else {
            absoute_url = url.to_string();
        }

        let response = reqwest::get(&absoute_url)
            .await
            .context(format!("{} couldn't be fetched", absoute_url))?;

        let response_bytes = response.bytes().await?.to_vec();

        Ok(response_bytes)
    } else {
        bail!("Cant fetch from empty ulr")
    }
}
