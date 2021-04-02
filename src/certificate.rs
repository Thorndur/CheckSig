use std::str;

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, FixedOffset};
use der_parser::oid;
use wasm_bindgen::__rt::core::future::Future;
use wasm_bindgen::__rt::core::pin::Pin;
use web_sys::window;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_certificate;

use crate::cryptography::verify_signed_message;

fn check_root_certificate(
    certificate: X509Certificate,
    signing_date_time: DateTime<FixedOffset>,
) -> Result<()> {
    if !is_in_certificate_valid_timerange(&certificate, &signing_date_time) {
        bail!("Signature date is too old or too new for Root Certificate Validity Timerange");
    } else {
        verify_signature(
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

                    match verify_signature(
                        &certificate,
                        parent_certificate
                            .tbs_certificate
                            .subject_pki
                            .subject_public_key
                            .as_ref(),
                    ) {
                        Ok(_) => check_certificate(parent_certificate, signing_date_time).await,
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

                    verify_signature(
                        &certificate,
                        root_certificate
                            .tbs_certificate
                            .subject_pki
                            .subject_public_key
                            .as_ref(),
                    )
                        .and_then(|_| check_root_certificate(root_certificate, signing_date_time))
                }
            }
        }
    })
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
    return match certificate
        .tbs_certificate
        .extensions()
        .get(&oid!(1.3.6 .1 .5 .5 .7 .1 .1))
    {
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
        None => bail!("Missing Certificate extension: Certificate Authority Information Acces"),
    };
}

fn verify_signature(certificate: &X509Certificate, parent_public_key: &[u8]) -> Result<()> {
    let signature_alg = &certificate.signature_algorithm.algorithm;
    //certificate.verify_signature()

    let public_key = parent_public_key.as_ref();
    let message = certificate.tbs_certificate.as_ref();
    let signature = certificate.signature_value.as_ref();

    verify_signed_message(signature_alg, public_key, message, signature)
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
