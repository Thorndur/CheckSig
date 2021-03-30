use itertools::Itertools;
use anyhow::Context;
use anyhow::Result;
use crate::log;
use chrono::DateTime;
use chrono::FixedOffset;

pub fn extract_signature_message_and_signing_date_time_from_pdf(document: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>, DateTime<FixedOffset>)> {
    let signature_element_start_separator = b"/Type /Sig";
    let signature_element_start_position = document
        .windows(signature_element_start_separator.len())
        .position(|window| window == signature_element_start_separator)
        .context("Signature couldn't be found")? + signature_element_start_separator.len();

    let signature_date_start_separator = b"/M (D:";
    let signature_date_start_position = document.split_at(signature_element_start_position).1
        .windows(signature_date_start_separator.len())
        .position(|window| window == signature_date_start_separator)
        .context("Signature date couldn't be extracted")? + signature_element_start_position + signature_date_start_separator.len();

    let signature_date_end_separator = b")";
    let signature_date_end_position = document.split_at(signature_date_start_position).1
        .windows(signature_date_end_separator.len())
        .position(|window| window == signature_date_end_separator)
        .context("Signature date couldn't be extracted")? + signature_date_start_position;

    let start_separator = b"/Contents <";
    let start_position = document//.split_at(signature_date_end_position).1
        .windows(start_separator.len())
        .position(|window| window == start_separator)
        .context("Signature couldn't be extracted")? + start_separator.len();

    let end_separator = b">";
    let end_position = document.split_at(start_position).1
        .windows(end_separator.len())
        .position(|window| window == end_separator)
        .context("Signature couldn't be extracted")?+ start_position;

    let byte_range_start_separator = b"/ByteRange [";
    let byte_range_start = document.split_at(end_position).1
        .windows(byte_range_start_separator.len())
        .position(|window| window == byte_range_start_separator)
        .context("Signature Message couldn't be extracted")?+ end_position + byte_range_start_separator.len();

    let byte_range_end_separator = b"]";
    let byte_range_end = document.split_at(byte_range_start).1
        .windows(byte_range_end_separator.len())
        .position(|window| window == byte_range_end_separator)
        .context("Signature Message couldn't be extracted")? + byte_range_start;

    let message = parse_byte_range(&document.as_slice()[byte_range_start..byte_range_end])
        .iter()
        .map(|range| document.as_slice()[range.0..(range.0+range.1)].to_vec())
        .concat();

    // first 38 bytes are removed to ignore PAdES wrapper of CMS
    let signature_bytes = document.as_slice()[start_position+38..end_position].to_vec().clone();

    let date = String::from_utf8_lossy(&document.as_slice()[signature_date_start_position..signature_date_end_position]).to_string();


    let parsingDate = date.replace("'", "");

    let datetime = DateTime::parse_from_str(parsingDate.as_str(), "%Y%m%d%H%M%S%z")
        .expect("Signing date couldn't be parsed");

    let signature = hex::decode(
        String::from_utf8_lossy(
            signature_bytes.as_slice()
        ).as_bytes()
    ).context("Signature couldn't be extracted")?;

    Ok((signature, message, datetime))
}

#[test]
fn parse_byte_range_test() {
    //assert_eq!(parse_byte_range(b""), Vec::new());
    assert_eq!(parse_byte_range(b"0 1"), vec![(0,1)]);
    assert_eq!(parse_byte_range(b"0 1 5 7"), vec![(0,1),(5,7)]);
}

fn parse_byte_range(byte_range_descriptor: &[u8]) -> Vec<(usize, usize)> {
    byte_range_descriptor
        .split(|byte| *byte == b' ')
        .map(|slice| String::from_utf8_lossy(slice).to_string().parse::<usize>().unwrap())
        .fold( Vec::new(), |mut byte_slices: Vec<(Option<usize>,Option<usize>)>, limit| {
            match byte_slices.last() {
                None => byte_slices.push((Some(limit), None)),
                Some((Some(t),None)) => {
                    let length = byte_slices.len();
                    byte_slices[length - 1] = (Some(*t), Some(limit))
                },
                Some((Some(_),Some(_))) => byte_slices.push((Some(limit), None)),
                _ => {}
            };
            byte_slices
        })
        .iter()
        .map(|(start, end)| (start.unwrap(), end.unwrap()))
        .collect()
}