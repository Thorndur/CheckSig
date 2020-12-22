#[test]
fn byte_range_test() {
    //assert_eq!(parse_byte_range(b""), Vec::new());
    assert_eq!(parse_byte_range(b"0 1"), vec![(0,1)]);
    assert_eq!(parse_byte_range(b"0 1 5 7"), vec![(0,1),(5,7)]);
}

pub fn parse_byte_range(byte_range_descriptor: &[u8]) -> Vec<(usize, usize)> {
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