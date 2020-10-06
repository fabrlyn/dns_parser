pub fn from_wire_shark(s: String) -> Vec<u8> {
  s.split("\n")
    .filter(|line| line.len() > 0)
    .map(|line| line.chars().skip(7).collect::<String>())
    .map(|line| {
      line
        .split(' ')
        .map(|hex| u8::from_str_radix(&hex[0..2], 16).unwrap())
        .collect::<Vec<u8>>()
    })
    .flatten()
    .collect()
}

mod test {

  #[test]
  fn test_from_wire_shark() {
    let string = "
0020   00 00 00 00 00 05
0030   00 00 00 00 00 01 08 5f 68 6f 6d 65 6b 69 74 04
0040   5f 74 63 70 05 6c 6f 63 61 6c 00 00 0c 80 01 0f
0050   5f 63 6f 6d 70 61 6e 69 6f 6e 2d 6c 69 6e 6b c0
0060   15 00 0c 80 01 08 5f 61 69 72 70 6c 61 79 c0 15
0070   00 0c 80 01 05 5f 72 61 6f 70 c0 15 00 0c 80 01
0080   0c 5f 73 6c 65 65 70 2d 70 72 6f 78 79 04 5f 75
0090   64 70 c0 1a 00 0c 80 01 00 00 29 05 a0 00 00 11
00a0   94 00 12 00 04 00 0e 00 e4 76 42 8b ec 99 88 74
00b0   42 8b ec 99 88

"
    .to_owned();

    let result = super::from_wire_shark(string);
    println!("result: {:?} - {:?}", result.len(), result);
  }
}
