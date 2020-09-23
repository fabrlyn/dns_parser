use crate::shared::ParseError;

const HEADER_SIZE: usize = 12;

type RawHeader = [u8; HEADER_SIZE];

pub type MessageId = u16;

#[derive(Debug, PartialEq, Eq)]
pub enum RCode {
  NoError,
  FormatError,
  ServerFailure,
  NameError,
  NotImplemented,
  Refused,
  Other(u8),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RD {
  RecursionDesired,
  RecursionNotDesired,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QR {
  Query,
  Response,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RA {
  RecursionAvailable,
  RecursionNotAvailable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TC {
  NotTruncated,
  Truncated,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AA {
  NotAuthoritative,
  Authoritative,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpCode {
  Query,
  InverseQuery,
  Status,
  Other(u8),
}

#[derive(Debug)]
pub struct Header {
  pub id: u16,
  pub qr: QR,
  pub op_code: OpCode,
  pub aa: AA,
  pub tc: TC,
  pub rd: RD,
  pub ra: RA,
  pub z: u8,
  pub r_code: RCode,
  pub qd_count: u16,
  pub an_count: u16,
  pub ns_count: u16,
  pub ar_count: u16,
}

pub fn parse_header(data: &[u8]) -> Result<Header, ParseError> {
  if data.len() < HEADER_SIZE {
    return Err(ParseError::HeaderError(String::from(
      "Data is smaller than header",
    )));
  }

  let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
  header.clone_from_slice(&data[0..HEADER_SIZE]);

  Ok(Header {
    id: parse_header_message_id(header),
    qr: parse_header_query_or_response(header),
    op_code: parse_header_op_code(header),
    aa: parse_header_authoritative_answer(header),
    tc: parse_header_truncated(header),
    rd: parse_header_recursion_desired(header),
    ra: parse_header_recursion_available(header),
    z: parse_header_z(header),
    r_code: parse_header_r_code(header),
    qd_count: parse_header_qd_count(header),
    an_count: parse_header_an_count(header),
    ns_count: parse_header_ns_count(header),
    ar_count: parse_header_ar_count(header),
  })
}

fn parse_header_r_code(header: RawHeader) -> RCode {
  let mask = 0b00001111;
  let r_code = mask & header[3];
  match r_code {
    0 => RCode::NoError,
    1 => RCode::FormatError,
    2 => RCode::ServerFailure,
    3 => RCode::NameError,
    4 => RCode::NotImplemented,
    5 => RCode::Refused,
    n => RCode::Other(n),
  }
}

fn parse_header_qd_count(header: RawHeader) -> u16 {
  (header[4] as u16) << 8 | header[5] as u16
}

fn parse_header_an_count(header: RawHeader) -> u16 {
  (header[6] as u16) << 8 | header[7] as u16
}

fn parse_header_ns_count(header: RawHeader) -> u16 {
  (header[8] as u16) << 8 | header[9] as u16
}

fn parse_header_ar_count(header: RawHeader) -> u16 {
  (header[10] as u16) << 8 | header[11] as u16
}

fn parse_header_z(header: RawHeader) -> u8 {
  let mask = 0b01110000;
  (mask & header[3]) >> 4
}

fn parse_header_recursion_available(header: RawHeader) -> RA {
  let mask = 0b10000000;
  let recursion_available = (mask & header[3]) >> 7;
  match recursion_available {
    1 => RA::RecursionAvailable,
    _ => RA::RecursionNotAvailable,
  }
}

fn parse_header_recursion_desired(header: RawHeader) -> RD {
  let mask = 0b00000001;
  let recursion_desired = mask & header[2];
  match recursion_desired {
    1 => RD::RecursionDesired,
    _ => RD::RecursionNotDesired,
  }
}

fn parse_header_message_id(header: RawHeader) -> MessageId {
  (header[0] as u16) << 8 | header[1] as u16
}

fn parse_header_query_or_response(header: RawHeader) -> QR {
  if header[2] >> 7 == 1 {
    QR::Response
  } else {
    QR::Query
  }
}

fn parse_header_op_code(header: RawHeader) -> OpCode {
  let mask = 0b01111000;
  let op_code = (mask & header[2]) >> 3;
  match op_code {
    0 => OpCode::Query,
    1 => OpCode::InverseQuery,
    2 => OpCode::Status,
    n => OpCode::Other(n),
  }
}

fn parse_header_authoritative_answer(header: RawHeader) -> AA {
  let mask = 0b00000100;
  let aa = (mask & header[2]) >> 2;
  match aa {
    1 => AA::Authoritative,
    _ => AA::NotAuthoritative,
  }
}

fn parse_header_truncated(header: RawHeader) -> TC {
  let mask = 0b00000010;
  let truncated = (mask & header[2]) >> 1;
  match truncated {
    1 => TC::Truncated,
    _ => TC::NotTruncated,
  }
}

mod test {

  #[allow(dead_code)]
  const DATA_1: [u8; 383] = [
    0, 2, 132, 0, 0, 0, 0, 1, 0, 0, 0, 3, 11, 95, 103, 111, 111, 103, 108, 101, 99, 97, 115, 116,
    4, 95, 116, 99, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 0, 0, 0, 120, 0, 52, 49, 71,
    111, 111, 103, 108, 101, 45, 72, 111, 109, 101, 45, 77, 105, 110, 105, 45, 101, 48, 55, 49, 57,
    101, 101, 53, 100, 55, 102, 56, 57, 98, 102, 100, 57, 101, 97, 55, 52, 52, 53, 97, 55, 49, 48,
    48, 53, 55, 53, 50, 192, 12, 192, 46, 0, 16, 128, 1, 0, 0, 17, 148, 0, 200, 35, 105, 100, 61,
    101, 48, 55, 49, 57, 101, 101, 53, 100, 55, 102, 56, 57, 98, 102, 100, 57, 101, 97, 55, 52, 52,
    53, 97, 55, 49, 48, 48, 53, 55, 53, 50, 35, 99, 100, 61, 69, 48, 48, 53, 52, 69, 50, 53, 48,
    68, 54, 67, 68, 49, 52, 56, 55, 56, 67, 57, 51, 67, 67, 49, 70, 55, 65, 67, 54, 52, 55, 68, 19,
    114, 109, 61, 52, 49, 55, 55, 50, 65, 55, 66, 56, 56, 54, 51, 70, 66, 48, 69, 5, 118, 101, 61,
    48, 53, 19, 109, 100, 61, 71, 111, 111, 103, 108, 101, 32, 72, 111, 109, 101, 32, 77, 105, 110,
    105, 18, 105, 99, 61, 47, 115, 101, 116, 117, 112, 47, 105, 99, 111, 110, 46, 112, 110, 103,
    22, 102, 110, 61, 76, 105, 118, 105, 110, 103, 32, 82, 111, 111, 109, 32, 115, 112, 101, 97,
    107, 101, 114, 9, 99, 97, 61, 49, 57, 56, 54, 54, 48, 4, 115, 116, 61, 48, 15, 98, 115, 61, 70,
    65, 56, 70, 67, 65, 57, 68, 66, 67, 69, 70, 4, 110, 102, 61, 49, 3, 114, 115, 61, 192, 46, 0,
    33, 128, 1, 0, 0, 0, 120, 0, 45, 0, 0, 0, 0, 31, 73, 36, 101, 48, 55, 49, 57, 101, 101, 53, 45,
    100, 55, 102, 56, 45, 57, 98, 102, 100, 45, 57, 101, 97, 55, 45, 52, 52, 53, 97, 55, 49, 48,
    48, 53, 55, 53, 50, 192, 29, 193, 72, 0, 1, 128, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 137,
  ];

  /*
  Message ID: 0
  QoR: Query(0)
  */
  #[allow(dead_code)]
  const DATA_2: [u8; 154] = [
    0, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 1, 8, 95, 104, 111, 109, 101, 107, 105, 116, 4, 95, 116, 99,
    112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 15, 95, 99, 111, 109, 112, 97, 110, 105, 111,
    110, 45, 108, 105, 110, 107, 192, 21, 0, 12, 0, 1, 12, 95, 115, 108, 101, 101, 112, 45, 112,
    114, 111, 120, 121, 4, 95, 117, 100, 112, 192, 26, 0, 12, 0, 1, 192, 37, 0, 12, 0, 1, 0, 0, 17,
    136, 0, 7, 4, 99, 111, 110, 102, 192, 37, 192, 37, 0, 12, 0, 1, 0, 0, 17, 136, 0, 11, 8, 77,
    97, 99, 98, 111, 111, 107, 49, 192, 37, 0, 0, 41, 5, 160, 0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0,
    105, 118, 66, 139, 236, 153, 136, 116, 66, 139, 236, 153, 136,
  ];

  #[test]
  fn parse_header_op_code_query() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OpCode::Query, op_code);
  }

  #[test]
  fn parse_header_op_code_inverse_query() {
    let data = [0, 0, 0b00001000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OpCode::InverseQuery, op_code);
  }

  #[test]
  fn parse_header_op_code_status() {
    let data = [0, 0, 0b00010000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OpCode::Status, op_code);
  }

  #[test]
  fn parse_header_op_code_other() {
    let data = [0, 0, 0b00101000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OpCode::Other(5), op_code);
  }

  #[test]
  fn parse_header_authoritative_answer_is_authoritative() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let authoritative_answer = super::parse_header_authoritative_answer(data);
    assert_eq!(super::AA::NotAuthoritative, authoritative_answer);
  }

  #[test]
  fn parse_header_authoritative_answer_is_not_authoritative() {
    let data = [0, 0, 0b00000100, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let authoritative_answer = super::parse_header_authoritative_answer(data);
    assert_eq!(super::AA::Authoritative, authoritative_answer);
  }
  #[test]
  fn parse_header_truncation_not_truncated() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let truncated = super::parse_header_truncated(data);
    assert_eq!(super::TC::NotTruncated, truncated);
  }

  #[test]
  fn parse_header_truncation_is_truncated() {
    let data = [0, 0, 0b00000010, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let truncated = super::parse_header_truncated(data);
    assert_eq!(super::TC::Truncated, truncated);
  }

  #[test]
  fn parse_header_recursion_is_desired() {
    let data = [0, 0, 0b00000001, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let recursion_desired = super::parse_header_recursion_desired(data);
    assert_eq!(super::RD::RecursionDesired, recursion_desired);
  }

  #[test]
  fn parse_header_recursion_is_not_desired() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let recursion_desired = super::parse_header_recursion_desired(data);
    assert_eq!(super::RD::RecursionNotDesired, recursion_desired);
  }

  #[test]

  fn parse_header_recursion_available() {
    let data = [0, 0, 0, 0b10000000, 0, 0, 0, 0, 0, 0, 0, 0];
    let recursion_available = super::parse_header_recursion_available(data);
    assert_eq!(super::RA::RecursionAvailable, recursion_available);
  }

  #[test]

  fn parse_header_recursion_not_available() {
    let data = [0, 0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0];
    let recursion_available = super::parse_header_recursion_available(data);
    assert_eq!(super::RA::RecursionNotAvailable, recursion_available);
  }

  #[test]
  fn parse_header_z() {
    let data = [0, 0, 0, 0b01010000, 0, 0, 0, 0, 0, 0, 0, 0];
    let z = super::parse_header_z(data);
    assert_eq!(5, z);
  }

  #[test]
  fn parse_header_r_code_t_no_error() {
    let data = [0, 0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::NoError, r_code);
  }

  #[test]
  fn parse_header_r_code_t_format_error() {
    let data = [0, 0, 0, 0b00000001, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::FormatError, r_code);
  }

  #[test]
  fn parse_header_r_code_t_server_failure() {
    let data = [0, 0, 0, 0b00000010, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::ServerFailure, r_code);
  }

  #[test]
  fn parse_header_r_code_t_name_error() {
    let data = [0, 0, 0, 0b00000011, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::NameError, r_code);
  }

  #[test]
  fn parse_header_r_code_t_not_implemented() {
    let data = [0, 0, 0, 0b00000100, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::NotImplemented, r_code);
  }

  #[test]
  fn parse_header_r_code_t_refused() {
    let data = [0, 0, 0, 0b00000101, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::Refused, r_code);
  }

  #[test]
  fn parse_header_r_code_t_other() {
    let data = [0, 0, 0, 0b00001010, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::RCode::Other(10), r_code);
  }

  #[test]
  fn parse_header_qd_count() {
    let data = [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
    let qd_count = super::parse_header_qd_count(data);
    assert_eq!(257, qd_count);
  }

  #[test]
  fn parse_header_an_count() {
    let data = [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0];
    let an_count = super::parse_header_an_count(data);
    assert_eq!(257, an_count);
  }

  #[test]
  fn parse_header_ns_count() {
    let data = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0];
    let an_count = super::parse_header_ns_count(data);
    assert_eq!(257, an_count);
  }

  #[test]
  fn parse_header_ar_count() {
    let data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    let an_count = super::parse_header_ar_count(data);
    assert_eq!(257, an_count);
  }
}
