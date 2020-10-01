use crate::shared::ParseError;
use serde::{Deserialize, Serialize};

const HEADER_SIZE: usize = 12;

type RawHeader = [u8; HEADER_SIZE];

pub type MessageId = u16;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ResponseCode {
  NoError,
  FormatError,
  ServerFailure,
  NameError,
  NotImplemented,
  Refused,
  Other,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum RecursionDesired {
  RecursionDesired,
  RecursionNotDesired,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum QueryOrResponse {
  Query,
  Response,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum RA {
  RecursionAvailable,
  RecursionNotAvailable,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Truncation {
  NotTruncated,
  Truncated,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AuthoritativeAnswer {
  NotAuthoritative,
  Authoritative,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum OperationCode {
  Query,
  InverseQuery,
  Status,
  Other,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
  pub id: MessageId,
  pub query_or_response: QueryOrResponse,
  pub operation_code: OperationCode,
  pub operation_code_value: u8,
  pub authoritative_answer: AuthoritativeAnswer,
  pub truncation: Truncation,
  pub recursion_desired: RecursionDesired,
  pub recursion_available: RA,
  pub z: u8,
  pub response_code: ResponseCode,
  pub response_code_value: u8,
  pub question_count: u16,
  pub answer_count: u16,
  pub name_server_count: u16,
  pub additional_count: u16,
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
    query_or_response: parse_header_query_or_response(header),
    operation_code: parse_header_op_code(header),
    operation_code_value: parse_header_op_code_value(header),
    authoritative_answer: parse_header_authoritative_answer(header),
    truncation: parse_header_truncated(header),
    recursion_desired: parse_header_recursion_desired(header),
    recursion_available: parse_header_recursion_available(header),
    z: parse_header_z(header),
    response_code: parse_header_r_code(header),
    response_code_value: parse_header_response_code_value(header),
    question_count: parse_header_qd_count(header),
    answer_count: parse_header_an_count(header),
    name_server_count: parse_header_ns_count(header),
    additional_count: parse_header_ar_count(header),
  })
}

fn parse_header_r_code(header: RawHeader) -> ResponseCode {
  let mask = 0b00001111;
  let r_code = mask & header[3];
  match r_code {
    0 => ResponseCode::NoError,
    1 => ResponseCode::FormatError,
    2 => ResponseCode::ServerFailure,
    3 => ResponseCode::NameError,
    4 => ResponseCode::NotImplemented,
    5 => ResponseCode::Refused,
    _ => ResponseCode::Other,
  }
}

fn parse_header_response_code_value(header: RawHeader) -> u8 {
  let mask = 0b00001111;
  mask & header[3]
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

fn parse_header_recursion_desired(header: RawHeader) -> RecursionDesired {
  let mask = 0b00000001;
  let recursion_desired = mask & header[2];
  match recursion_desired {
    1 => RecursionDesired::RecursionDesired,
    _ => RecursionDesired::RecursionNotDesired,
  }
}

fn parse_header_message_id(header: RawHeader) -> MessageId {
  (header[0] as u16) << 8 | header[1] as u16
}

fn parse_header_query_or_response(header: RawHeader) -> QueryOrResponse {
  if header[2] >> 7 == 1 {
    QueryOrResponse::Response
  } else {
    QueryOrResponse::Query
  }
}

fn parse_header_op_code(header: RawHeader) -> OperationCode {
  let mask = 0b01111000;
  let op_code = (mask & header[2]) >> 3;
  match op_code {
    0 => OperationCode::Query,
    1 => OperationCode::InverseQuery,
    2 => OperationCode::Status,
    _ => OperationCode::Other,
  }
}

fn parse_header_op_code_value(header: RawHeader) -> u8 {
  let mask = 0b01111000;
  (mask & header[2]) >> 3
}

fn parse_header_authoritative_answer(header: RawHeader) -> AuthoritativeAnswer {
  let mask = 0b00000100;
  let aa = (mask & header[2]) >> 2;
  match aa {
    1 => AuthoritativeAnswer::Authoritative,
    _ => AuthoritativeAnswer::NotAuthoritative,
  }
}

fn parse_header_truncated(header: RawHeader) -> Truncation {
  let mask = 0b00000010;
  let truncated = (mask & header[2]) >> 1;
  match truncated {
    1 => Truncation::Truncated,
    _ => Truncation::NotTruncated,
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
    assert_eq!(super::OperationCode::Query, op_code);
  }

  #[test]
  fn parse_header_op_code_inverse_query() {
    let data = [0, 0, 0b00001000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OperationCode::InverseQuery, op_code);
  }

  #[test]
  fn parse_header_op_code_status() {
    let data = [0, 0, 0b00010000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OperationCode::Status, op_code);
  }

  #[test]
  fn parse_header_op_code_other() {
    let data = [0, 0, 0b00101000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let op_code = super::parse_header_op_code(data);
    assert_eq!(super::OperationCode::Other, op_code);
  }

  #[test]
  fn parse_header_authoritative_answer_is_authoritative() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let authoritative_answer = super::parse_header_authoritative_answer(data);
    assert_eq!(
      super::AuthoritativeAnswer::NotAuthoritative,
      authoritative_answer
    );
  }

  #[test]
  fn parse_header_authoritative_answer_is_not_authoritative() {
    let data = [0, 0, 0b00000100, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let authoritative_answer = super::parse_header_authoritative_answer(data);
    assert_eq!(
      super::AuthoritativeAnswer::Authoritative,
      authoritative_answer
    );
  }
  #[test]
  fn parse_header_truncation_not_truncated() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let truncated = super::parse_header_truncated(data);
    assert_eq!(super::Truncation::NotTruncated, truncated);
  }

  #[test]
  fn parse_header_truncation_is_truncated() {
    let data = [0, 0, 0b00000010, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let truncated = super::parse_header_truncated(data);
    assert_eq!(super::Truncation::Truncated, truncated);
  }

  #[test]
  fn parse_header_recursion_is_desired() {
    let data = [0, 0, 0b00000001, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let recursion_desired = super::parse_header_recursion_desired(data);
    assert_eq!(super::RecursionDesired::RecursionDesired, recursion_desired);
  }

  #[test]
  fn parse_header_recursion_is_not_desired() {
    let data = [0, 0, 0b00000000, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let recursion_desired = super::parse_header_recursion_desired(data);
    assert_eq!(
      super::RecursionDesired::RecursionNotDesired,
      recursion_desired
    );
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
    assert_eq!(super::ResponseCode::NoError, r_code);
  }

  #[test]
  fn parse_header_r_code_t_format_error() {
    let data = [0, 0, 0, 0b00000001, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::ResponseCode::FormatError, r_code);
  }

  #[test]
  fn parse_header_r_code_t_server_failure() {
    let data = [0, 0, 0, 0b00000010, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::ResponseCode::ServerFailure, r_code);
  }

  #[test]
  fn parse_header_r_code_t_name_error() {
    let data = [0, 0, 0, 0b00000011, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::ResponseCode::NameError, r_code);
  }

  #[test]
  fn parse_header_r_code_t_not_implemented() {
    let data = [0, 0, 0, 0b00000100, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::ResponseCode::NotImplemented, r_code);
  }

  #[test]
  fn parse_header_r_code_t_refused() {
    let data = [0, 0, 0, 0b00000101, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::ResponseCode::Refused, r_code);
  }

  #[test]
  fn parse_header_r_code_t_other() {
    let data = [0, 0, 0, 0b00001010, 0, 0, 0, 0, 0, 0, 0, 0];
    let r_code = super::parse_header_r_code(data);
    assert_eq!(super::ResponseCode::Other, r_code);
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
