use net2::unix::UnixUdpBuilderExt;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
enum RCode {
  NoError,
  FormatError,
  ServerFailure,
  NameError,
  NotImplemented,
  Refused,
  Other(u8),
}

#[derive(Debug, PartialEq, Eq)]
enum RD {
  RecursionDesired,
  RecursionNotDesired,
}

#[derive(Debug, PartialEq, Eq)]
enum QR {
  Query,
  Response,
}

#[derive(Debug, PartialEq, Eq)]
enum RA {
  RecursionAvailable,
  RecursionNotAvailable,
}

#[derive(Debug, PartialEq, Eq)]
enum TC {
  NotTruncated,
  Truncated,
}

#[derive(Debug, PartialEq, Eq)]
enum AA {
  NotAuthoritative,
  Authoritative,
}

#[derive(Debug, PartialEq, Eq)]
enum OpCode {
  Query,
  InverseQuery,
  Status,
  Other(u8),
}

#[derive(Debug, PartialEq, Eq)]
enum ParseError {
  HeaderError(String),
  QueryLabelError(String),
  QueryError(String),
}

type MessageId = u16;

type RawHeader = [u8; HEADER_SIZE];

#[derive(Debug)]
struct Header {
  id: u16,
  qr: QR,
  op_code: OpCode,
  aa: AA,
  tc: TC,
  rd: RD,
  ra: RA,
  z: u8,
  r_code: RCode,
  qd_count: u16,
  an_count: u16,
  ns_count: u16,
  ar_count: u16,
}

#[derive(Debug, PartialEq, Eq)]
enum Type {
  Invalid,
  A,
  NS,
  MD,
  MF,
  CNAME,
  SOA,
  MB,
  MG,
  MR,
  NULL,
  WKS,
  PTR,
  HINFO,
  MINFO,
  MX,
  TXT,
}

#[derive(Debug, PartialEq, Eq)]
enum QType {
  Type(Type),
  AXFR,
  MAILB,
  MAILA,
  Any,
}

#[derive(Debug, PartialEq, Eq)]
enum Class {
  Invalid,
  IN,
  CS,
  CH,
  HS,
}

#[derive(Debug, PartialEq, Eq)]
enum QClass {
  Any,
  Class(Class),
}

#[derive(Debug, PartialEq, Eq)]
struct Query {
  labels: Vec<String>,
  q_type: QType,
  q_class: QClass,
}

impl Query {
  fn size(&self) -> usize {
    let mut sum = self
      .labels
      .iter()
      .fold(self.labels.len(), |sum, s| sum + s.len());

    if sum == 0 {
      sum = 1;
    }

    sum + 2 + 2 + 1
  }
}

const HEADER_SIZE: usize = 12;
const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const MULTICAST_PORT: u16 = 5353;

/*
https://justanapplication.wordpress.com/category/dns/dns-resource-records/dns-srv-record/

https://tools.ietf.org/html/rfc5395 -> Has packet structure
https://tools.ietf.org/html/rfc2136
https://tools.ietf.org/html/rfc6195

https://flylib.com/books/en/3.223.1.151/1/ <- Pretty clear

https://tools.ietf.org/html/rfc1035 -> 4.1.1
                              1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   OpCode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                QDCOUNT/ZOCOUNT                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                ANCOUNT/PRCOUNT                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                NSCOUNT/UPCOUNT                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

fn parse(data: &[u8]) -> Result<(Header, Vec<Query>), ParseError> {
  let raw_header = copy_header(data)?;
  let header = parse_header(raw_header);
  println!("header: {:?}", header);
  let queries = parse_queries(&header, &data[12..])?;
  Ok((header, queries))
}

fn parse_query(data: &[u8]) -> Result<Query, ParseError> {
  let labels = parse_question_query_labels(data)?;
  let mut offset = labels.iter().fold(labels.len() + 1, |sum, l| sum + l.len());

  if data.len() < offset + 4 {
    return Err(ParseError::QueryError(
      "Data not long enough for query".to_owned(),
    ));
  }

  let mut q_type_data: [u8; 2] = [0; 2];
  q_type_data.copy_from_slice(&data[offset..offset + 2]);
  let q_type = parse_q_type(q_type_data);

  let mut q_class_data: [u8; 2] = [0; 2];
  q_class_data.copy_from_slice(&data[offset + 2..offset + 4]);
  let q_class = parse_q_class(q_class_data);

  Ok(Query {
    labels,
    q_type,
    q_class,
  })
}

fn parse_class(data: [u8; 2]) -> Class {
  let class = (data[0] as u16) << 8 | data[1] as u16;
  match class {
    1 => Class::IN,
    2 => Class::CS,
    3 => Class::CH,
    4 => Class::HS,
    _ => Class::Invalid,
  }
}

fn parse_q_class(data: [u8; 2]) -> QClass {
  let class = (data[0] as u16) << 8 | data[1] as u16;
  match class {
    255 => QClass::Any,
    _ => QClass::Class(parse_class(data)),
  }
}

fn parse_type(data: [u8; 2]) -> Type {
  let t = (data[0] as u16) << 8 | data[1] as u16;
  println!("parse_type - data: {:?}", data);
  match t {
    1 => Type::A,
    2 => Type::NS,
    3 => Type::MD,
    4 => Type::MF,
    5 => Type::CNAME,
    6 => Type::SOA,
    7 => Type::MB,
    8 => Type::MG,
    9 => Type::MR,
    10 => Type::NULL,
    11 => Type::WKS,
    12 => Type::PTR,
    13 => Type::HINFO,
    14 => Type::MINFO,
    15 => Type::MX,
    16 => Type::TXT,
    _ => Type::Invalid,
  }
}

fn parse_q_type(data: [u8; 2]) -> QType {
  let q_type = (data[0] as u16) << 8 | data[1] as u16;
  match q_type {
    252 => QType::AXFR,
    253 => QType::MAILB,
    254 => QType::MAILA,
    255 => QType::Any,
    _ => QType::Type(parse_type(data)),
  }
}

fn parse_queries(header: &Header, data: &[u8]) -> Result<Vec<Query>, ParseError> {
  //println!("{:?}", data);
  let mut queries = vec![];
  let mut previous_index = 0;
  println!("qd_count:{:?}", header.qd_count);
  for _ in 0..header.qd_count {
    println!("previously {:?}", previous_index);
    println!("{:?}\n", &data[previous_index..]);
    let query = parse_query(&data[previous_index..])?;
    println!("query: {:?}", query);
    previous_index += query.size();
    queries.push(query);
  }
  Ok(queries)
}

fn parse_question_query_name_label(data: &[u8]) -> Result<Option<String>, ParseError> {
  let data_len = data.len();
  if data_len == 0 {
    return Err(ParseError::QueryLabelError(
      "Data is zero length".to_owned(),
    ));
  }

  let count = data[0];
  if count == 0 {
    return Ok(None);
  }

  if (count as usize) > (data_len - 1) {
    return Err(ParseError::QueryLabelError(
      "Wrong label count. Count would overflow data".to_owned(),
    ));
  }

  if count > 63 {
    return Err(ParseError::QueryLabelError(
      "Count exceeds limit of 63".to_owned(),
    ));
  }

  let label_data = &data[1..((count + 1) as usize)];
  for &i in label_data {
    if i == 0 {
      return Err(ParseError::QueryLabelError(
        "Zero encountered before end of label".to_owned(),
      ));
    }
  }

  std::str::from_utf8(label_data)
    .map(|s| Some(s.to_owned()))
    .map_err(|e| ParseError::QueryLabelError(e.to_string()))
}

fn parse_question_query_labels(data: &[u8]) -> Result<Vec<String>, ParseError> {
  let mut name = vec![];
  let mut previous_count = 0;
  let mut data = &data[previous_count..];
  loop {
    if let Some(label) = parse_question_query_name_label(&data)? {
      previous_count = label.len() + 1;
      name.push(label);
      data = &data[previous_count..];
    } else {
      return Ok(name);
    }
  }
}

fn copy_header(message: &[u8]) -> Result<RawHeader, ParseError> {
  if message.len() < HEADER_SIZE {
    return Err(ParseError::HeaderError(String::from(
      "message is smaller than header",
    )));
  }

  let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
  header.clone_from_slice(&message[0..HEADER_SIZE]);
  Ok(header)
}

fn parse_header(header: RawHeader) -> Header {
  Header {
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
  }
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

pub fn net_mdns() {
  let socket = net2::UdpBuilder::new_v4()
    .unwrap()
    .reuse_address(true)
    .unwrap()
    .reuse_port(true)
    .unwrap()
    .bind((ADDR_ANY, MULTICAST_PORT))
    .unwrap();

  socket.set_multicast_loop_v4(false).unwrap();
  socket
    .join_multicast_v4(&MULTICAST_ADDR, &Ipv4Addr::new(0, 0, 0, 0))
    .unwrap();

  let mut buf = [0u8; 65535];
  loop {
    let (amt, src) = socket.recv_from(&mut buf).unwrap();
    let header = parse(&buf[0..amt]);
    println!("{} sent header {:?}", src, header);
    match header {
      Ok((header, queries)) => {
        println!("header: {:?}", header);
        println!("queries: {:?}", queries);
      }
      Err(e) => {
        println!("Failed to parse header: {:?}", e);
      }
    }

    //println!("received {} bytes from {:?}", amt, src);
    let data = &mut buf[..amt];
    for i in data {
      print!("{:?}, ", i);
    }
    println!("\n");
  }
}

/*
Message ID: 2
QoR: Response(1)
*/
mod test {
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
  fn try_and_copy_header_and_return_header() {
    let result = super::copy_header(&DATA_1);
    if let Err(e) = result {
      assert!(false, e);
    }
  }

  #[test]
  fn try_and_copy_header_and_fail() {
    let result = super::copy_header(&DATA_1[0..(super::HEADER_SIZE - 1)]);
    if let Ok(_) = result {
      assert!(false, "Header copy should fail")
    }
  }

  #[test]
  fn parse_header_message_id() {
    let result = super::copy_header(&DATA_1);
    if let Ok(header) = result {
      let message_id = super::parse_header_message_id(header);
      assert_eq!(2, message_id);
    } else {
      assert!(false);
    }
  }

  #[test]
  fn parse_header_query_or_response_t_is_query() {
    let result = super::copy_header(&DATA_2);
    if let Ok(header) = result {
      let query_or_response = super::parse_header_query_or_response(header);
      assert_eq!(super::QR::Query, query_or_response);
    } else {
      assert!(false);
    }
  }

  #[test]
  fn parse_header_query_or_response_t_is_response() {
    let result = super::copy_header(&DATA_1);
    if let Ok(header) = result {
      let query_or_response = super::parse_header_query_or_response(header);
      assert_eq!(super::QR::Response, query_or_response);
    } else {
      assert!(false);
    }
  }

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

  #[test]
  fn parse_question_query_name_label_with_zero_length() {
    if let Ok(_) = super::parse_question_query_name_label(&[]) {
      assert!(false);
    }
  }

  #[test]
  fn parse_question_query_name_label_with_count_zero() {
    let result = super::parse_question_query_name_label(&[0]);
    assert_eq!(Ok(None), result);
  }

  #[test]
  fn parse_question_query_name_label_with_overflowing_count() {
    match super::parse_question_query_name_label(&[1]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      n => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_question_query_name_label_with_higher_than_63() {
    match super::parse_question_query_name_label(&[64]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_question_query_name_label_with_premature_zero() {
    match super::parse_question_query_name_label(&[4, 97, 98, 0, 99]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_question_query_name_label_with_text_abc() {
    let result = super::parse_question_query_name_label(&[3, 97, 98, 99]);
    assert_eq!(Ok(Some("abc".to_owned())), result);
  }

  #[test]
  fn parse_question_query_labels_with_three_sections() {
    let result =
      super::parse_question_query_labels(&[3, 97, 98, 99, 2, 100, 101, 4, 102, 103, 104, 105, 0]);
    println!("{:?}", result);
  }

  #[test]
  fn parse_type() {
    let test_data = [
      ([0, 0], super::Type::Invalid),
      ([0, 1], super::Type::A),
      ([0, 2], super::Type::NS),
      ([0, 3], super::Type::MD),
      ([0, 4], super::Type::MF),
      ([0, 5], super::Type::CNAME),
      ([0, 6], super::Type::SOA),
      ([0, 7], super::Type::MB),
      ([0, 8], super::Type::MG),
      ([0, 9], super::Type::MR),
      ([0, 10], super::Type::NULL),
      ([0, 11], super::Type::WKS),
      ([0, 12], super::Type::PTR),
      ([0, 13], super::Type::HINFO),
      ([0, 14], super::Type::MINFO),
      ([0, 15], super::Type::MX),
      ([0, 16], super::Type::TXT),
      ([0, 17], super::Type::Invalid),
    ];

    for td in &test_data {
      let result = super::parse_type(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn parse_q_type() {
    let test_data = [
      ([0, 254], super::QType::MAILA),
      ([0, 253], super::QType::MAILB),
      ([0, 252], super::QType::AXFR),
      ([0, 255], super::QType::Any),
      ([0, 1], super::QType::Type(super::Type::A)),
      ([0, 0], super::QType::Type(super::Type::Invalid)),
    ];

    for td in &test_data {
      let result = super::parse_q_type(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn parse_class() {
    let test_data = [
      ([0, 0], super::Class::Invalid),
      ([0, 1], super::Class::IN),
      ([0, 2], super::Class::CS),
      ([0, 3], super::Class::CH),
      ([0, 4], super::Class::HS),
      ([0, 5], super::Class::Invalid),
    ];

    for td in &test_data {
      let result = super::parse_class(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn parse_q_class() {
    let test_data = [
      ([0, 255], super::QClass::Any),
      ([0, 1], super::QClass::Class(super::Class::IN)),
      ([0, 5], super::QClass::Class(super::Class::Invalid)),
    ];

    for td in &test_data {
      let result = super::parse_q_class(td.0);
      assert_eq!(td.1, result);
    }
  }

  #[test]
  fn query_size_when_empty() {
    let query = super::Query {
      labels: vec![],
      q_type: super::QType::Any,
      q_class: super::QClass::Any,
    };
    assert_eq!(6, query.size());
  }

  #[test]
  fn query_size_with_two_labels() {
    let query = super::Query {
      labels: vec!["abc".to_owned(), "de".to_owned()],
      q_type: super::QType::Any,
      q_class: super::QClass::Any,
    };
    assert_eq!(12, query.size());
  }

  #[test]
  fn parse_query_with_to_short_data() {
    let data = [0, 1, 0, 0];
    let result = super::parse_query(&data);
    match result {
      Err(super::ParseError::QueryError(_)) => {}
      _ => assert!(false),
    }
  }

  #[test]
  fn parse_query_without_labels() {
    let data = [0, 0, 1, 0, 1];
    let result = super::parse_query(&data);
    assert_eq!(
      Ok(super::Query {
        labels: vec![],
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN)
      }),
      result
    );
  }

  #[test]
  fn parse_query_with_three_labels() {
    let data = [
      3, 97, 98, 99, 2, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let result = super::parse_query(&data);
    assert_eq!(
      Ok(super::Query {
        labels: vec!["abc".to_owned(), "de".to_owned(), "fghi".to_owned()],
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN)
      }),
      result
    );
  }

  #[test]
  fn parse_queries() {
    let header_data = [0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];

    let data_piece_one = [
      3, 97, 98, 99, 2, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let data_piece_two = [
      2, 97, 98, 3, 99, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let data = [data_piece_one, data_piece_two].concat();

    let header = super::parse_header(header_data);
    let result = super::parse_queries(&header, &data);
    let expected = Ok(vec![
      super::Query {
        labels: vec!["abc".to_owned(), "de".to_owned(), "fghi".to_owned()],
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN),
      },
      super::Query {
        labels: vec!["ab".to_owned(), "cde".to_owned(), "fghi".to_owned()],
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN),
      },
    ]);

    assert_eq!(expected, result);
  }

  #[test]
  fn parse_test() {
    let data = [
      0, 0, 0, 0, 0, 5, 0, 1, 0, 0, 0, 1, 8, 95, 104, 111, 109, 101, 107, 105, 116, 4, 95, 116, 99,
      112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 15, 95, 99, 111, 109, 112, 97, 110, 105, 111,
      110, 45, 108, 105, 110, 107, 192, 21, 0, 12, 0, 1, 8, 95, 97, 105, 114, 112, 108, 97, 121,
      192, 21, 0, 12, 0, 1, 5, 95, 114, 97, 111, 112, 192, 21, 0, 12, 0, 1, 12, 95, 115, 108, 101,
      101, 112, 45, 112, 114, 111, 120, 121, 4, 95, 117, 100, 112, 192, 26, 0, 12, 0, 1, 192, 37,
      0, 12, 0, 1, 0, 0, 17, 148, 0, 11, 8, 77, 97, 99, 98, 111, 111, 107, 49, 192, 37, 0, 0, 41,
      5, 160, 0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0, 5, 118, 66, 139, 236, 153, 136, 116, 66, 139,
      236, 153, 136,
    ];
    let result = super::parse(&data);
    println!("result: {:?}", result);
    let char_data: String = data[(8 + 1 + 4 + 1 + 5 + 1 + 12)..]
      .iter()
      .map(|n| *n as char)
      .collect();
    println!("char data: {:?}", char_data);
  }
}

/*

A Domain Name point to a Node.
A node can have zero or more Resource Records
Resource Records containing the same: NAME, CLASS, TYPE, are consider to belong to the same Resource Record Set
A Resource Record is consider unique based on the above Set rule including also comparing: RDLENGTH and RDATA

*/
