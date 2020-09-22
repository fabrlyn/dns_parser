use crate::header::{parse_header, Header};
use crate::shared::ParseError;
use net2::unix::UnixUdpBuilderExt;
use std::net::Ipv4Addr;

/*
https://justanapplication.wordpress.com/category/dns/dns-resource-records/dns-srv-record/

https://tools.ietf.org/html/rfc5395
https://tools.ietf.org/html/rfc2136
https://tools.ietf.org/html/rfc6195

https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

https://flylib.com/books/en/3.223.1.151/1/

https://tools.ietf.org/html/rfc1035 -> 4.1.1
*/

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
enum ResourceRecordType {
  A,
  AAAA,
  Other(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Label {
  Value(u16, Option<String>),
  Pointer(u16, u16),
}

impl Label {
  fn size(&self) -> usize {
    match self {
      Label::Value(_, Some(l)) => l.len() + 1,
      Label::Value(_, None) => 1,
      Label::Pointer(_, _) => 2,
    }
  }
}

#[derive(Debug, PartialEq, Eq)]
enum QClass {
  Any,
  Class(Class),
}

#[derive(Debug, PartialEq, Eq)]
struct Query {
  values: Vec<Label>,
  q_response_type: QuestionResponseType,
  q_type: QType,
  q_class: QClass,
}

#[derive(PartialEq, Eq, Debug)]
enum QuestionResponseType {
  QU,
  QM,
}

#[derive(Debug)]
enum ResourceRecordData {
  A(std::net::Ipv4Addr),
  Other(Vec<u8>),
}

impl ResourceRecordData {
  fn size(&self) -> usize {
    match self {
      ResourceRecordData::A(_) => 4,
      ResourceRecordData::Other(v) => v.len(),
    }
  }
}

#[derive(Debug)]
struct ResourceRecord {
  name: Vec<Label>,
  resource_record_type: ResourceRecordType,
  class: Class,
  ttl: u32,
  resource_record_data_length: u16,
  resource_record_data: ResourceRecordData,
}

impl ResourceRecord {
  fn size(&self) -> usize {
    let type_length = 2;
    let class_length = 2;
    let ttl_length = 4;
    let data_length_length = 2;
    let name_size = self.name.iter().fold(0, |sum, l| sum + l.size());

    self.resource_record_data.size()
      + type_length
      + class_length
      + ttl_length
      + data_length_length
      + name_size
  }
}

impl Query {
  fn size(&self) -> usize {
    let q_type_size = 2;
    let q_class_size = 2;

    self
      .values
      .iter()
      .fold(q_type_size + q_class_size, |sum, s| sum + s.size())
  }
}

#[derive(Debug)]
struct Message {
  header: Header,
  queries: Vec<Query>,
  answers: Vec<ResourceRecord>,
  name_servers: Vec<ResourceRecord>,
  additional_records: Vec<ResourceRecord>,
}

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const ADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const MULTICAST_PORT: u16 = 5353;

const LABEL_TYPE_MASK: u8 = 0b11000000;
const LABEL_MASK_TYPE_VALUE: u8 = 0b00000000;
const LABEL_MASK_TYPE_POINTER: u8 = 0b11000000;

fn parse_resource_record_data(
  resource_record_type: &ResourceRecordType,
  _class: &Class,
  resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  if data.len() < resource_data_length as usize {
    return Err(ParseError::ResourceRecordError(
      "Data would overflow parsing resource record data".to_owned(),
    ));
  }

  match resource_record_type {
    ResourceRecordType::A => parse_resource_record_data_ip_a(resource_data_length, data),
    _ => parse_resource_record_data_other(resource_data_length, data),
  }
}

fn parse_resource_record_data_other(
  resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  Ok(ResourceRecordData::Other(Vec::from(
    &data[0..(resource_data_length as usize)],
  )))
}

fn parse_resource_record_data_ip_a(
  _resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  if data.len() < 4 {
    return Err(ParseError::ResourceRecordError(
      "Data would overflow when parsing IPv4 resource".to_owned(),
    ));
  }

  Ok(ResourceRecordData::A(std::net::Ipv4Addr::new(
    data[0], data[1], data[2], data[3],
  )))
}

fn parse_resource_data_length(data: [u8; 2]) -> u16 {
  (data[0] as u16) << 8 | data[1] as u16
}

fn parse_ttl(data: [u8; 4]) -> u32 {
  (data[0] as u32) << 24 | (data[1] as u32) << 16 | (data[2] as u32) << 8 | data[3] as u32
}

fn parse_resource_record_type(data: [u8; 2]) -> ResourceRecordType {
  let resource_record_type = (data[0] as u16) << 8 | data[1] as u16;
  match resource_record_type {
    1 => ResourceRecordType::A,
    28 => ResourceRecordType::AAAA,
    n => ResourceRecordType::Other(n),
  }
}

fn parse_name(start_offset: u16, data: &[u8]) -> Result<Vec<Label>, ParseError> {
  let mut values = vec![];
  let mut index = 0;
  let mut current_offset = start_offset;

  if data.len() == 0 {
    return Err(ParseError::QueryLabelError(
      "Failed to parse query values, zero length data".to_owned(),
    ));
  }

  loop {
    if data.len() <= index {
      return Err(ParseError::QueryLabelError(
        "Index going out of bounds when parsing query values".to_owned(),
      ));
    }

    let data = &data[index..];
    let label_type = LABEL_TYPE_MASK & data[0];

    let label = match label_type {
      LABEL_MASK_TYPE_POINTER => parse_label_pointer(current_offset, data),
      LABEL_MASK_TYPE_VALUE => parse_label_value(current_offset, data),
      n => Err(ParseError::QueryLabelError(format!(
        "Unknown label type: {}",
        n
      ))),
    }?;
    current_offset += label.size() as u16;
    values.push(label.clone());

    match label {
      Label::Pointer(_, _) => return Ok(values),
      Label::Value(_, None) => return Ok(values),
      _ => {
        index += label.size();
      }
    }
  }
}

fn parse(data: &[u8]) -> Result<Message, ParseError> {
  let header = parse_header(data)?;

  let offset = 12;

  let queries = parse_queries(offset, &header, &data[offset as usize..])?;
  let queries_length = queries.iter().fold(offset, |sum, q| sum + q.size() as u16);

  let answers = parse_answers(queries_length, &header, &data[queries_length as usize..])?;
  let answers_length = answers
    .iter()
    .fold(queries_length, |sum, a| sum + a.size() as u16);

  let name_servers = parse_name_servers(answers_length, &header, &data[answers_length as usize..])?;
  let name_server_resources_length = name_servers
    .iter()
    .fold(answers_length, |sum, r| sum + r.size() as u16);

  let additional_records = parse_additional_resource_records(
    name_server_resources_length,
    &header,
    &data[name_server_resources_length as usize..],
  )?;

  Ok(Message {
    header,
    queries,
    answers,
    name_servers,
    additional_records,
  })
}

fn parse_query(current_offset: u16, data: &[u8]) -> Result<Query, ParseError> {
  let values = parse_name(current_offset, data)?;
  let offset = values.iter().fold(0, |sum, l| sum + l.size());

  if data.len() < offset + 4 {
    return Err(ParseError::QueryError(
      "Data not long enough for query".to_owned(),
    ));
  }

  let mut q_type_data: [u8; 2] = [0; 2];
  q_type_data.copy_from_slice(&data[offset..offset + 2]);
  let (q_response_type, q_type) = parse_q_type(q_type_data);

  let mut q_class_data: [u8; 2] = [0; 2];
  q_class_data.copy_from_slice(&data[offset + 2..offset + 4]);
  let q_class = parse_q_class(q_class_data);

  Ok(Query {
    values,
    q_response_type,
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

fn parse_q_response_type(data: u8) -> QuestionResponseType {
  if (0b10000000 & data) == 0b10000000 {
    return QuestionResponseType::QU;
  }
  QuestionResponseType::QM
}

fn parse_q_type(data: [u8; 2]) -> (QuestionResponseType, QType) {
  let q_type = ((0b01111111 & data[0]) as u16) << 8 | data[1] as u16;
  let response_type = parse_q_response_type(data[0]);
  (
    response_type,
    match q_type {
      252 => QType::AXFR,
      253 => QType::MAILB,
      254 => QType::MAILA,
      255 => QType::Any,
      _ => QType::Type(parse_type(data)),
    },
  )
}

fn read_until_termination_label_from_offset(labels: Vec<Label>, pointer_offset: u16) -> Vec<Label> {
  let mut end_found = false;
  labels
    .into_iter()
    .skip_while(|l| match l {
      Label::Value(offset, _) => *offset != pointer_offset,
      _ => true,
    })
    .take_while(|l| {
      if end_found {
        return false;
      }

      match l {
        Label::Value(_, None) => {
          end_found = true;
          true
        }
        _ => true,
      }
    })
    .collect()
}

fn resolve_name(all_labels: Vec<Label>, to_resolve: Vec<Label>) -> Vec<Label> {
  to_resolve
    .iter()
    .fold(vec![], |mut labels, label| match label {
      Label::Pointer(_, pointer) => {
        read_until_termination_label_from_offset(all_labels.clone(), *pointer)
          .into_iter()
          .for_each(|l| labels.push(l));
        labels
      }
      label => {
        labels.push(label.clone());
        labels
      }
    })
}

fn parse_queries(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<Query>, ParseError> {
  let mut queries = vec![];
  let mut previous_index = 0;
  let mut current_offset = start_offset;
  for _ in 0..header.qd_count {
    let query = parse_query(current_offset, &data[previous_index..])?;
    previous_index += query.size();
    current_offset += query.size() as u16;
    queries.push(query);
  }
  Ok(queries)
}

fn parse_resource_record(start_offset: u16, data: &[u8]) -> Result<ResourceRecord, ParseError> {
  let name = parse_name(start_offset, data)?;
  let next_index = name.iter().fold(0, |sum, l| sum + l.size());

  let resource_record_type_data: [u8; 2] = [data[next_index], data[next_index + 1]];
  let resource_record_type = parse_resource_record_type(resource_record_type_data);

  let resource_record_class_data: [u8; 2] = [data[next_index + 2], data[next_index + 3]];
  let resource_record_class = parse_class(resource_record_class_data);

  let ttl_data: [u8; 4] = [
    data[next_index + 4],
    data[next_index + 5],
    data[next_index + 6],
    data[next_index + 7],
  ];
  let ttl = parse_ttl(ttl_data);

  let resource_record_data_length_data: [u8; 2] = [data[next_index + 8], data[next_index + 9]];
  let resource_record_data_length = parse_resource_data_length(resource_record_data_length_data);

  let resource_record_data_data = &data[next_index + 10..];
  let resource_record_data = parse_resource_record_data(
    &resource_record_type,
    &resource_record_class,
    resource_record_data_length,
    resource_record_data_data,
  )?;

  Ok(ResourceRecord {
    name,
    resource_record_type,
    class: resource_record_class,
    ttl,
    resource_record_data_length,
    resource_record_data,
  })
}

fn parse_resource_records(
  start_offset: u16,
  count: u16,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  let mut answers = vec![];
  let mut previous_index = 0;
  let mut current_offset = start_offset;
  for _ in 0..count {
    let answer = parse_resource_record(current_offset, &data[previous_index..])?;
    previous_index += answer.size();
    current_offset += answer.size() as u16;
    answers.push(answer);
  }
  Ok(answers)
}

fn parse_additional_resource_records(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(start_offset, header.ar_count, data)
}

fn parse_name_servers(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(start_offset, header.ns_count, data)
}

fn parse_answers(
  start_offset: u16,
  header: &Header,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  parse_resource_records(start_offset, header.an_count, data)
}

fn parse_label_value(current_offset: u16, data: &[u8]) -> Result<Label, ParseError> {
  let data_len = data.len();
  if data_len == 0 {
    return Err(ParseError::QueryLabelError(
      "Data is zero length".to_owned(),
    ));
  }

  let count = data[0];
  if count == 0 {
    return Ok(Label::Value(current_offset, None));
  }

  if count > 63 {
    return Err(ParseError::QueryLabelError(
      "Count exceeds limit of 63".to_owned(),
    ));
  }

  if (count as usize) > (data_len - 1) {
    return Err(ParseError::QueryLabelError(
      "Wrong label count. Count would overflow data".to_owned(),
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
    .map(|s| Label::Value(current_offset, Some(s.to_owned())))
    .map_err(|e| ParseError::QueryLabelError(e.to_string()))
}

fn parse_label_pointer(current_offset: u16, data: &[u8]) -> Result<Label, ParseError> {
  if data.len() < 2 {
    return Err(ParseError::QueryLabelError(
      "Trying to parse pointer label, but data is not long enough".to_owned(),
    ));
  }
  let pointer_value = ((!LABEL_MASK_TYPE_POINTER & data[0]) as u16) << 8 | data[1] as u16;
  Ok(Label::Pointer(current_offset, pointer_value))
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
    let (amt, _src) = socket.recv_from(&mut buf).unwrap();
    let header = parse(&buf[0..amt]);
    match header {
      Ok(message) => {
        println!("header: {:?}", message.header);
        println!("queries: {:?}", message.queries);
        println!("answers: {:?}", message.answers);
        println!("name_servers: {:?}", message.name_servers);
        println!("additional: {:?}", message.additional_records);
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

  #[test]
  fn parse_name_label_with_zero_length() {
    if let Ok(_) = super::parse_name(0, &[]) {
      assert!(false);
    }
  }

  #[test]
  fn parse_name_with_count_zero() {
    let result = super::parse_name(0, &[0]);
    assert_eq!(Ok(vec![super::Label::Value(0, None)]), result);
  }

  #[test]
  fn parse_name_with_overflowing_label_count() {
    match super::parse_name(0, &[1]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_name_with_label_higher_than_63_count() {
    match super::parse_name(0, &[64]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_name_with_premature_zero_in_label() {
    match super::parse_name(0, &[4, 97, 98, 0, 99]) {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_name_with_label_text_abc() {
    let result = super::parse_name(0, &[3, 97, 98, 99, 0]);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, None)
      ]),
      result
    );
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
      assert_eq!((super::QuestionResponseType::QM, td.1), result);
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
      values: vec![super::Label::Value(0, None)],
      q_response_type: super::QuestionResponseType::QM,
      q_type: super::QType::Any,
      q_class: super::QClass::Any,
    };
    assert_eq!(5, query.size());
  }

  #[test]
  fn query_size_with_two_values() {
    let query = super::Query {
      values: vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("de".to_owned())),
        super::Label::Value(7, None),
      ],
      q_response_type: super::QuestionResponseType::QM,
      q_type: super::QType::Any,
      q_class: super::QClass::Any,
    };
    assert_eq!(12, query.size());
  }

  #[test]
  fn parse_query_with_to_short_data() {
    let data = [0, 1, 0, 0];
    let result = super::parse_query(0, &data);
    match result {
      Err(super::ParseError::QueryError(_)) => {}
      _ => assert!(false),
    }
  }

  #[test]
  fn parse_query_without_values() {
    let data = [0, 0, 1, 0, 1];
    let result = super::parse_query(0, &data);
    assert_eq!(
      Ok(super::Query {
        values: vec![super::Label::Value(0, None)],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN)
      }),
      result
    );
  }

  #[test]
  fn parse_query_with_three_values() {
    let data = [
      3, 97, 98, 99, 2, 100, 101, 4, 102, 103, 104, 105, 0, 0, 1, 0, 1,
    ];
    let result = super::parse_query(0, &data);
    assert_eq!(
      Ok(super::Query {
        values: vec![
          super::Label::Value(0, Some("abc".to_owned())),
          super::Label::Value(4, Some("de".to_owned())),
          super::Label::Value(7, Some("fghi".to_owned())),
          super::Label::Value(12, None)
        ],
        q_response_type: super::QuestionResponseType::QM,
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

    let header = crate::header::parse_header(&header_data).unwrap();
    let result = super::parse_queries(12, &header, &data);
    let expected = Ok(vec![
      super::Query {
        values: vec![
          super::Label::Value(12, Some("abc".to_owned())),
          super::Label::Value(16, Some("de".to_owned())),
          super::Label::Value(19, Some("fghi".to_owned())),
          super::Label::Value(24, None),
        ],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN),
      },
      super::Query {
        values: vec![
          super::Label::Value(29, Some("ab".to_owned())),
          super::Label::Value(32, Some("cde".to_owned())),
          super::Label::Value(36, Some("fghi".to_owned())),
          super::Label::Value(41, None),
        ],
        q_response_type: super::QuestionResponseType::QM,
        q_type: super::QType::Type(super::Type::A),
        q_class: super::QClass::Class(super::Class::IN),
      },
    ]);

    assert_eq!(expected, result);
  }

  #[test]
  fn parse_label_pointer() {
    let data = [193, 10];
    let result = super::parse_label_pointer(0, &data);
    assert_eq!(Ok(super::Label::Pointer(0, 266)), result);
  }

  #[test]
  fn parse_label_pointer_and_fail() {
    let data = [193];
    let result = super::parse_label_pointer(0, &data);
    match result {
      Err(super::ParseError::QueryLabelError(_)) => {}
      _ => {
        assert!(false);
      }
    }
  }

  #[test]
  fn parse_label_value() {
    let data = [8, 97, 98, 99, 100, 101, 102, 103, 104];
    let result = super::parse_label_value(0, &data);
    assert_eq!(
      Ok(super::Label::Value(0, Some("abcdefgh".to_owned()))),
      result
    );
  }

  #[test]
  fn parse_label_value_empty() {
    let data = [0, 97, 98, 99, 100, 101, 102, 103, 104];
    let result = super::parse_label_value(0, &data);
    assert_eq!(Ok(super::Label::Value(0, None)), result);
  }

  #[test]
  fn label_size_value() {
    let data = [8, 97, 98, 99, 100, 101, 102, 103, 104];
    let result = super::parse_label_value(0, &data);
    assert_eq!(Ok(9), result.map(|r| r.size()));
  }

  #[test]
  fn label_size_pointer() {
    let data = [192, 10];
    let result = super::parse_label_pointer(0, &data);
    assert_eq!(Ok(2), result.map(|r| r.size()));
  }

  #[test]
  fn parse_query_with_value_values() {
    let data = [3, 97, 98, 99, 2, 100, 101, 1, 102, 0];
    let result = super::parse_name(0, &data);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("de".to_owned())),
        super::Label::Value(7, Some("f".to_owned())),
        super::Label::Value(9, None),
      ]),
      result
    );
  }

  #[test]
  fn parse_query_with_value_and_pointer_values() {
    let data = [3, 97, 98, 99, 2, 100, 101, 1, 102, 192, 10];
    let result = super::parse_name(0, &data);
    assert_eq!(
      Ok(vec![
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("de".to_owned())),
        super::Label::Value(7, Some("f".to_owned())),
        super::Label::Pointer(9, 10),
      ]),
      result
    );
  }

  #[test]
  fn parse_q_response_type_for_unicast() {
    let data = 0b10000000;
    let result = super::parse_q_response_type(data);
    assert_eq!(super::QuestionResponseType::QU, result);
  }

  #[test]
  fn parse_q_response_type_for_multicast() {
    let data = 0b00000000;
    let result = super::parse_q_response_type(data);
    assert_eq!(super::QuestionResponseType::QM, result);
  }

  #[test]
  fn parse_resource_record_type() {
    let data = &[
      (super::ResourceRecordType::A, [0, 1]),
      (super::ResourceRecordType::AAAA, [0, 28]),
      (super::ResourceRecordType::Other(257), [1, 1]),
    ];
    for td in data {
      let result = super::parse_resource_record_type(td.1);
      assert_eq!(td.0, result);
    }
  }

  #[test]
  fn parse_ttl() {
    let data = [1, 1, 1, 1];
    let result = super::parse_ttl(data);
    assert_eq!(16843009, result);
  }

  #[test]
  fn parse_resource_data_length() {
    let data = [(0, [0, 0]), (1, [0, 1]), (257, [1, 1])];
    for td in &data {
      let result = super::parse_resource_data_length(td.1);
      assert_eq!(td.0, result);
    }
  }

  #[test]
  fn resource_data_size() {
    let data = [
      (
        8,
        super::ResourceRecordData::Other(vec![1, 2, 3, 4, 5, 6, 7, 8]),
      ),
      (
        4,
        super::ResourceRecordData::A(std::net::Ipv4Addr::new(192, 168, 0, 158)),
      ),
    ];

    for td in &data {
      let result = td.1.size();
      assert_eq!(td.0, result);
    }
  }

  #[test]
  fn resource_record_size() {
    let data = [(
      26,
      super::ResourceRecord {
        name: vec![
          super::Label::Value(0, Some("abc".to_owned())),
          super::Label::Value(4, None),
        ],
        resource_record_type: super::ResourceRecordType::Other(12),
        class: super::Class::IN,
        ttl: 4500,
        resource_record_data_length: 11,
        resource_record_data: super::ResourceRecordData::Other(vec![
          1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        ]),
      },
    )];

    for td in &data {
      let result = td.1.size();
      assert_eq!(td.0, result);
    }
  }

  #[test]
  fn parse_test_pointer_logic() {
    let data = [
      0, 0, 0, 0, 0, 6, 0, 0, 0, 7, 0, 1, 4, 99, 111, 110, 102, 15, 95, 99, 111, 109, 112, 97, 110,
      105, 111, 110, 45, 108, 105, 110, 107, 4, 95, 116, 99, 112, 5, 108, 111, 99, 97, 108, 0, 0,
      255, 128, 1, 4, 99, 111, 110, 102, 14, 95, 109, 101, 100, 105, 97, 114, 101, 109, 111, 116,
      101, 116, 118, 192, 33, 0, 255, 128, 1, 4, 99, 111, 110, 102, 8, 95, 97, 105, 114, 112, 108,
      97, 121, 192, 33, 0, 255, 128, 1, 17, 57, 48, 68, 68, 53, 68, 66, 53, 57, 53, 54, 53, 64, 99,
      111, 110, 102, 5, 95, 114, 97, 111, 112, 192, 33, 0, 255, 128, 1, 18, 55, 48, 45, 51, 53, 45,
      54, 48, 45, 54, 51, 46, 49, 32, 99, 111, 110, 102, 12, 95, 115, 108, 101, 101, 112, 45, 112,
      114, 111, 120, 121, 4, 95, 117, 100, 112, 192, 38, 0, 255, 128, 1, 4, 99, 111, 110, 102, 192,
      38, 0, 255, 128, 1, 192, 12, 0, 33, 0, 1, 0, 0, 0, 120, 0, 8, 0, 0, 0, 0, 192, 0, 192, 168,
      192, 49, 0, 33, 0, 1, 0, 0, 0, 120, 0, 8, 0, 0, 0, 0, 192, 1, 192, 168, 192, 75, 0, 33, 0, 1,
      0, 0, 0, 120, 0, 8, 0, 0, 0, 0, 27, 88, 192, 168, 192, 95, 0, 33, 0, 1, 0, 0, 0, 120, 0, 8,
      0, 0, 0, 0, 27, 88, 192, 168, 192, 125, 0, 33, 0, 1, 0, 0, 0, 120, 0, 8, 0, 0, 0, 0, 241,
      224, 192, 168, 192, 168, 0, 28, 0, 1, 0, 0, 0, 120, 0, 16, 254, 128, 0, 0, 0, 0, 0, 0, 0,
      174, 105, 16, 111, 52, 62, 9, 192, 168, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 136, 0,
      0, 41, 5, 160, 0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0, 100, 144, 221, 93, 181, 149, 101, 144,
      221, 93, 172, 40, 91,
    ];

    println!("data: {:?}\n", &data[89..]);

    let result = super::parse(&data).unwrap();
    println!("result: {:?}", result);
  }

  #[test]
  fn read_until_termination_label_from_offset() {
    let labels = vec![
      super::Label::Value(0, Some("abc".to_owned())),
      super::Label::Value(4, Some("def".to_owned())),
      super::Label::Value(8, None),
      super::Label::Value(12, Some("ghi".to_owned())),
      super::Label::Value(16, None),
      super::Label::Value(20, Some("jkl".to_owned())),
      super::Label::Value(24, None),
    ];

    let result = super::read_until_termination_label_from_offset(labels, 12);
    assert_eq!(
      vec![
        super::Label::Value(12, Some("ghi".to_owned())),
        super::Label::Value(16, None)
      ],
      result
    );
  }

  #[test]
  fn resolve_name() {
    let labels = vec![
      super::Label::Value(0, Some("abc".to_owned())),
      super::Label::Value(4, Some("def".to_owned())),
      super::Label::Value(8, None),
      super::Label::Value(12, Some("ghi".to_owned())),
      super::Label::Value(16, None),
      super::Label::Value(20, Some("jkl".to_owned())),
      super::Label::Pointer(24, 0),
    ];

    let result = super::resolve_name(labels.clone(), labels[5..].to_vec());
    assert_eq!(
      vec![
        super::Label::Value(20, Some("jkl".to_owned())),
        super::Label::Value(0, Some("abc".to_owned())),
        super::Label::Value(4, Some("def".to_owned())),
        super::Label::Value(8, None),
      ],
      result
    );
  }
}
