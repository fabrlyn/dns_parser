use crate::shared::{extract_domain_name, parse_class, parse_name, Class, Label, ParseError};
use std::fmt::Debug;

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceRecordType {
  A,
  AAAA,
  CNAME,
  TXT,
  MX,
  NS,
  PTR,
  SOA,
  OPT,
  SRV,
  NSEC,
  Other(u16),
}

#[derive(Debug)]
pub struct SRV {}

#[derive(Debug)]
pub enum ResourceRecordData {
  A(std::net::Ipv4Addr),
  PTR(String),
  TXT(String),
  SRV(SRV),
  Other(Vec<u8>),
}

impl std::fmt::Display for ResourceRecordData {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let value = match self {
      ResourceRecordData::Other(value) => format!("{:?})", value),
      a => format!("{:?}", a),
    };
    write!(f, "{:?}", value);
    Ok(())
  }
}

#[derive(Debug)]
pub struct ResourceRecord {
  pub values: Vec<Label>,
  pub resource_record_type: ResourceRecordType,
  pub class: Class,
  pub ttl: u32,
  pub resource_record_data_length: u16,
  pub resource_record_data: ResourceRecordData,
}

impl<'a> ResourceRecord {
  pub fn size(&self) -> usize {
    let type_length = 2;
    let class_length = 2;
    let ttl_length = 4;
    let data_length_length = 2;
    let name_size = self.values.iter().fold(0, |sum, l| sum + l.size());

    (self.resource_record_data_length as usize)
      + type_length
      + class_length
      + ttl_length
      + data_length_length
      + name_size
  }
}

fn parse_resource_record_data(
  label_store: &mut Vec<Label>,
  offset: usize,
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
    ResourceRecordType::A => parse_resource_record_data_ip_a(offset, resource_data_length, data),
    ResourceRecordType::TXT => parse_resource_record_data_txt(offset, resource_data_length, data),
    ResourceRecordType::PTR => {
      parse_resource_record_data_ptr(label_store, offset, resource_data_length, data)
    }
    _ => parse_resource_record_data_other(offset, resource_data_length, data),
  }
}

fn to_ascii(data: &[u8]) -> String {
  data.iter().map(|c| *c as char).collect::<String>()
}

fn parse_resource_record_data_txt(
  offset: usize,
  resource_record_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  Ok(ResourceRecordData::TXT(to_ascii(
    &data[offset..offset + (resource_record_length as usize)],
  )))
}

fn parse_resource_record_data_other(
  offset: usize,
  resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  Ok(ResourceRecordData::Other(Vec::from(
    &data[offset..offset + (resource_data_length as usize)],
  )))
}

fn parse_resource_record_data_ptr(
  label_store: &mut Vec<Label>,
  offset: usize,
  _resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  let values = parse_name(offset, data)?;
  values.iter().for_each(|v| label_store.push(v.clone()));
  let name = extract_domain_name(label_store, &values);
  Ok(ResourceRecordData::PTR(name))
}

fn parse_resource_record_data_ip_a(
  offset: usize,
  _resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  if data.len() < 4 {
    return Err(ParseError::ResourceRecordError(
      "Data would overflow when parsing IPv4 resource".to_owned(),
    ));
  }

  Ok(ResourceRecordData::A(std::net::Ipv4Addr::new(
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
  )))
}

fn parse_resource_record_data_srv(
  offset: usize,
  _resource_data_length: u16,
  data: &[u8],
) -> Result<ResourceRecordData, ParseError> {
  Ok(ResourceRecordData::SRV(SRV {}))
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
    2 => ResourceRecordType::NS,
    5 => ResourceRecordType::CNAME,
    6 => ResourceRecordType::SOA,
    12 => ResourceRecordType::PTR,
    15 => ResourceRecordType::MX,
    16 => ResourceRecordType::TXT,
    28 => ResourceRecordType::AAAA,
    33 => ResourceRecordType::SRV,
    41 => ResourceRecordType::OPT,
    47 => ResourceRecordType::NSEC,
    n => ResourceRecordType::Other(n),
  }
}

fn parse_resource_record(
  label_store: &mut Vec<Label>,
  offset: usize,
  data: &[u8],
) -> Result<ResourceRecord, ParseError> {
  let values = parse_name(offset, data)?;
  let next_index = values.iter().fold(offset, |sum, l| sum + l.size());
  values.iter().for_each(|v| label_store.push(v.clone()));

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

  let resource_record_data = parse_resource_record_data(
    label_store,
    next_index + 10,
    &resource_record_type,
    &resource_record_class,
    resource_record_data_length,
    data,
  )?;

  Ok(ResourceRecord {
    values,
    resource_record_type,
    class: resource_record_class,
    ttl,
    resource_record_data_length,
    resource_record_data,
  })
}

pub fn parse_resource_records(
  label_store: &mut Vec<Label>,
  start_offset: usize,
  count: u16,
  data: &[u8],
) -> Result<Vec<ResourceRecord>, ParseError> {
  let mut answers = vec![];
  let mut current_offset = start_offset;
  for _ in 0..count {
    let answer = parse_resource_record(label_store, current_offset, data)?;
    current_offset += answer.size();
    answers.push(answer);
  }
  Ok(answers)
}

mod test {

  #[test]
  fn parse_resource_record_type() {
    let data = &[
      (super::ResourceRecordType::A, [0, 1]),
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
  fn parse_resource_record_data_src() {
    let srv_data = &[
      0, 0, 0, 0, 125, 127, 36, 101, 48, 55, 49, 57, 101, 101, 53, 45, 100, 55, 102, 56, 45, 57,
      98, 102, 100, 45, 57, 101, 97, 55, 45, 52, 52, 53, 97, 55, 49, 48, 48, 53, 55, 53, 50, 192,
      29,
    ];

    let result = super::parse_resource_record_data_srv(0, srv_data.len() as u16, srv_data);
    println!("result: {:?}", result);
  }
}
