use crate::shared::{parse_class, parse_name, Class, Label, ParseError};

#[derive(Debug, PartialEq, Eq)]
enum ResourceRecordType {
  A,
  AAAA,
  Other(u16),
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
pub struct ResourceRecord<'a> {
  name: Vec<Label<'a>>,
  resource_record_type: ResourceRecordType,
  class: Class,
  ttl: u32,
  resource_record_data_length: u16,
  resource_record_data: ResourceRecordData,
}

impl<'a> ResourceRecord<'a> {
  pub fn size(&self) -> usize {
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

fn parse_resource_record<'a>(
  offset: usize,
  data: &'a [u8],
) -> Result<ResourceRecord<'a>, ParseError> {
  let name = parse_name(offset, data)?;
  let next_index = name.iter().fold(offset, |sum, l| sum + l.size());

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

pub fn parse_resource_records<'a>(
  start_offset: usize,
  count: u16,
  data: &'a [u8],
) -> Result<Vec<ResourceRecord<'a>>, ParseError> {
  let mut answers = vec![];
  let mut current_offset = start_offset;
  for _ in 0..count {
    let answer = parse_resource_record(current_offset, data)?;
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
}
