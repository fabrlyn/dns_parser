use crate::header::Header;
use crate::shared::{
  extract_domain_name, parse_class, parse_name, parse_type, Class, Label, ParseError, Type,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum QType {
  Type(Type),
  AXFR,
  MAILB,
  MAILA,
  Any,
}

#[derive(Debug, PartialEq, Eq)]
enum QClass {
  Any,
  Class(Class),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Query<'a> {
  pub values: Vec<Label<'a>>,
  pub name: String,
  q_response_type: QuestionResponseType,
  q_type: QType,
  q_class: QClass,
}

#[derive(PartialEq, Eq, Debug)]
enum QuestionResponseType {
  QU,
  QM,
}

impl<'a> Query<'a> {
  pub fn size(&self) -> usize {
    let q_type_size = 2;
    let q_class_size = 2;

    self
      .values
      .iter()
      .fold(q_type_size + q_class_size, |sum, s| sum + s.size())
  }
}

fn parse_query<'a>(
  labels: &[Label<'a>],
  offset: usize,
  data: &'a [u8],
) -> Result<Query<'a>, ParseError> {
  let values = parse_name(offset, data)?;
  let name = extract_domain_name(labels, &values);

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
    name,
    values,
    q_response_type,
    q_type,
    q_class,
  })
}

fn parse_q_class(data: [u8; 2]) -> QClass {
  let class = (data[0] as u16) << 8 | data[1] as u16;
  match class {
    255 => QClass::Any,
    _ => QClass::Class(parse_class(data)),
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

pub fn parse_queries<'a>(
  offset: usize,
  header: &Header,
  data: &'a [u8],
) -> Result<Vec<Query<'a>>, ParseError> {
  let mut queries = vec![];
  let mut current_offset = offset;
  let mut labels = vec![];
  for _ in 0..header.question_count {
    let query = parse_query(&labels, current_offset, data)?;
    current_offset += query.size();
    labels = [labels, query.values.clone()].concat();
    queries.push(query);
  }
  Ok(queries)
}

mod test {

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
}
